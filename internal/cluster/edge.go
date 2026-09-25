package cluster

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hyperdns/internal/core/dns"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/database"
)

const maxSnapshotAge = 5 * time.Minute

type edgeAccess struct {
	clients  map[string]*database.Client
	allowAll bool
}

// EdgeState is a complete, immutable access snapshot plus local metering.
// A controller outage can use a recent snapshot; once it is older than five
// minutes, access closes instead of serving revoked subscribers indefinitely.
type EdgeState struct {
	access        atomic.Pointer[edgeAccess]
	lastConfirmed atomic.Int64
	mu            sync.Mutex
	pending       map[string]uint64
	usageBase     map[string]uint64
	resetCount    map[string]uint64
}

func NewEdgeState() *EdgeState {
	s := &EdgeState{pending: make(map[string]uint64), usageBase: make(map[string]uint64), resetCount: make(map[string]uint64)}
	s.access.Store(&edgeAccess{clients: make(map[string]*database.Client)})
	return s
}

func (s *EdgeState) IsIPAllowed(ip string) (*database.Client, bool) {
	if time.Since(time.Unix(s.lastConfirmed.Load(), 0)) > maxSnapshotAge {
		return nil, false
	}
	a := s.access.Load()
	client := a.clients[ip]
	if client != nil && !client.ExpiresAt.IsZero() && time.Now().After(client.ExpiresAt) {
		client = nil
	}
	return client, client != nil || a.allowAll
}

func (s *EdgeState) HasFreshSnapshot() bool {
	return s.lastConfirmed.Load() > 0 && time.Since(time.Unix(s.lastConfirmed.Load(), 0)) <= maxSnapshotAge
}

func (s *EdgeState) IsAllowAll() bool {
	return time.Since(time.Unix(s.lastConfirmed.Load(), 0)) <= maxSnapshotAge && s.access.Load().allowAll
}

func (s *EdgeState) AddTraffic(id string, n uint64) {
	if id == "" || n == 0 {
		return
	}
	s.mu.Lock()
	s.pending[id] += n
	s.mu.Unlock()
}

func (s *EdgeState) QuotaExceeded(c *database.Client) bool {
	if c == nil || c.TrafficLimitGB <= 0 {
		return false
	}
	s.mu.Lock()
	pending := s.pending[c.ID]
	s.mu.Unlock()
	return float64(c.TrafficUsedBytes+pending) >= c.TrafficLimitGB*(1<<30)
}

func (s *EdgeState) Apply(snapshot Snapshot, confirmed time.Time) (*matcher.Matcher, error) {
	if snapshot.Revision == "" {
		return nil, errors.New("cluster: snapshot has no revision")
	}
	a := &edgeAccess{clients: make(map[string]*database.Client), allowAll: snapshot.AllowAll}
	for i := range snapshot.Clients {
		c := &snapshot.Clients[i]
		if c.ID == "" {
			return nil, errors.New("cluster: snapshot contains a client without ID")
		}
		if !c.Enabled || (!c.ExpiresAt.IsZero() && confirmed.After(c.ExpiresAt)) {
			continue
		}
		for _, ip := range c.AllowedIPs {
			if ip != "" {
				a.clients[ip] = c
			}
		}
	}
	m := matcher.NewMatcher()
	var proxied, blocked, direct []string
	records := make(map[string]string)
	for _, p := range snapshot.Policies {
		switch p.Key {
		case "custom_proxied":
			proxied = p.CustomDomains
		case "custom_blocked":
			blocked = p.CustomDomains
		case "custom_direct":
			direct = p.CustomDomains
		case "custom_records":
			for _, entry := range p.CustomDomains {
				if d, ip, ok := strings.Cut(entry, "="); ok {
					records[strings.TrimSpace(d)] = strings.TrimSpace(ip)
				}
			}
		default:
			if _, ok := matcher.PresetRuleKeys[p.Key]; ok {
				m.SetRuleEnabled(p.Key, p.Enabled)
			}
		}
	}
	m.SetCustomRules(proxied, blocked, direct, records)
	s.mu.Lock()
	current := make(map[string]bool, len(snapshot.Clients))
	for _, client := range snapshot.Clients {
		current[client.ID] = true
		if previous, seen := s.usageBase[client.ID]; seen &&
			(client.TrafficUsedBytes < previous || client.TrafficResetCount != s.resetCount[client.ID]) {
			delete(s.pending, client.ID)
		}
		s.usageBase[client.ID] = client.TrafficUsedBytes
		s.resetCount[client.ID] = client.TrafficResetCount
	}
	for id := range s.pending {
		if !current[id] {
			delete(s.pending, id)
		}
	}
	s.mu.Unlock()
	s.access.Store(a)
	s.lastConfirmed.Store(confirmed.Unix())
	return m, nil
}

func (s *EdgeState) Confirm() { s.lastConfirmed.Store(time.Now().Unix()) }

func (s *EdgeState) Revoke() { s.lastConfirmed.Store(0) }

type savedSnapshot struct {
	Snapshot Snapshot  `json:"snapshot"`
	SavedAt  time.Time `json:"saved_at"`
}

func validateSnapshot(s Snapshot) error {
	if len(s.Revision) != 64 {
		return errors.New("cluster: snapshot revision is invalid")
	}
	for _, client := range s.Clients {
		if client.ID == "" {
			return errors.New("cluster: snapshot contains a client without ID")
		}
	}
	want := s.Revision
	s.Revision, s.NodePublicIP = "", ""
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != want {
		return errors.New("cluster: snapshot revision does not match its contents")
	}
	return nil
}

type Agent struct {
	ID        string
	PublicIP  string
	URL       string
	Token     string
	CAFile    string
	StateDir  string
	DB        *database.DB
	Access    *EdgeState
	DNS       *dns.Handler
	DoH       *dns.DoHHandler
	Upstreams *upstream.UpstreamPool
	Telemetry func() NodeTelemetry
	client    *http.Client
	revision  string
	last      savedSnapshot
}

func (a *Agent) certPaths() (string, string) {
	return filepath.Join(a.StateDir, "node.crt"), filepath.Join(a.StateDir, "node.key")
}

func (a *Agent) Connect() error {
	if a.ID == "" || a.PublicIP == "" || !strings.HasPrefix(a.URL, "https://") || a.CAFile == "" || a.StateDir == "" {
		return errors.New("cluster: node ID, public IP, HTTPS controller URL, CA file and state directory are required")
	}
	parsedURL, err := url.Parse(a.URL)
	if err != nil || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.Path != "" || parsedURL.RawQuery != "" {
		return errors.New("cluster: controller URL must be an HTTPS origin without a path")
	}
	caPEM, err := os.ReadFile(a.CAFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("cluster: invalid CA PEM")
	}
	if err := os.MkdirAll(a.StateDir, 0700); err != nil {
		return err
	}
	certPath, keyPath := a.certPaths()
	var pair tls.Certificate
	if a.Token != "" {
		pair, err = a.enroll(roots)
		if err != nil {
			return err
		}
	} else if _, err := os.Stat(certPath); err == nil {
		pair, err = tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return err
		}
	} else {
		return errors.New("cluster: enrollment token required on first start")
	}
	a.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: controllerName,
			Certificates: []tls.Certificate{pair},
		},
	}}
	return nil
}

func (a *Agent) enroll(roots *x509.CertPool) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: a.ID}}, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	body, _ := json.Marshal(map[string]string{
		"id": a.ID, "token": a.Token, "csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	})
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: controllerName},
	}}
	resp, err := client.Post(strings.TrimRight(a.URL, "/")+"/v1/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return tls.Certificate{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return tls.Certificate{}, fmt.Errorf("cluster: enrollment refused (HTTP %d)", resp.StatusCode)
	}
	var result struct {
		Certificate string `json:"certificate"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&result); err != nil {
		return tls.Certificate{}, err
	}
	pair, err := tls.X509KeyPair([]byte(result.Certificate), keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPath, keyPath := a.certPaths()
	if err := writePrivateFile(keyPath, keyPEM); err != nil {
		return tls.Certificate{}, err
	}
	if err := writePrivateFile(certPath, []byte(result.Certificate)); err != nil {
		return tls.Certificate{}, err
	}
	return pair, nil
}

func writePrivateFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (a *Agent) LoadSaved() error {
	if a.DB == nil || a.Access == nil {
		return errors.New("cluster: edge storage is not initialized")
	}
	var saved savedSnapshot
	if err := a.DB.GetSetting("edge_snapshot", &saved); err != nil {
		return err
	}
	if saved.Snapshot.Revision == "" {
		return nil
	}
	if err := validateSnapshot(saved.Snapshot); err != nil {
		return err
	}
	if saved.Snapshot.NodePublicIP != a.PublicIP {
		return errors.New("cluster: saved snapshot belongs to another public IP")
	}
	m, err := a.Access.Apply(saved.Snapshot, saved.SavedAt)
	if err != nil {
		return err
	}
	a.DNS.SetMatcher(m)
	if a.DoH != nil {
		a.DoH.SetDoHTokens(saved.Snapshot.DoHTokens)
	}
	if len(saved.Snapshot.Upstreams) > 0 {
		a.Upstreams.SetUpstreams(saved.Snapshot.Upstreams)
	}
	a.revision, a.last = saved.Snapshot.Revision, saved
	return nil
}

func (a *Agent) SyncOnce(ctx context.Context) error {
	if a.client == nil {
		return errors.New("cluster: agent not connected")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(a.URL, "/")+"/v1/snapshot", nil)
	if err != nil {
		return err
	}
	if a.revision != "" {
		req.Header.Set("If-None-Match", a.revision)
	}
	if a.Telemetry != nil {
		if body, err := json.Marshal(a.Telemetry()); err == nil {
			req.Header.Set("X-HyperDNS-Edge-Telemetry", base64.RawURLEncoding.EncodeToString(body))
		}
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		a.Access.Revoke()
		if a.last.Snapshot.Revision != "" {
			a.revision = ""
			a.last = savedSnapshot{}
			if err := a.DB.SetSetting("edge_snapshot", a.last); err != nil {
				return err
			}
		}
		return fmt.Errorf("cluster: controller revoked this node (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNotModified {
		if a.last.Snapshot.Revision == "" {
			return errors.New("cluster: 304 without a saved snapshot")
		}
		if time.Since(a.last.SavedAt) >= time.Minute {
			a.last.SavedAt = time.Now().UTC()
			if err := a.DB.SetSetting("edge_snapshot", a.last); err != nil {
				return err
			}
		}
		a.Access.Confirm()
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cluster: snapshot HTTP %d", resp.StatusCode)
	}
	var snapshot Snapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&snapshot); err != nil {
		return err
	}
	if snapshot.NodePublicIP != a.PublicIP {
		return fmt.Errorf("cluster: node public IP mismatch: registered %s, configured %s", snapshot.NodePublicIP, a.PublicIP)
	}
	if err := validateSnapshot(snapshot); err != nil {
		return err
	}
	now := time.Now().UTC()
	// Persist before promoting. A failed disk write must not create an in-memory
	// policy that disappears on the next process restart.
	saved := savedSnapshot{Snapshot: snapshot, SavedAt: now}
	if err := a.DB.SetSetting("edge_snapshot", saved); err != nil {
		return err
	}
	m, err := a.Access.Apply(snapshot, now)
	if err != nil {
		return err
	}
	a.DNS.SetMatcher(m)
	if a.DoH != nil {
		a.DoH.SetDoHTokens(snapshot.DoHTokens)
	}
	if len(snapshot.Upstreams) > 0 {
		a.Upstreams.SetUpstreams(snapshot.Upstreams)
	}
	a.revision, a.last = snapshot.Revision, saved
	return nil
}

func (a *Agent) Run(ctx context.Context, onError func(error)) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.SyncOnce(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
