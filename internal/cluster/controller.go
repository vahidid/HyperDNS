package cluster

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"hyperdns/internal/database"
)

const controllerName = "hyperdns-controller"

type Node struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	Location        string        `json:"location"`
	PublicIP        string        `json:"public_ip"`
	Enabled         bool          `json:"enabled"`
	Enrolled        bool          `json:"enrolled"`
	CreatedAt       time.Time     `json:"created_at"`
	LastSeen        time.Time     `json:"last_seen"`
	Revision        string        `json:"revision"`
	EnrollmentHash  string        `json:"enrollment_hash,omitempty"`
	CertFingerprint string        `json:"cert_fingerprint,omitempty"`
	Telemetry       NodeTelemetry `json:"telemetry"`
}

// NodeTelemetry is sampled by the edge and accepted only over its enrolled mTLS connection.
type NodeTelemetry struct {
	DNSQueries     uint64    `json:"dns_queries"`
	DNSQPS         float64   `json:"dns_qps"`
	CPUPercent     float64   `json:"cpu_percent"`
	MemoryPercent  float64   `json:"memory_percent"`
	ActiveRelays   int64     `json:"active_relays"`
	ProxyBytesSent uint64    `json:"proxy_bytes_sent"`
	ProxyBytesRecv uint64    `json:"proxy_bytes_recv"`
	UptimeSec      int64     `json:"uptime_sec"`
	CapturedAt     time.Time `json:"captured_at"`
}

type NodeProbe struct {
	CheckedAt    time.Time `json:"checked_at"`
	DNSReachable bool      `json:"dns_reachable"`
	DNSRTTMs     *float64  `json:"dns_rtt_ms,omitempty"`
	TCPReachable bool      `json:"tcp_reachable"`
}

type NodeView struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Location  string         `json:"location"`
	PublicIP  string         `json:"public_ip"`
	Enabled   bool           `json:"enabled"`
	Enrolled  bool           `json:"enrolled"`
	CreatedAt time.Time      `json:"created_at"`
	LastSeen  time.Time      `json:"last_seen"`
	Revision  string         `json:"revision"`
	Telemetry *NodeTelemetry `json:"telemetry,omitempty"`
	Probe     *NodeProbe     `json:"probe,omitempty"`
}

func view(n Node) NodeView {
	v := NodeView{ID: n.ID, Name: n.Name, Location: n.Location, PublicIP: n.PublicIP, Enabled: n.Enabled, Enrolled: n.Enrolled, CreatedAt: n.CreatedAt, LastSeen: n.LastSeen, Revision: n.Revision}
	if !n.Telemetry.CapturedAt.IsZero() {
		v.Telemetry = &n.Telemetry
	}
	return v
}

type Snapshot struct {
	Revision     string            `json:"revision"`
	Clients      []database.Client `json:"clients"`
	Policies     []database.Policy `json:"policies"`
	AllowAll     bool              `json:"allow_all"`
	Upstreams    []string          `json:"upstreams"`
	DoHTokens    []string          `json:"doh_tokens"`
	NodePublicIP string            `json:"node_public_ip,omitempty"`
}

type persistedCA struct {
	Cert []byte `json:"cert"`
	Key  []byte `json:"key"`
}

type Controller struct {
	mu            sync.Mutex
	db            *database.DB
	nodes         []Node
	caCert        *x509.Certificate
	caKey         *ecdsa.PrivateKey
	caPEM         []byte
	serverTLS     tls.Certificate
	server        *http.Server
	probes        map[string]NodeProbe
	probeStop     chan struct{}
	ControllerURL string
}

func NewController(db *database.DB, publicURL string) (*Controller, error) {
	if db == nil {
		return nil, errors.New("cluster: database is required")
	}
	parsedURL, err := url.Parse(publicURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.Path != "" || parsedURL.RawQuery != "" {
		return nil, errors.New("cluster: controller URL must be an HTTPS origin without a path")
	}
	c := &Controller{db: db, ControllerURL: strings.TrimRight(publicURL, "/"), probes: make(map[string]NodeProbe)}
	if err := db.GetSetting("cluster_nodes", &c.nodes); err != nil {
		return nil, err
	}
	if c.nodes == nil {
		c.nodes = []Node{}
	}
	var saved persistedCA
	if err := db.GetSetting("cluster_ca", &saved); err != nil {
		return nil, err
	}
	if (len(saved.Cert) == 0) != (len(saved.Key) == 0) {
		return nil, errors.New("cluster: stored CA is incomplete; restore the controller backup")
	}
	if len(saved.Cert) == 0 {
		var err error
		saved, err = newCA()
		if err != nil {
			return nil, err
		}
		if err := db.SetSetting("cluster_ca", saved); err != nil {
			return nil, err
		}
	}
	block, _ := pem.Decode(saved.Cert)
	if block == nil {
		return nil, errors.New("cluster: stored CA certificate is invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(saved.Key)
	if keyBlock == nil {
		return nil, errors.New("cluster: stored CA key is invalid")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	c.caCert, c.caKey, c.caPEM = cert, key, saved.Cert
	serverPEM, serverKey, err := c.signCertificate(controllerName, nil, true)
	if err != nil {
		return nil, err
	}
	c.serverTLS, err = tls.X509KeyPair(serverPEM, serverKey)
	return c, err
}

func newCA() (persistedCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return persistedCA{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return persistedCA{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "HyperDNS cluster CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return persistedCA{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return persistedCA{}, err
	}
	return persistedCA{
		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

func (c *Controller) signCertificate(name string, publicKey any, server bool) ([]byte, []byte, error) {
	var privatePEM []byte
	if server {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		publicKey = &key.PublicKey
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, nil, err
		}
		privatePEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	expires := time.Now().AddDate(1, 0, 0)
	if server {
		expires = time.Now().AddDate(9, 0, 0)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: expires,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{controllerName}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.caCert, publicKey, c.caKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), privatePEM, nil
}

func randomHex(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (c *Controller) CAPEM() string { return string(c.caPEM) }

// BootstrapNode permits a one-time installer download before the node enrolls.
// Only the token hash is stored; the same credential is consumed by /v1/enroll.
func (c *Controller) BootstrapNode(id, token string) (NodeView, bool) {
	if len(id) != 32 || len(token) != 64 {
		return NodeView{}, false
	}
	got := sha256.Sum256([]byte(token))
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range c.nodes {
		if n.ID != id || !n.Enabled || n.Enrolled {
			continue
		}
		want, err := hex.DecodeString(n.EnrollmentHash)
		if err == nil && len(want) == len(got) && subtle.ConstantTimeCompare(got[:], want) == 1 {
			return view(n), true
		}
	}
	return NodeView{}, false
}

func (c *Controller) List() []NodeView {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]NodeView, len(c.nodes))
	for i, n := range c.nodes {
		out[i] = view(n)
		if probe, ok := c.probes[n.ID]; ok {
			out[i].Probe = &probe
		}
	}
	return out
}

func (c *Controller) Create(name, location, publicIP string) (NodeView, string, error) {
	name, location = strings.TrimSpace(name), strings.TrimSpace(location)
	ip := net.ParseIP(strings.TrimSpace(publicIP))
	if name == "" || len(name) > 80 || len(location) > 80 || ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return NodeView{}, "", errors.New("name and a public IPv4 are required; name/location must be at most 80 characters")
	}
	id, err := randomHex(16)
	if err != nil {
		return NodeView{}, "", err
	}
	token, err := randomHex(32)
	if err != nil {
		return NodeView{}, "", err
	}
	hash := sha256.Sum256([]byte(token))
	n := Node{ID: id, Name: name, Location: location, PublicIP: ip.String(), Enabled: true, CreatedAt: time.Now().UTC(), EnrollmentHash: hex.EncodeToString(hash[:])}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, existing := range c.nodes {
		if existing.PublicIP == n.PublicIP {
			return NodeView{}, "", errors.New("a node already uses this public IP")
		}
	}
	c.nodes = append(c.nodes, n)
	if err := c.db.SetSetting("cluster_nodes", c.nodes); err != nil {
		c.nodes = c.nodes[:len(c.nodes)-1]
		return NodeView{}, "", err
	}
	return view(n), token, nil
}

func (c *Controller) SetEnabled(id string, enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.nodes {
		if c.nodes[i].ID == id {
			old := c.nodes[i]
			c.nodes[i].Enabled = enabled
			if err := c.db.SetSetting("cluster_nodes", c.nodes); err != nil {
				c.nodes[i] = old
				return err
			}
			return nil
		}
	}
	return errors.New("node not found")
}

// ResetEnrollment revokes the old node certificate at the application gate and
// issues one new single-use token, for lost credentials or an interrupted join.
func (c *Controller) ResetEnrollment(id string) (string, error) {
	token, err := randomHex(32)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(token))
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.nodes {
		if c.nodes[i].ID == id {
			old := c.nodes[i]
			c.nodes[i].Enrolled = false
			c.nodes[i].EnrollmentHash = hex.EncodeToString(hash[:])
			c.nodes[i].CertFingerprint = ""
			c.nodes[i].LastSeen = time.Time{}
			c.nodes[i].Revision = ""
			c.nodes[i].Telemetry = NodeTelemetry{}
			if err := c.db.SetSetting("cluster_nodes", c.nodes); err != nil {
				c.nodes[i] = old
				return "", err
			}
			return token, nil
		}
	}
	return "", errors.New("node not found")
}

func (c *Controller) Delete(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, n := range c.nodes {
		if n.ID == id {
			old := c.nodes
			c.nodes = append(append([]Node{}, old[:i]...), old[i+1:]...)
			if err := c.db.SetSetting("cluster_nodes", c.nodes); err != nil {
				c.nodes = old
				return err
			}
			delete(c.probes, id)
			return nil
		}
	}
	return errors.New("node not found")
}

func (c *Controller) Snapshot() (Snapshot, error) {
	clients, err := c.db.ListClients()
	if err != nil {
		return Snapshot{}, err
	}
	policies, err := c.db.ListPolicies()
	if err != nil {
		return Snapshot{}, err
	}
	var allowAll bool
	if err := c.db.GetSetting("allow_all", &allowAll); err != nil {
		return Snapshot{}, err
	}
	var dnsSettings database.DNSSettings
	if err := c.db.GetSetting("dns", &dnsSettings); err != nil {
		return Snapshot{}, err
	}
	var accessSettings struct {
		DoHTokens []string `json:"doh_tokens"`
	}
	if err := c.db.GetSetting("access", &accessSettings); err != nil {
		return Snapshot{}, err
	}
	// Node snapshots carry only fields used for access and policy decisions.
	// Portal tokens, registration secrets, notes, and admin credentials stay on
	// the controller.
	for i := range clients {
		client := clients[i]
		clients[i] = database.Client{
			ID: client.ID, Name: client.Name, AllowedIPs: client.AllowedIPs,
			Enabled: client.Enabled, ExpiresAt: client.ExpiresAt,
			TrafficLimitGB: client.TrafficLimitGB, TrafficUsedBytes: client.TrafficUsedBytes,
			TrafficResetCount: client.TrafficResetCount,
			CustomPolicies:    client.CustomPolicies,
		}
	}
	s := Snapshot{Clients: clients, Policies: policies, AllowAll: allowAll, Upstreams: dnsSettings.Upstreams, DoHTokens: accessSettings.DoHTokens}
	body, err := json.Marshal(s)
	if err != nil {
		return Snapshot{}, err
	}
	hash := sha256.Sum256(body)
	s.Revision = hex.EncodeToString(hash[:])
	return s, nil
}

func (c *Controller) Start(bind string) error {
	if bind == "" {
		bind = "0.0.0.0:9443"
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.caCert)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll", c.enroll)
	mux.HandleFunc("/v1/snapshot", c.serveSnapshot)
	c.server = &http.Server{
		Addr: bind, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c.serverTLS},
			ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots,
		},
	}
	ln, err := tls.Listen("tcp", bind, c.server.TLSConfig)
	if err != nil {
		return err
	}
	go func() { _ = c.server.Serve(ln) }()
	c.probeStop = make(chan struct{})
	go c.probeLoop(c.probeStop)
	return nil
}

func (c *Controller) Stop(ctx context.Context) error {
	if c.probeStop != nil {
		close(c.probeStop)
		c.probeStop = nil
	}
	if c.server == nil {
		return nil
	}
	return c.server.Shutdown(ctx)
}

// probeLoop measures DNS service latency from the controller, not ICMP latency
// from a subscriber. A REFUSED DNS response still proves that the listener is up.
func (c *Controller) probeLoop(stop <-chan struct{}) {
	c.probeNodes()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			c.probeNodes()
		}
	}
}

func (c *Controller) probeNodes() {
	c.mu.Lock()
	nodes := append([]Node(nil), c.nodes...)
	c.mu.Unlock()
	var probes sync.WaitGroup
	limit := make(chan struct{}, 8)
	for _, n := range nodes {
		if !n.Enabled || !n.Enrolled {
			continue
		}
		limit <- struct{}{}
		probes.Add(1)
		go func(n Node) {
			defer probes.Done()
			defer func() { <-limit }()
			probe := probeDNS(net.JoinHostPort(n.PublicIP, "53"))
			c.mu.Lock()
			for _, current := range c.nodes {
				if current.ID == n.ID && current.Enabled && current.Enrolled {
					c.probes[n.ID] = probe
					break
				}
			}
			c.mu.Unlock()
		}(n)
	}
	probes.Wait()
}

func probeDNS(addr string) NodeProbe {
	probe := NodeProbe{CheckedAt: time.Now().UTC()}
	msg := new(mdns.Msg)
	msg.SetQuestion("hyperdns-probe.invalid.", mdns.TypeA)
	started := time.Now()
	if reply, _, err := (&mdns.Client{Net: "udp", Timeout: 2 * time.Second}).Exchange(msg, addr); err == nil && reply != nil {
		v := float64(time.Since(started).Microseconds()) / 1000
		probe.DNSReachable, probe.DNSRTTMs = true, &v
	}
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		probe.TCPReachable = true
		_ = conn.Close()
	}
	return probe
}

func (c *Controller) enroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct{ ID, Token, CSR string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil {
		http.Error(w, "invalid CSR", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != req.ID {
		http.Error(w, "invalid CSR", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.nodes {
		n := &c.nodes[i]
		if n.ID != req.ID {
			continue
		}
		got := sha256.Sum256([]byte(req.Token))
		want, _ := hex.DecodeString(n.EnrollmentHash)
		if !n.Enabled || n.Enrolled || len(want) != len(got) || subtle.ConstantTimeCompare(got[:], want) != 1 {
			http.Error(w, "invalid enrollment", http.StatusForbidden)
			return
		}
		certPEM, _, err := c.signCertificate(req.ID, csr.PublicKey, false)
		if err != nil {
			http.Error(w, "could not issue certificate", http.StatusInternalServerError)
			return
		}
		old := *n
		certBlock, _ := pem.Decode(certPEM)
		if certBlock == nil {
			http.Error(w, "could not issue certificate", http.StatusInternalServerError)
			return
		}
		fingerprint := sha256.Sum256(certBlock.Bytes)
		n.Enrolled, n.EnrollmentHash = true, ""
		n.CertFingerprint = hex.EncodeToString(fingerprint[:])
		if err := c.db.SetSetting("cluster_nodes", c.nodes); err != nil {
			*n = old
			http.Error(w, "could not save enrollment", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{"certificate": string(certPEM)})
		return
	}
	http.Error(w, "invalid enrollment", http.StatusForbidden)
}

func (c *Controller) serveSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	id := r.TLS.PeerCertificates[0].Subject.CommonName
	var telemetry NodeTelemetry
	telemetryValid := false
	if header := r.Header.Get("X-HyperDNS-Edge-Telemetry"); len(header) > 0 && len(header) < 2048 {
		if raw, err := base64.RawURLEncoding.DecodeString(header); err == nil {
			if json.Unmarshal(raw, &telemetry) == nil && validTelemetry(telemetry) {
				telemetry.CapturedAt = time.Now().UTC()
				telemetryValid = true
			}
		}
	}
	fingerprint := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	fingerprintHex := hex.EncodeToString(fingerprint[:])
	var nodeIP string
	c.mu.Lock()
	idx := -1
	for i, n := range c.nodes {
		if n.ID == id && n.Enabled && n.Enrolled && n.CertFingerprint == fingerprintHex {
			idx = i
			nodeIP = n.PublicIP
			break
		}
	}
	c.mu.Unlock()
	if idx < 0 {
		http.Error(w, "node disabled", http.StatusForbidden)
		return
	}
	s, err := c.Snapshot()
	if err != nil {
		http.Error(w, "snapshot unavailable", http.StatusInternalServerError)
		return
	}
	s.NodePublicIP = nodeIP
	c.mu.Lock()
	stillEnabled := false
	for i := range c.nodes {
		if c.nodes[i].ID == id && c.nodes[i].Enabled && c.nodes[i].Enrolled && c.nodes[i].CertFingerprint == fingerprintHex {
			stillEnabled = true
			old := c.nodes[i]
			c.nodes[i].LastSeen = time.Now().UTC()
			c.nodes[i].Revision = s.Revision
			if telemetryValid {
				c.nodes[i].Telemetry = telemetry
			}
			if err := c.db.SetSetting("cluster_nodes", c.nodes); err != nil {
				c.nodes[i] = old
			}
			break
		}
	}
	c.mu.Unlock()
	if !stillEnabled {
		http.Error(w, "node disabled", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", s.Revision)
	if r.Header.Get("If-None-Match") == s.Revision {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s)
}

func validTelemetry(t NodeTelemetry) bool {
	return !math.IsNaN(t.DNSQPS) && !math.IsInf(t.DNSQPS, 0) && t.DNSQPS >= 0 && t.DNSQPS <= 1e7 &&
		!math.IsNaN(t.CPUPercent) && !math.IsInf(t.CPUPercent, 0) && t.CPUPercent >= -1 && t.CPUPercent <= 100 &&
		!math.IsNaN(t.MemoryPercent) && !math.IsInf(t.MemoryPercent, 0) && t.MemoryPercent >= -1 && t.MemoryPercent <= 100 &&
		t.ActiveRelays >= 0 && t.UptimeSec >= 0
}
