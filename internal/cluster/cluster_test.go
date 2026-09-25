package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"hyperdns/internal/core/dns"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
)

func clusterTestDB(t *testing.T) *database.DB {
	t.Helper()
	dir := t.TempDir()
	cipher, err := crypto.LoadOrGenerateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Create(filepath.Join(dir, "data.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestProbeDNSMeasuresUDPAndTCPService(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	addr := packet.LocalAddr().String()
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		buf := make([]byte, 4096)
		n, remote, err := packet.ReadFrom(buf)
		if err != nil {
			return
		}
		query := new(mdns.Msg)
		if query.Unpack(buf[:n]) != nil {
			return
		}
		reply := new(mdns.Msg)
		reply.SetRcode(query, mdns.RcodeRefused)
		wire, err := reply.Pack()
		if err == nil {
			_, _ = packet.WriteTo(wire, remote)
		}
	}()
	probe := probeDNS(addr)
	if !probe.DNSReachable || !probe.TCPReachable || probe.DNSRTTMs == nil || *probe.DNSRTTMs < 0 {
		t.Fatalf("healthy DNS service reported %+v", probe)
	}
}

func TestEnrollmentIsSingleUseAndDisabledNodeCannotReadSnapshot(t *testing.T) {
	db := clusterTestDB(t)
	if err := db.SaveClient(database.Client{
		ID: "client-1", Name: "Subscriber", Token: "portal-secret",
		RegisterSecret: "registration-secret", Note: "private note",
		AllowedIPs: []string{"8.8.4.4"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SavePolicy(database.Policy{Key: "custom_proxied", CustomDomains: []string{"example.test"}}); err != nil {
		t.Fatal(err)
	}
	c, err := NewController(db, "https://controller.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	node, token, err := c.Create("Paris", "France", "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.BootstrapNode(node.ID, token); !ok {
		t.Fatal("valid one-time installer token was refused")
	}
	if _, ok := c.BootstrapNode(node.ID, "wrong"); ok {
		t.Fatal("invalid installer token was accepted")
	}

	roots := x509.NewCertPool()
	roots.AddCert(c.caCert)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll", c.enroll)
	mux.HandleFunc("/v1/snapshot", c.serveSnapshot)
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{c.serverTLS}, MinVersion: tls.VersionTLS13,
		ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots,
	}
	server.StartTLS()
	defer server.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte(c.CAPEM()), 0600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{ID: node.ID, Token: token, URL: server.URL, CAFile: caPath, StateDir: t.TempDir(), PublicIP: node.PublicIP}
	if err := a.Connect(); err != nil {
		t.Fatal(err)
	}
	if !c.List()[0].Enrolled {
		t.Fatal("node was not marked enrolled")
	}
	if _, ok := c.BootstrapNode(node.ID, token); ok {
		t.Fatal("installer token remained valid after enrollment")
	}

	second := &Agent{ID: node.ID, Token: token, URL: server.URL, CAFile: caPath, StateDir: t.TempDir(), PublicIP: node.PublicIP}
	if err := second.Connect(); err == nil {
		t.Fatal("enrollment token was accepted twice")
	}

	res, err := a.client.Get(server.URL + "/v1/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("snapshot: status %d, error %v", res.StatusCode, err)
	}
	for _, secret := range []string{"portal-secret", "registration-secret", "private note"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("snapshot leaked %q", secret)
		}
	}
	if !strings.Contains(string(body), "8.8.4.4") {
		t.Fatal("snapshot omitted the allowed client IP")
	}

	edgeDB := clusterTestDB(t)
	access := NewEdgeState()
	pool := upstream.NewUpstreamPool([]string{"1.1.1.1:53"}, time.Second, false, "")
	handler := dns.NewHandler(access, nil, matcher.NewMatcher(), pool, nil, node.PublicIP)
	a.DB, a.Access, a.DNS, a.Upstreams = edgeDB, access, handler, pool
	a.Telemetry = func() NodeTelemetry {
		return NodeTelemetry{DNSQueries: 42, DNSQPS: 2.5, CPUPercent: 18, MemoryPercent: 31, UptimeSec: 90}
	}
	if err := a.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := c.List()[0].Telemetry; got.DNSQueries != 42 || got.DNSQPS != 2.5 || got.CapturedAt.IsZero() {
		t.Fatalf("edge telemetry not recorded: %+v", got)
	}
	query := new(mdns.Msg)
	query.SetQuestion("example.test.", mdns.TypeA)
	answer := handler.ProcessQuery(query, "8.8.4.4")
	if len(answer.Answer) != 1 {
		t.Fatalf("proxied answer has %d records", len(answer.Answer))
	}
	if ip := answer.Answer[0].(*mdns.A).A.String(); ip != node.PublicIP {
		t.Fatalf("edge proxied to %s, want %s", ip, node.PublicIP)
	}
	if err := a.SyncOnce(t.Context()); err != nil {
		t.Fatalf("unchanged snapshot: %v", err)
	}

	if err := c.SetEnabled(node.ID, false); err != nil {
		t.Fatal(err)
	}
	res, err = a.client.Get(server.URL + "/v1/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("disabled node received %d, want 403", res.StatusCode)
	}
	if err := a.SyncOnce(t.Context()); err == nil {
		t.Fatal("disabled edge sync was accepted")
	}
	if _, ok := access.IsIPAllowed("8.8.4.4"); ok {
		t.Fatal("disabled node kept serving its old snapshot")
	}

	if err := c.SetEnabled(node.ID, true); err != nil {
		t.Fatal(err)
	}
	newToken, err := c.ResetEnrollment(node.ID)
	if err != nil || newToken == token {
		t.Fatal("reset did not rotate token")
	}
	res, err = a.client.Get(server.URL + "/v1/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("old certificate after reset received %d", res.StatusCode)
	}
	oldClient := a.client
	a.Token = newToken
	if err := a.Connect(); err != nil {
		t.Fatalf("re-enrollment: %v", err)
	}
	res, err = oldClient.Get(server.URL + "/v1/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("old certificate regained access after re-enrollment: %d", res.StatusCode)
	}
}

func TestEdgeSnapshotExpiresClosed(t *testing.T) {
	state := NewEdgeState()
	s := Snapshot{Revision: "revision", Clients: []database.Client{{
		ID: "client-1", AllowedIPs: []string{"8.8.8.8"}, Enabled: true,
		ExpiresAt: time.Now().Add(time.Hour),
	}}}
	if _, err := state.Apply(s, time.Now().Add(-6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := state.IsIPAllowed("8.8.8.8"); ok {
		t.Fatal("stale snapshot allowed traffic")
	}
	if _, err := state.Apply(s, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok := state.IsIPAllowed("8.8.8.8"); !ok {
		t.Fatal("fresh snapshot refused client")
	}
	s.Clients[0].ExpiresAt = time.Now().Add(-time.Second)
	if _, err := state.Apply(s, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok := state.IsIPAllowed("8.8.8.8"); ok {
		t.Fatal("expired client remained allowed")
	}
}

func TestEdgeLocalQuotaClearsWhenControllerResetsCycle(t *testing.T) {
	state := NewEdgeState()
	s := Snapshot{Revision: "revision", Clients: []database.Client{{
		ID: "client-1", AllowedIPs: []string{"8.8.8.8"}, Enabled: true,
		TrafficLimitGB: 1.0 / (1 << 30),
	}}}
	if _, err := state.Apply(s, time.Now()); err != nil {
		t.Fatal(err)
	}
	client, ok := state.IsIPAllowed("8.8.8.8")
	if !ok {
		t.Fatal("client refused")
	}
	state.AddTraffic(client.ID, 2)
	if !state.QuotaExceeded(client) {
		t.Fatal("local usage did not enforce quota")
	}
	s.Clients[0].TrafficResetCount = 1
	if _, err := state.Apply(s, time.Now()); err != nil {
		t.Fatal(err)
	}
	client, _ = state.IsIPAllowed("8.8.8.8")
	if state.QuotaExceeded(client) {
		t.Fatal("previous cycle's local usage survived rollover")
	}
}

func TestControllerRestoresClusterIdentity(t *testing.T) {
	db := clusterTestDB(t)
	first, err := NewController(db, "https://controller.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	node, token, err := first.Create("Berlin", "Germany", "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewController(db, "https://controller.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	if restarted.CAPEM() != first.CAPEM() || len(restarted.List()) != 1 || restarted.List()[0].ID != node.ID {
		t.Fatal("controller restart changed the cluster CA or lost a node")
	}
	var stored []Node
	if err := db.GetSetting("cluster_nodes", &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].EnrollmentHash == "" || stored[0].EnrollmentHash == token {
		t.Fatal("enrollment token was not stored as a hash")
	}
}
