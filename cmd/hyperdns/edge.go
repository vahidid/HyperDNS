package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"hyperdns/internal/bootstrap"
	"hyperdns/internal/cluster"
	"hyperdns/internal/core/cache"
	"hyperdns/internal/core/dns"
	"hyperdns/internal/core/matcher"
	"hyperdns/internal/core/proxy"
	"hyperdns/internal/core/upstream"
	"hyperdns/internal/crypto"
	"hyperdns/internal/database"
	"hyperdns/internal/service"
)

type edgeOptions struct {
	DBPath, KeyPath, ConfigPath, BindHost, PublicIP    string
	ControllerURL, NodeID, TokenFile, CAFile, StateDir string
	DNSPort                                            int
}

func runEdge(o edgeOptions) error {
	if ip := net.ParseIP(o.PublicIP); ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return errors.New("-public-ip must be this node's public IPv4 address")
	}
	if o.DBPath == "" {
		o.DBPath = "edge-data.db"
	}
	if o.KeyPath == "" {
		o.KeyPath = "edge-master.key"
	}
	if o.StateDir == "" {
		o.StateDir = filepath.Join(filepath.Dir(o.DBPath), "cluster-node")
	}
	state, err := bootstrap.ClassifyPaths(o.DBPath, o.KeyPath)
	if err != nil {
		return err
	}
	cipher, err := crypto.LoadOrGenerateMasterKey(o.KeyPath)
	if err != nil {
		return err
	}
	var db *database.DB
	if state == bootstrap.PathsComplete {
		db, err = database.OpenExisting(o.DBPath, cipher)
	} else {
		db, err = database.Create(o.DBPath, cipher)
	}
	if err != nil {
		return err
	}
	defer db.Close()

	serverSettings := &database.ServerSettings{BindHost: "0.0.0.0", PublicIP: o.PublicIP}
	dnsSettings := &database.DNSSettings{
		Enabled: true, Port: 53, DoTPort: 853, DoHPort: 8443,
		Upstreams: []string{"1.1.1.1:53", "8.8.8.8:53"},
		CacheSize: 20000, CacheMinTTL: 60, CacheMaxTTL: 86400,
		QueryTimeout: 2 * time.Second, FastestRacing: true, ServeStaleSeconds: 30,
	}
	sniSettings := &database.SNIProxySettings{
		Enabled: true, HTTPPort: 80, HTTPSPort: 443,
		GameChatTLSPort: 5223, GameChatXMPPPort: 5222, RiotRTMPort: 2099, RiotPatcherPort: 8393,
		Timeout: 120 * time.Second, EnableFragmentation: true, FragmentSize: 2, FragmentDelayMs: 5,
	}
	tlsSettings := &database.TLSSettings{}
	if o.ConfigPath != "" {
		applyConfigFile(o.ConfigPath, serverSettings, dnsSettings, sniSettings, tlsSettings)
	}
	if o.BindHost != "" {
		serverSettings.BindHost = o.BindHost
	}
	if o.DNSPort > 0 {
		dnsSettings.Port = o.DNSPort
	}
	serverSettings.PublicIP = o.PublicIP

	access := cluster.NewEdgeState()
	c := cache.NewCache(dnsSettings.CacheSize, dnsSettings.CacheMinTTL, dnsSettings.CacheMaxTTL)
	defer c.Close()
	c.SetStaleWindow(time.Duration(dnsSettings.ServeStaleSeconds) * time.Second)
	m := matcher.NewMatcher()
	u := upstream.NewUpstreamPool(dnsSettings.Upstreams, dnsSettings.QueryTimeout, dnsSettings.FastestRacing, dnsSettings.ECSClientIP)
	sniServer := proxy.NewServer(*sniSettings, serverSettings.BindHost, "", access)
	stats := service.NewStatsService(db, sniServer.GetStats, c.GetStats)
	defer stats.Close()
	dnsHandler := dns.NewHandler(access, c, m, u, stats, o.PublicIP)
	dohHandler := dns.NewDoHHandler(dnsHandler)
	var joinToken string
	if o.TokenFile != "" {
		info, err := os.Stat(o.TokenFile)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			if info.Mode().Perm()&0077 != 0 {
				return errors.New("join-token-file must be readable only by its owner")
			}
			body, err := os.ReadFile(o.TokenFile)
			if err != nil {
				return err
			}
			joinToken = strings.TrimSpace(string(body))
		}
	}
	agent := &cluster.Agent{
		ID: o.NodeID, PublicIP: o.PublicIP, URL: o.ControllerURL, Token: joinToken,
		CAFile: o.CAFile, StateDir: o.StateDir, DB: db, Access: access,
		DNS: dnsHandler, DoH: dohHandler, Upstreams: u,
		Telemetry: func() cluster.NodeTelemetry {
			live := stats.GetLiveStats()
			return cluster.NodeTelemetry{
				DNSQueries: live.TotalQueries, DNSQPS: live.QPS,
				CPUPercent: live.SystemCPUPercent, MemoryPercent: live.SystemMemPercent,
				ActiveRelays: live.ActiveRelays, ProxyBytesSent: live.BytesSent,
				ProxyBytesRecv: live.BytesRecv, UptimeSec: live.UptimeSec,
			}
		},
	}
	if err := agent.Connect(); err != nil {
		return err
	}
	if o.TokenFile != "" && joinToken != "" {
		if err := os.Remove(o.TokenFile); err != nil {
			log.Printf("[Edge] Remove used join-token-file: %v", err)
		}
	}
	if err := agent.LoadSaved(); err != nil {
		return err
	}
	initialCtx, initialCancel := context.WithTimeout(context.Background(), 12*time.Second)
	err = agent.SyncOnce(initialCtx)
	initialCancel()
	if err != nil {
		// A recent encrypted snapshot keeps an existing node usable during a
		// short controller outage. A new node must receive its first snapshot.
		if !access.HasFreshSnapshot() {
			return fmt.Errorf("initial snapshot unavailable: %w", err)
		}
		log.Printf("[Edge] Controller unavailable; using recent snapshot: %v", err)
	}

	var dohMux http.Handler
	var tlsConfig *tls.Config
	if tlsSettings.Domain != "" {
		tlsConfig, err = service.LoadOrGenerateTLSConfig(tlsSettings)
		if err != nil {
			return fmt.Errorf("edge DoT/DoH certificate: %w", err)
		}
		mux := http.NewServeMux()
		mux.Handle("/dns-query", dohHandler)
		dohMux = mux
	}
	dnsServer := dns.NewServer(dnsHandler, tlsConfig, dohMux, serverSettings.BindHost, dnsSettings.Port, dnsSettings.DoTPort, dnsSettings.DoHPort)
	if err := dnsServer.Start(); err != nil {
		return err
	}
	if sniSettings.Enabled {
		if err := sniServer.Start(); err != nil {
			dnsServer.Stop()
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("[Edge] Node %s serving DNS on %s:%d and proxy on %s", o.NodeID, serverSettings.BindHost, dnsSettings.Port, o.PublicIP)
	syncDone := make(chan struct{})
	go func() {
		defer close(syncDone)
		agent.Run(ctx, func(err error) { log.Printf("[Edge] Snapshot sync: %v", err) })
	}()
	<-ctx.Done()
	<-syncDone
	dnsServer.Stop()
	sniServer.Stop()
	return nil
}
