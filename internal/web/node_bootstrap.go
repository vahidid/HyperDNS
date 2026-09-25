package web

import (
	"embed"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
)

//go:embed edge-bootstrap.sh
var edgeBootstrapFS embed.FS

var edgeBootstrapTemplate = template.Must(template.New("edge-bootstrap.sh").ParseFS(edgeBootstrapFS, "edge-bootstrap.sh"))

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func (ws *WebServer) handleEdgeBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if ws.cluster == nil || r.TLS == nil || strings.ContainsAny(r.Host, " \t\r\n/\\'\"") {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/edge/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 || len(parts) > 4 || (parts[0] != "bootstrap" && parts[0] != "binary") {
		http.NotFound(w, r)
		return
	}
	if (parts[0] == "bootstrap" && len(parts) != 3) || (parts[0] == "binary" && len(parts) != 4) {
		http.NotFound(w, r)
		return
	}
	node, valid := ws.cluster.BootstrapNode(parts[1], parts[2])
	if !valid {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if parts[0] == "binary" {
		binary, ok := edgeBinary(parts[3])
		if !ok {
			http.Error(w, "Edge binary unavailable for this architecture", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=hyperdns")
		http.ServeFile(w, r, binary)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_ = edgeBootstrapTemplate.Execute(w, struct {
		PanelBase, ControllerURL, NodeID, NodeIP, JoinToken, CAPEM string
	}{
		PanelBase: shellQuote("https://" + r.Host), ControllerURL: shellQuote(ws.cluster.ControllerURL),
		NodeID: shellQuote(node.ID), NodeIP: shellQuote(node.PublicIP),
		JoinToken: shellQuote(parts[2]), CAPEM: ws.cluster.CAPEM(),
	})
}

// edgeBinary prefers the running controller binary for its architecture, so
// operators can deploy one build and immediately join like-for-like servers.
// A different Linux architecture can be uploaded to edge-binaries explicitly.
func edgeBinary(arch string) (string, bool) {
	if arch != "amd64" && arch != "arm64" {
		return "", false
	}
	if runtime.GOOS == "linux" && arch == runtime.GOARCH {
		path, err := os.Executable()
		return path, err == nil
	}
	path := filepath.Join("/opt/hyperdns/edge-binaries", "hyperdns-linux-"+arch)
	info, err := os.Stat(path)
	return path, err == nil && info.Mode().IsRegular()
}
