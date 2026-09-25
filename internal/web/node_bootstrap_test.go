package web

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"hyperdns/internal/cluster"
)

func TestEdgeBootstrapRequiresLiveOneTimeToken(t *testing.T) {
	ws, db, cleanup := setupTestWebServer(t)
	defer cleanup()
	controller, err := cluster.NewController(db, "https://controller.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	ws.SetClusterController(controller)
	node, token, err := controller.Create("Paris", "France", "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	path := "/edge/bootstrap/" + node.ID + "/" + token
	req := httptest.NewRequest(http.MethodGet, "https://panel.example"+path, nil)
	got := httptest.NewRecorder()
	ws.BuildHandler().ServeHTTP(got, req)
	if got.Code != http.StatusOK {
		t.Fatalf("bootstrap = %d: %s", got.Code, got.Body.String())
	}
	if !strings.Contains(got.Body.String(), "NODE_ID='"+node.ID+"'") || !strings.Contains(got.Body.String(), "HYPERDNS_CLUSTER_CA") {
		t.Fatal("bootstrap script omitted node identity or pinned CA")
	}
	check := exec.Command("bash", "-n")
	check.Stdin = strings.NewReader(got.Body.String())
	if out, err := check.CombinedOutput(); err != nil {
		t.Fatalf("generated shell syntax: %v: %s", err, out)
	}

	for _, suffix := range []string{"/wrong", "/" + token + "/extra"} {
		bad := httptest.NewRecorder()
		ws.BuildHandler().ServeHTTP(bad, httptest.NewRequest(http.MethodGet, "https://panel.example/edge/bootstrap/"+node.ID+suffix, nil))
		if bad.Code != http.StatusNotFound {
			t.Fatalf("bad token/path returned %d", bad.Code)
		}
	}
	plain := httptest.NewRecorder()
	ws.BuildHandler().ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "http://panel.example"+path, nil))
	if plain.Code != http.StatusNotFound {
		t.Fatalf("plaintext bootstrap returned %d", plain.Code)
	}
	if err := controller.SetEnabled(node.ID, false); err != nil {
		t.Fatal(err)
	}
	denied := httptest.NewRecorder()
	ws.BuildHandler().ServeHTTP(denied, req)
	if denied.Code != http.StatusNotFound {
		t.Fatalf("disabled node bootstrap returned %d", denied.Code)
	}
}
