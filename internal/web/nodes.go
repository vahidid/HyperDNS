package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"hyperdns/internal/httpx"
)

func (ws *WebServer) handleNodes(w http.ResponseWriter, r *http.Request) {
	if ws.cluster == nil {
		httpx.WriteJSONError(w, http.StatusConflict, "Start HyperDNS with -role controller to manage nodes")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"nodes": ws.cluster.List(), "controller_url": ws.cluster.ControllerURL,
			"ca_pem": ws.cluster.CAPEM(),
		})
	case http.MethodPost:
		var req struct {
			Name     string `json:"name"`
			Location string `json:"location"`
			PublicIP string `json:"public_ip"`
			Password string `json:"password"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid node request")
			return
		}
		if !ws.reauthCurrentPassword(req.Password) {
			httpx.WriteJSONError(w, http.StatusForbidden, "Current admin password is required")
			return
		}
		node, token, err := ws.cluster.Create(req.Name, req.Location, req.PublicIP)
		if err != nil {
			httpx.WriteJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node": node, "join_token": token, "controller_url": ws.cluster.ControllerURL,
			"ca_pem": ws.cluster.CAPEM(),
		})
	default:
		httpx.WriteMethodNotAllowed(w, "GET, POST")
	}
}

func (ws *WebServer) handleNodeAction(w http.ResponseWriter, r *http.Request) {
	if ws.cluster == nil {
		httpx.WriteJSONError(w, http.StatusConflict, "Start HyperDNS with -role controller to manage nodes")
		return
	}
	if r.Method != http.MethodPost {
		httpx.WriteMethodNotAllowed(w, "POST")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/nodes/"), "/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		httpx.WriteJSONError(w, http.StatusNotFound, "Unknown node action")
		return
	}
	var req struct {
		Password string `json:"password"`
		Enabled  bool   `json:"enabled"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "Invalid node request")
		return
	}
	if !ws.reauthCurrentPassword(req.Password) {
		httpx.WriteJSONError(w, http.StatusForbidden, "Current admin password is required")
		return
	}
	var err error
	var token string
	switch parts[1] {
	case "enabled":
		err = ws.cluster.SetEnabled(parts[0], req.Enabled)
	case "delete":
		err = ws.cluster.Delete(parts[0])
	case "reset-enrollment":
		token, err = ws.cluster.ResetEnrollment(parts[0])
	default:
		httpx.WriteJSONError(w, http.StatusNotFound, "Unknown node action")
		return
	}
	if err != nil {
		httpx.WriteJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "join_token": token})
}
