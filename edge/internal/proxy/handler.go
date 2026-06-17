// edge/proxy — HTTP handler that fingerprints a ClientHello and forwards signals to the detector.
// Mints/keeps a session id, builds network signals, best-effort POSTs them to /ingest.

package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/signal"
)

// IDFunc mints a new correlation id.
type IDFunc func() (string, error)

// Handler routes the edge's HTTP surface.
type Handler struct {
	mux         *http.ServeMux
	detectorURL string
	hints       fingerprint.HintTable
	newID       IDFunc
	now         func() time.Time
	client      *http.Client
}

// New builds a Handler. detectorURL may be empty to disable forwarding (e.g. in tests).
func New(detectorURL string, hints fingerprint.HintTable, newID IDFunc, now func() time.Time) *Handler {
	h := &Handler{
		detectorURL: detectorURL,
		hints:       hints,
		newID:       newID,
		now:         now,
		client:      &http.Client{Timeout: 5 * time.Second},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("POST /fingerprint", h.fingerprint)
	h.mux = mux
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

type fpRequest struct {
	ClientHelloB64 string `json:"client_hello_b64"`
	SessionID      string `json:"session_id"`
}

type fpResponse struct {
	SessionID string          `json:"session_id"`
	Signals   []signal.Signal `json:"signals"`
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) fingerprint(w http.ResponseWriter, r *http.Request) {
	var req fpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.ClientHelloB64)
	if err != nil {
		http.Error(w, "invalid base64", http.StatusBadRequest)
		return
	}
	ch, err := fingerprint.ParseClientHello(raw)
	if err != nil {
		http.Error(w, "invalid client hello", http.StatusUnprocessableEntity)
		return
	}
	sid := req.SessionID
	if sid == "" {
		if sid, err = h.newID(); err != nil {
			http.Error(w, "could not mint session id", http.StatusInternalServerError)
			return
		}
	}
	sigs := signal.FromClientHello(sid, ch, h.hints, h.now())
	h.forward(sigs)
	writeJSON(w, http.StatusOK, fpResponse{SessionID: sid, Signals: sigs})
}

// forward best-effort POSTs signals to the detector; failures are non-fatal for the edge.
func (h *Handler) forward(sigs []signal.Signal) {
	if h.detectorURL == "" {
		return
	}
	body, err := signal.Marshal(sigs)
	if err != nil {
		return
	}
	resp, err := h.client.Post(h.detectorURL+"/ingest", "application/json", bytes.NewReader(body))
	if err == nil {
		_ = resp.Body.Close()
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
