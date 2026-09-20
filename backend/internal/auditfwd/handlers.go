package auditfwd

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// Mount attaches audit-forwarding settings routes (System.Configure only). It
// takes the auth service directly to avoid an app.Deps import cycle.
func Mount(r chi.Router, a *auth.Service, f *Forwarder) {
	h := &handler{f: f}
	r.Group(func(pr chi.Router) {
		pr.Use(a.RequireAuth)
		pr.With(a.RequirePermission("System.Configure")).Get("/audit/forwarding", h.get)
		pr.With(a.RequirePermission("System.Configure")).Put("/audit/forwarding", h.put)
		pr.With(a.RequirePermission("System.Configure")).Post("/audit/forwarding/test", h.test)
	})
}

type handler struct{ f *Forwarder }

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	// Redacted: the collector token used to come straight back out of here, in
	// plaintext, which is not what any other configuration endpoint in this product
	// does with a secret. tokenSet says whether one is configured.
	httpx.WriteJSON(w, http.StatusOK, h.f.LoadConfig(r.Context()).Redacted())
}

func (h *handler) put(w http.ResponseWriter, r *http.Request) {
	var c Config
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&c); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.f.SaveConfig(r.Context(), c); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save settings")
		return
	}
	httpx.Audit(r, h.f.store, models.AuditEvent{Action: "system.audit_forwarding", TargetKind: "system",
		Detail: map[string]any{"enabled": c.Enabled, "type": c.Type}})
	// Read back what was stored rather than echoing the request: the response used
	// to hand the token straight back to the caller that had just sent it, which is
	// how it ended up in browser devtools and proxy logs as well as the database.
	httpx.WriteJSON(w, http.StatusOK, h.f.LoadConfig(r.Context()).Redacted())
}

func (h *handler) test(w http.ResponseWriter, r *http.Request) {
	// An empty body means "test what is saved", which is what pressing Test after
	// saving asks for. It used to answer {"error":"invalid request body"} — a
	// perfectly good configuration reported as a bad request, from the one button
	// whose job is to tell you whether the configuration works.
	c := h.f.LoadConfig(r.Context())
	var sent Config
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&sent)
	switch {
	case err == nil:
		// A body was supplied: test THAT, so a target can be tried before it is
		// saved. An omitted token falls back to the stored one, so testing an
		// unchanged target does not need the secret sent back up.
		if sent.Token == "" && sent.TokenEnc == "" {
			sent.Token = c.Token
		}
		c = sent
	case errors.Is(err, io.EOF):
		// No body at all. Keep the stored configuration.
	default:
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.f.SendTest(c); err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
