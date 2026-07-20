// Package dr provides the disaster-recovery console: replication/recovery status
// for this instance's database, peer-instance health, and administrator-triggered
// failover / failback. Everything here is gated by DR.Manage.
//
// Scope boundary (important, and mirrored in docs/disaster-recovery.md): Fleet does
// NOT replicate the database or move DNS itself. The failover/failback actions
// record intent (audited), optionally promote THIS instance's PostgreSQL via
// pg_promote(), and POST to an operator-configured webhook that wires the real
// steps (DB promotion, DNS repoint, standby jump-host WireGuard bring-up). The
// console reflects state and triggers orchestration; it is not the orchestrator.
package dr

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// Mount attaches DR routes, gated by DR.Manage.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d, http: &http.Client{Timeout: 8 * time.Second}}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("DR.Manage"))
		pr.Get("/dr/status", h.status)
		pr.Put("/dr/config", h.setConfig)
		pr.Post("/dr/failover", h.failover)
		pr.Post("/dr/failback", h.failback)
		pr.Post("/dr/promote", h.promote)
	})
}

type handler struct {
	d    *app.Deps
	http *http.Client
}

// MountPublic mounts the unauthenticated GET /dr/mode in NORMAL operation, so the
// SPA can detect posture on load without logging in. It always reports standby:false
// here — a standby instance mounts the standby variant instead (MountStandby).
func MountPublic(r chi.Router) {
	r.Get("/dr/mode", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"standby": false})
	})
}

// MountStandby mounts the entire API surface for a read-only DR standby instance:
// GET /dr/mode (reports standby + live replication lag) and POST /dr/standby/promote
// (a write-free, token-gated break-glass promotion). No other routes exist, and no
// endpoint here writes to the database (a replica can't) except pg_promote(), which
// is a promotion request, not a table write.
func MountStandby(r chi.Router, d *app.Deps, token string) {
	h := &standbyHandler{d: d, token: token}
	r.Get("/dr/mode", h.mode)
	r.Get("/dr/standby/status", h.mode)
	r.Post("/dr/standby/promote", h.promoteAndRestart)
}

// status reports the DR configuration, this DB's replication posture, and peer
// reachability, so the console can show readiness before an admin acts.
func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	cfg := h.d.Store.DRConfig(r.Context())
	repl, err := h.d.Store.DBReplication(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read replication status")
		return
	}
	peer := h.peerHealth(r.Context(), cfg.PeerURL)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"config":      cfg,
		"replication": repl,
		"peer":        peer,
	})
}

type peerStatus struct {
	Configured bool   `json:"configured"`
	Reachable  bool   `json:"reachable"`
	Detail     string `json:"detail"`
}

// peerHealth probes the peer instance's /ready endpoint (best-effort).
func (h *handler) peerHealth(ctx context.Context, peerURL string) peerStatus {
	if peerURL == "" {
		return peerStatus{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, trimSlash(peerURL)+"/ready", nil)
	if err != nil {
		return peerStatus{Configured: true, Detail: "invalid peer URL"}
	}
	resp, err := h.http.Do(req)
	if err != nil {
		return peerStatus{Configured: true, Reachable: false, Detail: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return peerStatus{Configured: true, Reachable: true, Detail: "ready"}
	}
	return peerStatus{Configured: true, Reachable: false, Detail: resp.Status}
}

type configReq struct {
	Role            string `json:"role"`
	PeerURL         string `json:"peerUrl"`
	FailoverWebhook string `json:"failoverWebhook"`
	FailbackWebhook string `json:"failbackWebhook"`
}

func (h *handler) setConfig(w http.ResponseWriter, r *http.Request) {
	var rq configReq
	if !httpx.Decode(w, r, &rq) {
		return
	}
	switch rq.Role {
	case "", "standalone":
		rq.Role = "standalone"
	case "primary", "standby":
	default:
		httpx.WriteError(w, http.StatusBadRequest, "role must be standalone, primary, or standby")
		return
	}
	cfg := store.DRConfig{
		Role: rq.Role, PeerURL: rq.PeerURL,
		FailoverWebhook: rq.FailoverWebhook, FailbackWebhook: rq.FailbackWebhook,
	}
	if err := h.d.Store.SetDRConfig(r.Context(), cfg); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save DR config")
		return
	}
	h.audit(r, "dr.config_update", map[string]any{"role": cfg.Role})
	httpx.WriteJSON(w, http.StatusOK, cfg)
}

// actionReq is the body for failover/failback. promoteLocalDb, when true, also runs
// pg_promote() on this instance's DB (use it on the standby that is taking over).
type actionReq struct {
	PromoteLocalDb bool `json:"promoteLocalDb"`
}

func (h *handler) failover(w http.ResponseWriter, r *http.Request) { h.action(w, r, "failover") }
func (h *handler) failback(w http.ResponseWriter, r *http.Request) { h.action(w, r, "failback") }

// action runs a failover or failback: optionally promote the local DB, fire the
// configured webhook, and audit — reporting each step's outcome so the admin sees
// exactly what happened rather than a single opaque success/fail.
func (h *handler) action(w http.ResponseWriter, r *http.Request, kind string) {
	var rq actionReq
	_ = json.NewDecoder(r.Body).Decode(&rq)
	cfg := h.d.Store.DRConfig(r.Context())

	steps := []map[string]any{}
	overallOK := true

	if rq.PromoteLocalDb {
		ok, err := h.d.Store.PromoteDB(r.Context())
		step := map[string]any{"step": "promote_local_db", "ok": ok && err == nil}
		if err != nil {
			step["error"] = err.Error()
			overallOK = false
		}
		steps = append(steps, step)
	}

	hook := cfg.FailoverWebhook
	if kind == "failback" {
		hook = cfg.FailbackWebhook
	}
	if hook != "" {
		err := h.fireWebhook(r.Context(), hook, kind)
		step := map[string]any{"step": "webhook", "ok": err == nil}
		if err != nil {
			step["error"] = err.Error()
			overallOK = false
		}
		steps = append(steps, step)
	} else {
		steps = append(steps, map[string]any{"step": "webhook", "ok": true, "skipped": "no webhook configured"})
	}

	h.audit(r, "dr."+kind, map[string]any{"promoteLocalDb": rq.PromoteLocalDb, "webhook": hook != "", "ok": overallOK})
	status := http.StatusOK
	if !overallOK {
		status = http.StatusBadGateway
	}
	httpx.WriteJSON(w, status, map[string]any{"ok": overallOK, "steps": steps})
}

// promote runs pg_promote() on this instance's DB with no other side effects — the
// composable primitive behind the "promote local database" button.
func (h *handler) promote(w http.ResponseWriter, r *http.Request) {
	ok, err := h.d.Store.PromoteDB(r.Context())
	if err != nil {
		h.audit(r, "dr.promote", map[string]any{"ok": false, "error": err.Error()})
		httpx.WriteError(w, http.StatusBadGateway, "pg_promote failed: "+err.Error())
		return
	}
	h.audit(r, "dr.promote", map[string]any{"ok": ok})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": ok})
}

// fireWebhook POSTs a small JSON event to the operator's orchestration endpoint.
func (h *handler) fireWebhook(ctx context.Context, url, kind string) error {
	body, _ := json.Marshal(map[string]any{
		"event":     "dr." + kind,
		"instance":  h.d.Cfg.PublicURL,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return &httpError{resp.Status}
	}
	return nil
}

type httpError struct{ status string }

func (e *httpError) Error() string { return "webhook returned " + e.status }

func (h *handler) audit(r *http.Request, action string, detail map[string]any) {
	p := auth.MustPrincipal(r)
	if p == nil {
		return
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: action,
		TargetKind: "dr", Detail: detail,
	})
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
