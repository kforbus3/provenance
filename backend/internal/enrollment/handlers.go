package enrollment

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
)

// Mount attaches enrollment routes. Enrollment uses the caller's live session
// certificate, so routes require authentication + Host.Enroll.
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}
	// SSH-agent enrollment is a WebSocket; it authenticates with a query-param
	// token (browsers/CLIs can't set headers on the upgrade) inside the handler.
	r.Get("/hosts/{id}/enroll/agent", h.enrollAgent)
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Host.Enroll")).Post("/hosts/{id}/enroll", h.enroll)
		// No-install flow: fetch a bootstrap script the operator pipes through
		// their own ssh, then finish with the host public key they paste back.
		pr.With(d.Auth.RequirePermission("Host.Enroll")).Get("/hosts/{id}/enroll/script", h.enrollScript)
		pr.With(d.Auth.RequirePermission("Host.Enroll")).Post("/hosts/{id}/enroll/finish", h.enrollFinish)
		pr.With(d.Auth.RequirePermission("Host.Enroll")).Get("/enrollment/jobs", h.listJobs)
		pr.With(d.Auth.RequirePermission("Host.Enroll")).Get("/enrollment/jobs/{id}", h.getJob)
	})
}

type handler struct {
	d   *app.Deps
	svc *Service
}

type enrollReq struct {
	Method        string `json:"method"`        // "password" | "key" | "trusted"
	BootstrapUser string `json:"bootstrapUser"` // SSH user for password/key bootstrap
	Password      string `json:"password"`      // SSH password for bootstrap
	PrivateKey    string `json:"privateKey"`    // PEM private key for "key" bootstrap
	KeyPassphrase string `json:"keyPassphrase"` // passphrase for an encrypted key
	SudoPassword  string `json:"sudoPassword"`  // sudo password (if sudo needs one)
	WGEndpoint    string `json:"wgEndpoint"`    // jump host's public WireGuard endpoint
	ViaJump       bool   `json:"viaJump"`       // route bootstrap through the jump host
	SkipWireGuard bool   `json:"skipWireGuard"` // host is directly reachable from the jump host
}

func (h *handler) enroll(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	hostID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	host, err := h.d.Store.GetHost(r.Context(), hostID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return
	}
	var req enrollReq
	_ = json.NewDecoder(r.Body).Decode(&req) // body optional; defaults to trusted
	if req.Method == "password" && req.Password == "" {
		httpx.WriteError(w, http.StatusBadRequest, "password is required for password bootstrap")
		return
	}
	if req.Method == "key" && req.PrivateKey == "" {
		httpx.WriteError(w, http.StatusBadRequest, "private key is required for key bootstrap")
		return
	}
	res, err := h.svc.Enroll(r.Context(), p.SessionID, host, &p.UserID, EnrollParams{
		Method: req.Method, BootstrapUser: req.BootstrapUser, Password: req.Password,
		PrivateKey: req.PrivateKey, KeyPassphrase: req.KeyPassphrase,
		SudoPassword: req.SudoPassword, WGEndpoint: req.WGEndpoint, ViaJump: req.ViaJump,
		SkipWireGuard: req.SkipWireGuard,
	})
	if err != nil {
		// Surface the failed job so the UI can show which step failed.
		httpx.WriteJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// enrollScript returns the host bootstrap script for the no-install flow as
// text/plain, so it can be piped straight into `ssh user@host sudo bash`.
func (h *handler) enrollScript(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	hostID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	host, err := h.d.Store.GetHost(r.Context(), hostID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return
	}
	script, err := h.svc.EnrollScript(r.Context(), p.SessionID, host, &p.UserID, r.URL.Query().Get("wgEndpoint"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(script))
}

// enrollFinish completes the no-install flow using the host public key the
// operator pasted from the bootstrap script output.
func (h *handler) enrollFinish(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	hostID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	host, err := h.d.Store.GetHost(r.Context(), hostID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return
	}
	var req struct {
		HostPublicKey string `json:"hostPublicKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	res, err := h.svc.FinishScriptEnroll(r.Context(), p.SessionID, host, &p.UserID, req.HostPublicKey)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *handler) listJobs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	jobs, err := h.d.Store.ListEnrollmentJobs(r.Context(), limit)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list jobs")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

func (h *handler) getJob(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid job id")
		return
	}
	job, err := h.d.Store.GetEnrollmentJob(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "job not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, job)
}
