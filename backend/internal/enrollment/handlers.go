package enrollment

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
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
		// Moving a host to a different Provenance login account. Gated on
		// Host.Enroll because it is the enrollment machinery: it creates accounts
		// and rewrites sshd trust on the managed host.
		pr.With(d.Auth.RequirePermission("Host.Enroll")).Post("/hosts/{id}/login-account", h.migrateLoginAccount)
		pr.With(d.Auth.RequirePermission("Host.Enroll")).Get("/enrollment/jobs", h.listJobs)
		pr.With(d.Auth.RequirePermission("Host.Enroll")).Delete("/enrollment/jobs", h.clearJobs)
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
	Overlay       string `json:"overlay"`       // "" (default) | wireguard | openvpn
}

// enrollmentBudget bounds one whole enrollment run.
//
// It exists because enrollment is executed synchronously inside the HTTP request, and
// the router caps every request at 60s (api.Server: middleware.Timeout). The sum of
// enrollment's own per-step budgets is larger than that cap — the overlay verification
// alone waits up to 90s for the tunnel to carry traffic — so the cap, not the step,
// decided the outcome: the request context died mid-verify and the failure surfaced as
// the bare "context deadline exceeded" instead of the step's own diagnosis, while the
// tunnel it was waiting for came up moments later. A host switching transports was then
// left holding both, because the WireGuard teardown is gated on that verification.
//
// Provisioning a host also legitimately takes minutes (package installs over SSH), so
// the budget is generous rather than tight: it is a backstop against a wedged run, not
// a performance target.
const enrollmentBudget = 10 * time.Minute

// detachEnrollment returns the context an enrollment runs under: the request's values
// but none of its cancellation, plus an explicit deadline of its own.
//
// Deliberately NOT context.Background() + Auth.TenantScope here, which is the pattern
// the WebSocket paths use. This route passes through RequireAuth, so its context
// already carries the tenant the middleware resolved — including a provider admin's
// X-Prov-Tenant switch. TenantScope would re-pin it to the principal's HOME tenant and
// silently move the enrollment to the wrong tenant. WithoutCancel keeps the resolved
// value and drops only the deadline, which is the single thing wrong with it.
func detachEnrollment(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), enrollmentBudget)
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
	switch req.Overlay {
	case "", "wireguard", "openvpn":
		// ok
	default:
		httpx.WriteError(w, http.StatusBadRequest, "overlay must be one of: wireguard, openvpn")
		return
	}
	ctx, cancel := detachEnrollment(r)
	defer cancel()
	res, err := h.svc.Enroll(ctx, p.SessionID, host, &p.UserID, EnrollParams{
		Method: req.Method, BootstrapUser: req.BootstrapUser, Password: req.Password,
		PrivateKey: req.PrivateKey, KeyPassphrase: req.KeyPassphrase,
		SudoPassword: req.SudoPassword, WGEndpoint: req.WGEndpoint, ViaJump: req.ViaJump,
		SkipWireGuard: req.SkipWireGuard, Overlay: req.Overlay,
	})
	if err != nil {
		// Surface the failed job so the UI can show which step failed.
		httpx.WriteJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// enrollScript returns the host bootstrap script for the no-install flow as
// text/plain, so the operator can pipe it onto the host over their own ssh and
// run it there with `sudo` (see EnrollScript for the exact two-connection form).
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
	// The VPN overlay the operator picked in the enrollment dialog, same values the
	// over-SSH flow accepts. Empty means "use the deployment default".
	ovl := r.URL.Query().Get("overlay")
	switch ovl {
	case "", "wireguard", "openvpn":
		// ok
	default:
		httpx.WriteError(w, http.StatusBadRequest, "overlay must be one of: wireguard, openvpn")
		return
	}
	// RDP (Windows) hosts get a PowerShell WireGuard-enrollment script; SSH hosts get
	// the bash bootstrap script.
	var script string
	if host.Protocol == "rdp" {
		// Say so rather than silently handing back a WireGuard script: the Windows
		// enrollment script has no OpenVPN equivalent yet.
		if ovl == "openvpn" {
			httpx.WriteError(w, http.StatusBadRequest, "the OpenVPN overlay is not supported for Windows hosts yet")
			return
		}
		script, err = h.svc.EnrollScriptWindows(r.Context(), p.SessionID, host, &p.UserID, r.URL.Query().Get("wgEndpoint"))
	} else {
		script, err = h.svc.EnrollScript(r.Context(), p.SessionID, host, &p.UserID, r.URL.Query().Get("wgEndpoint"), ovl)
	}
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

func (h *handler) clearJobs(w http.ResponseWriter, r *http.Request) {
	n, err := h.d.Store.DeleteFinishedEnrollmentJobs(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not clear jobs")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": n})
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

// migrateLoginAccountReq names the account to move the host to and how far to go.
// An empty user means the current default, which is what the post-rename migration
// wants. removeOld defaults to false: adopting the new account is reversible,
// deleting the old one is not.
type migrateLoginAccountReq = MigrateOptions

// migrateLoginAccount moves one host onto a different Provenance login account,
// verifying the new account works before the old one is removed.
func (h *handler) migrateLoginAccount(w http.ResponseWriter, r *http.Request) {
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
	var req migrateLoginAccountReq
	_ = json.NewDecoder(r.Body).Decode(&req) // body optional; defaults to adopt-only, current default account

	actor := p.UserID
	// Same detach as enrolling, for the same reason: this makes at least two SSH round
	// trips per address plus a verification login, and the router caps a request at 60s.
	// It also covers the audit writes below — on a request that had already expired they
	// would fail too, losing the record of an account change that did happen.
	ctx, cancel := detachEnrollment(r)
	defer cancel()
	res, err := h.svc.MigrateLoginAccount(ctx, host, req)
	if err != nil {
		_, _ = h.d.Store.AppendAudit(ctx, models.AuditEvent{
			ActorID: &actor, Action: "host.login_account_migrate_failed", TargetKind: "host",
			TargetID: hostID.String(), Detail: map[string]any{"error": err.Error()},
		})
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	_, _ = h.d.Store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &actor, Action: "host.login_account_migrated", TargetKind: "host",
		TargetID: hostID.String(),
		Detail: map[string]any{"from": res.From, "to": res.To, "migrated": res.Migrated,
			"oldAccountLeft": res.OldAccountLeft},
	})
	httpx.WriteJSON(w, http.StatusOK, res)
}
