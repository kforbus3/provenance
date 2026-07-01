package scan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

// Mount attaches scan routes. JSON routes use cookie auth + Host.Scan; the report
// route authenticates via a token query param so it can be rendered in a
// sandboxed <iframe> or downloaded directly by the browser.
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/hosts/{id}/scan/profiles", h.profiles)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Post("/hosts/{id}/scan/prepare", h.prepare)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Post("/hosts/{id}/scan", h.start)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/hosts/{id}/scans", h.list)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/scans/{id}", h.get)
		pr.With(d.Auth.RequirePermission("Host.Scan")).Get("/scans/{id}/findings", h.findings)
		// Remediation modifies hosts -> Host.Remediate (admin-only by default).
		pr.With(d.Auth.RequirePermission("Host.Remediate")).Post("/scans/{id}/remediation/preview", h.remediatePreview)
		pr.With(d.Auth.RequirePermission("Host.Remediate")).Post("/scans/{id}/remediate", h.remediate)
		pr.With(d.Auth.RequirePermission("Host.Remediate")).Get("/remediations/{id}", h.remediationStatus)
	})
	r.Get("/scans/{id}/report", h.report)
}

type handler struct {
	d   *app.Deps
	svc *Service
}

// canAccess enforces host-level authorization (super admins bypass): the same
// gate as terminals/SFTP, so scanning is limited to hosts the user can reach.
func (h *handler) canAccess(r *http.Request, p *auth.Principal, hostID uuid.UUID) bool {
	if p == nil {
		return false
	}
	if p.IsSuperAdmin {
		return true
	}
	ok, err := h.d.Store.UserCanAccessHost(r.Context(), p.UserID, hostID)
	return err == nil && ok
}

func (h *handler) hostFromURL(w http.ResponseWriter, r *http.Request) (*models.Host, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad host id")
		return nil, false
	}
	host, err := h.d.Store.GetHost(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return nil, false
	}
	if !h.canAccess(r, auth.MustPrincipal(r), host.ID) {
		httpx.WriteError(w, http.StatusForbidden, "not authorized for host")
		return nil, false
	}
	return host, true
}

// profiles discovers the SCAP profiles available on the host (no install).
func (h *handler) profiles(w http.ResponseWriter, r *http.Request) {
	host, ok := h.hostFromURL(w, r)
	if !ok {
		return
	}
	installed, exact, datastream, profiles, err := h.svc.DiscoverProfiles(r.Context(), host)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "discover profiles: "+err.Error())
		return
	}
	if profiles == nil {
		profiles = []models.ScanProfile{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"installed": installed, "exact": exact, "installing": h.svc.IsInstalling(host.ID),
		"datastream": datastream, "profiles": profiles,
	})
}

// prepare installs the scanner + SCAP content on the host in the background so
// the profile picker can populate before the first scan.
func (h *handler) prepare(w http.ResponseWriter, r *http.Request) {
	host, ok := h.hostFromURL(w, r)
	if !ok {
		return
	}
	h.svc.EnsureInstalled(host)
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"installing": h.svc.IsInstalling(host.ID)})
}

type startReq struct {
	Profile              string   `json:"profile"`
	SkipExpensiveFsRules bool     `json:"skipExpensiveFsRules"`
	SkipRules            []string `json:"skipRules"`
}

// start creates a scan record and kicks off the scan in the background.
func (h *handler) start(w http.ResponseWriter, r *http.Request) {
	host, ok := h.hostFromURL(w, r)
	if !ok {
		return
	}
	var rq startReq
	_ = json.NewDecoder(r.Body).Decode(&rq) // body optional; empty profile -> standard
	p := auth.MustPrincipal(r)

	// Rules to exclude: the expensive-filesystem preset (if requested) plus any
	// explicit ids, de-duplicated.
	skip := map[string]bool{}
	var skipRules []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id != "" && !skip[id] {
			skip[id] = true
			skipRules = append(skipRules, id)
		}
	}
	if rq.SkipExpensiveFsRules {
		for _, id := range ExpensiveFSRules {
			add(id)
		}
	}
	for _, id := range rq.SkipRules {
		add(id)
	}

	rec, err := h.d.Store.CreateHostScan(r.Context(), host.ID, &p.UserID, p.Username, rq.Profile, false)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create scan")
		return
	}
	go h.svc.Run(rec.ID, host, rq.Profile, skipRules)

	h.audit(r, "host.scan", rec.ID.String(), map[string]any{
		"hostId": host.ID, "hostname": host.Hostname, "profile": rq.Profile, "skipped": len(skipRules),
	})
	httpx.WriteJSON(w, http.StatusAccepted, rec)
}

// list returns recent scans for a host.
func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	host, ok := h.hostFromURL(w, r)
	if !ok {
		return
	}
	scans, err := h.d.Store.ListHostScans(r.Context(), host.ID, 50)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list scans")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"scans": scans, "count": len(scans)})
}

// get returns one scan's status + summary (polled by the UI while running).
func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad scan id")
		return
	}
	rec, err := h.d.Store.GetHostScan(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "scan not found")
		return
	}
	if !h.canAccess(r, auth.MustPrincipal(r), rec.HostID) {
		httpx.WriteError(w, http.StatusForbidden, "not authorized for host")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rec)
}

// report serves the stored HTML report for in-UI viewing (sandboxed iframe) or
// download. Authenticated via token query param. A restrictive CSP neutralizes
// the report's inline scripts (no network/external loads) as defense in depth.
func (h *handler) report(w http.ResponseWriter, r *http.Request) {
	principal, err := h.d.Auth.AuthenticateToken(r.Context(), r.URL.Query().Get("token"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !principal.Has("Host.Scan") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "bad scan id", http.StatusBadRequest)
		return
	}
	rec, err := h.d.Store.GetHostScan(r.Context(), id)
	if err != nil {
		http.Error(w, "report not found", http.StatusNotFound)
		return
	}
	if !h.canAccess(r, principal, rec.HostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	path, err := h.d.Store.HostScanReportPath(r.Context(), id)
	if err != nil || path == "" {
		http.Error(w, "report not found", http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "report not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Query().Get("download") != "" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="scan-%s.html"`, id.String()[:8]))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *handler) audit(r *http.Request, action, targetID string, detail map[string]any) {
	p := auth.MustPrincipal(r)
	var actorID *uuid.UUID
	var name string
	if p != nil {
		actorID = &p.UserID
		name = p.Username
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: actorID, ActorName: name, Action: action,
		TargetKind: "host", TargetID: targetID, Detail: detail,
	})
}

// scanWithAccess loads a scan by URL id, its host, and verifies access.
func (h *handler) scanWithAccess(w http.ResponseWriter, r *http.Request) (*models.HostScan, *models.Host, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad scan id")
		return nil, nil, false
	}
	scan, err := h.d.Store.GetHostScan(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "scan not found")
		return nil, nil, false
	}
	if !h.canAccess(r, auth.MustPrincipal(r), scan.HostID) {
		httpx.WriteError(w, http.StatusForbidden, "not authorized for host")
		return nil, nil, false
	}
	host, err := h.d.Store.GetHost(r.Context(), scan.HostID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return nil, nil, false
	}
	return scan, host, true
}

// findings lists the failed rules of a scan (with severity + access-impacting flag).
func (h *handler) findings(w http.ResponseWriter, r *http.Request) {
	scan, host, ok := h.scanWithAccess(w, r)
	if !ok {
		return
	}
	f, err := h.svc.Findings(r.Context(), scan.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"findings":     f,
		"count":        len(f),
		"controlPlane": isControlPlaneHost(host, h.d.Cfg),
	})
}

type remediateReq struct {
	RuleIDs                []string `json:"ruleIds"`
	ConfirmAccessImpacting bool     `json:"confirmAccessImpacting"`
	ConfirmControlPlane    bool     `json:"confirmControlPlane"`
}

// remediatePreview returns the bash that would run for the selected rules.
func (h *handler) remediatePreview(w http.ResponseWriter, r *http.Request) {
	scan, host, ok := h.scanWithAccess(w, r)
	if !ok {
		return
	}
	var rq remediateReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil || len(rq.RuleIDs) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "ruleIds required")
		return
	}
	findings, err := h.svc.Findings(r.Context(), scan.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := validateRules(rq.RuleIDs, findings); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	script, err := h.svc.PreviewFix(r.Context(), scan, host, rq.RuleIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "preview failed: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"script": script})
}

// remediate applies fixes for the selected rules (background) then re-scans.
func (h *handler) remediate(w http.ResponseWriter, r *http.Request) {
	scan, host, ok := h.scanWithAccess(w, r)
	if !ok {
		return
	}
	var rq remediateReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil || len(rq.RuleIDs) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "ruleIds required")
		return
	}
	findings, err := h.svc.Findings(r.Context(), scan.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	impacting, err := validateRules(rq.RuleIDs, findings)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Access-impacting rules need an explicit second confirmation.
	if len(impacting) > 0 && !rq.ConfirmAccessImpacting {
		httpx.WriteJSON(w, http.StatusConflict, map[string]any{
			"error":           "selection includes access-impacting rules; confirmation required",
			"accessImpacting": impacting,
		})
		return
	}
	// Remediating Fleet's own control-plane host can lock Fleet out of the whole
	// fleet (this is how the ip_forward sysctl took down the web UI). Require a
	// distinct confirmation regardless of which rules are selected.
	if isControlPlaneHost(host, h.d.Cfg) && !rq.ConfirmControlPlane {
		httpx.WriteJSON(w, http.StatusConflict, map[string]any{
			"error":        "target is a Fleet control-plane host; remediating it can lock Fleet out of the fleet — explicit confirmation required",
			"controlPlane": true,
		})
		return
	}
	p := auth.MustPrincipal(r)
	rec, err := h.d.Store.CreateRemediation(r.Context(), scan.ID, host.ID, &p.UserID, p.Username, rq.RuleIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not start remediation")
		return
	}
	go h.svc.Remediate(rec.ID, scan, host, rq.RuleIDs, &p.UserID, p.Username)
	h.audit(r, "host.remediate", rec.ID.String(), map[string]any{
		"hostId": host.ID, "hostname": host.Hostname, "rules": rq.RuleIDs,
		"accessImpacting": impacting, "controlPlane": isControlPlaneHost(host, h.d.Cfg),
	})
	httpx.WriteJSON(w, http.StatusAccepted, rec)
}

func (h *handler) remediationStatus(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad id")
		return
	}
	rec, err := h.d.Store.GetRemediation(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !h.canAccess(r, auth.MustPrincipal(r), rec.HostID) {
		httpx.WriteError(w, http.StatusForbidden, "not authorized for host")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rec)
}
