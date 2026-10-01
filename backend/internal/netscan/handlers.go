package netscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// MaxRangeAddresses is the largest range an operator may define. It matches the
// sidecar's own limit (NETSCAN_MAX_RANGE_ADDRESSES), so a range that saves here
// also scans there.
const MaxRangeAddresses = 1024

// Mount attaches network-scan routes. Running and viewing scans needs Host.Scan,
// the same as package scans. Defining ranges -- which points the scanner at
// arbitrary networks -- and managing templates need System.Configure.
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		scan := pr.With(d.Auth.RequirePermission("Host.Scan"))
		conf := pr.With(d.Auth.RequirePermission("System.Configure"))
		scan.Post("/net-scans", h.trigger)
		scan.Get("/net-scans", h.list)
		scan.Get("/net-scans/status", h.status)
		scan.Get("/net-scans/latest", h.latest)
		scan.Get("/net-scans/exposed", h.exposed)
		scan.Get("/net-scans/hosts/{hostId}", h.host)
		scan.Delete("/net-scans/failed", h.clearFailed)
		conf.Post("/net-scans/templates/update", h.templatesUpdate)
		conf.Post("/net-scans/templates/import", h.templatesImport)
		// Literal segments above, the {id} pattern last.
		scan.Get("/net-scans/{id}", h.get)

		scan.Get("/net-scan-ranges", h.listRanges)
		conf.Post("/net-scan-ranges", h.createRange)
		conf.Put("/net-scan-ranges/{id}", h.updateRange)
		conf.Delete("/net-scan-ranges/{id}", h.deleteRange)
		scan.Post("/net-scan-ranges/{id}/scan", h.scanRange)
	})
}

type handler struct {
	d   *app.Deps
	svc *Service
}

type triggerReq struct {
	HostID  string   `json:"hostId"`
	HostIDs []string `json:"hostIds"`
	GroupID string   `json:"groupId"`
}

func (h *handler) trigger(w http.ResponseWriter, r *http.Request) {
	var rq triggerReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	hosts, status, msg := h.resolveHosts(r.Context(), rq)
	if status != 0 {
		httpx.WriteError(w, status, msg)
		return
	}
	p := auth.MustPrincipal(r)
	// The scans outlive the request, so they run on a background context -- one
	// scoped to this principal's tenant. A bare Background has no tenant, and under
	// multi-tenancy every result insert would be refused by row-level security.
	bg := h.d.Auth.TenantScope(context.Background(), p)
	started, skipped, _, err := h.svc.StartHosts(r.Context(), bg, hosts, &p.UserID, p.Username, false)
	if err != nil {
		if errors.Is(err, ErrNotConfigured) {
			httpx.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if started == nil {
		started = []Started{}
	}
	if skipped == nil {
		skipped = []Skipped{}
	}
	h.audit(r, "net_scan.start", map[string]any{"hosts": len(started), "skipped": len(skipped)})
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"started": started, "skipped": skipped})
}

func (h *handler) resolveHosts(ctx context.Context, rq triggerReq) ([]*models.Host, int, string) {
	var hosts []*models.Host
	switch {
	case rq.HostID != "":
		id, err := uuid.Parse(rq.HostID)
		if err != nil {
			return nil, http.StatusBadRequest, "invalid host id"
		}
		host, err := h.d.Store.GetHost(ctx, id)
		if err != nil {
			return nil, http.StatusNotFound, "no such host"
		}
		hosts = []*models.Host{host}
	case len(rq.HostIDs) > 0:
		if len(rq.HostIDs) > 1000 {
			return nil, http.StatusBadRequest, "too many hosts in one request"
		}
		for _, s := range rq.HostIDs {
			id, err := uuid.Parse(s)
			if err != nil {
				return nil, http.StatusBadRequest, "invalid host id: " + s
			}
			if host, err := h.d.Store.GetHost(ctx, id); err == nil {
				hosts = append(hosts, host)
			}
		}
	case rq.GroupID != "":
		id, err := uuid.Parse(rq.GroupID)
		if err != nil {
			return nil, http.StatusBadRequest, "invalid group id"
		}
		members, err := h.d.Store.HostsInGroup(ctx, id)
		if err != nil {
			return nil, http.StatusInternalServerError, "could not resolve group"
		}
		for i := range members {
			hosts = append(hosts, &members[i])
		}
	default:
		return nil, http.StatusBadRequest, "hostId, hostIds or groupId is required"
	}
	if len(hosts) == 0 {
		return nil, http.StatusBadRequest, "no hosts to scan"
	}
	return hosts, 0, ""
}

func optUUID(r *http.Request, name string) *uuid.UUID {
	if v := r.URL.Query().Get(name); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			return &id
		}
	}
	return nil
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	scans, err := h.d.Store.ListNetScans(r.Context(), optUUID(r, "hostId"), optUUID(r, "rangeId"), 200)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list network scans")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.svc.Status(r.Context()))
}

func (h *handler) latest(w http.ResponseWriter, r *http.Request) {
	scans, err := h.d.Store.LatestNetScans(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not build the roll-up")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

func (h *handler) exposed(w http.ResponseWriter, r *http.Request) {
	svcs, err := h.d.Store.ExposedServices(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list exposed services")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"services": svcs})
}

// host returns a host's latest scan on each path, with findings corroborated
// against its package scan.
func (h *handler) host(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "hostId"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	scans, err := h.d.Store.LatestNetScansForHost(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load network scans")
		return
	}
	CorroborateHostScans(r.Context(), h.d.Store, id, scans)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	scan, err := h.d.Store.GetNetScan(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such network scan")
		return
	}
	if scan.HostID != nil {
		one := []models.NetScan{*scan}
		CorroborateHostScans(r.Context(), h.d.Store, *scan.HostID, one)
		scan = &one[0]
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"scan": scan})
}

func (h *handler) clearFailed(w http.ResponseWriter, r *http.Request) {
	n, err := h.d.Store.DeleteFailedNetScans(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not clear failed scans")
		return
	}
	h.audit(r, "net_scan.clear_failed", map[string]any{"deleted": n})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": n})
}

func (h *handler) templatesUpdate(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.TemplatesUpdate(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "template update failed: "+err.Error())
		return
	}
	h.audit(r, "net_scan.templates_update", map[string]any{"version": st.Version})
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (h *handler) templatesImport(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, 512<<20)
	version := r.URL.Query().Get("version")
	st, err := h.svc.TemplatesImport(r.Context(), body, version)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "template import failed: "+err.Error())
		return
	}
	h.audit(r, "net_scan.templates_import", map[string]any{"version": st.Version})
	httpx.WriteJSON(w, http.StatusOK, st)
}

// --- ranges --------------------------------------------------------------------------

type rangeReq struct {
	Name    string `json:"name"`
	CIDR    string `json:"cidr"`
	Note    string `json:"note"`
	Enabled *bool  `json:"enabled"`
}

// ValidateRange canonicalises a CIDR and refuses what must not be scanned. The
// sidecar applies the same rules; refusing here means a bad range is never saved,
// rather than saved and failing every night.
func ValidateRange(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	pfx, err := netip.ParsePrefix(raw)
	if err != nil {
		addr, aerr := netip.ParseAddr(raw)
		if aerr != nil {
			return "", fmt.Errorf("%q is not a network (use CIDR notation, e.g. 10.0.2.0/24)", raw)
		}
		pfx = netip.PrefixFrom(addr, addr.BitLen())
	}
	pfx = pfx.Masked()
	a := pfx.Addr()
	if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return "", fmt.Errorf("%s cannot be scanned: loopback, unspecified, multicast or link-local", pfx)
	}
	hostBits := a.BitLen() - pfx.Bits()
	if hostBits > 10 { // 2^10 = 1024 addresses
		return "", fmt.Errorf("%s is too large: a range may hold at most %d addresses (a /%d for IPv4)",
			pfx, MaxRangeAddresses, a.BitLen()-10)
	}
	return pfx.String(), nil
}

func (h *handler) listRanges(w http.ResponseWriter, r *http.Request) {
	rs, err := h.d.Store.ListNetScanRanges(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list ranges")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ranges": rs})
}

func (h *handler) decodeRange(w http.ResponseWriter, r *http.Request) (rangeReq, string, bool) {
	var rq rangeReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return rq, "", false
	}
	rq.Name = strings.TrimSpace(rq.Name)
	if rq.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name is required")
		return rq, "", false
	}
	cidr, err := ValidateRange(rq.CIDR)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return rq, "", false
	}
	return rq, cidr, true
}

func (h *handler) createRange(w http.ResponseWriter, r *http.Request) {
	rq, cidr, ok := h.decodeRange(w, r)
	if !ok {
		return
	}
	enabled := rq.Enabled == nil || *rq.Enabled
	p := auth.MustPrincipal(r)
	rng, err := h.d.Store.CreateNetScanRange(r.Context(), rq.Name, cidr, rq.Note, enabled, &p.UserID)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			httpx.WriteError(w, http.StatusConflict, "that range is already defined")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "could not save range")
		return
	}
	h.audit(r, "net_scan.range_create", map[string]any{"id": rng.ID, "name": rng.Name, "cidr": rng.CIDR})
	httpx.WriteJSON(w, http.StatusCreated, rng)
}

func (h *handler) updateRange(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	rq, cidr, ok := h.decodeRange(w, r)
	if !ok {
		return
	}
	// enabled is required on update: an omitted field must not silently re-enable or
	// disable a range somebody set the other way.
	if rq.Enabled == nil {
		httpx.WriteError(w, http.StatusBadRequest, "enabled is required")
		return
	}
	rng, err := h.d.Store.UpdateNetScanRange(r.Context(), id, rq.Name, cidr, rq.Note, *rq.Enabled)
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "no such range")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save range")
		return
	}
	h.audit(r, "net_scan.range_update", map[string]any{"id": rng.ID, "name": rng.Name, "cidr": rng.CIDR,
		"enabled": rng.Enabled})
	httpx.WriteJSON(w, http.StatusOK, rng)
}

func (h *handler) deleteRange(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.d.Store.DeleteNetScanRange(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "no such range")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete range")
		return
	}
	h.audit(r, "net_scan.range_delete", map[string]any{"id": id})
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) scanRange(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	rng, err := h.d.Store.GetNetScanRange(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such range")
		return
	}
	p := auth.MustPrincipal(r)
	bg := h.d.Auth.TenantScope(context.Background(), p)
	runID, _, err := h.svc.StartRange(bg, rng, &p.UserID, p.Username, false)
	if err != nil {
		if errors.Is(err, ErrNotConfigured) {
			httpx.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "net_scan.range_scan", map[string]any{"id": rng.ID, "cidr": rng.CIDR})
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"runId": runID})
}

func (h *handler) audit(r *http.Request, action string, detail map[string]any) {
	p := auth.MustPrincipal(r)
	if detail == nil {
		detail = map[string]any{}
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: action, TargetKind: "net_scan", Detail: detail,
	})
}
