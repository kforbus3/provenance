// Package hosts provides host inventory CRUD and serves as the canonical example
// of a Fleet Terminal HTTP module: construct from *app.Deps, gate every route
// with auth + RBAC middleware, and audit state changes.
package hosts

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// Mount attaches host routes to r, gated by authentication and permissions.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)

		pr.With(d.Auth.RequirePermission("Host.View")).Get("/hosts", h.list)
		pr.With(d.Auth.RequirePermission("Host.View")).Get("/hosts/{id}", h.get)
		pr.With(d.Auth.RequirePermission("Host.View")).Get("/hosts/{id}/software", h.software)
		pr.With(d.Auth.RequirePermission("Host.View")).Post("/hosts/{id}/refresh", h.refreshFacts)
		pr.With(d.Auth.RequirePermission("Host.Edit")).Post("/hosts/{id}/maintenance", h.setMaintenance)
		pr.With(d.Auth.RequirePermission("Host.Edit")).Delete("/hosts/{id}/maintenance", h.clearMaintenance)
		// Bulk actions over an ad-hoc host selection. Each mirrors its single-host
		// counterpart's permission, applied to every host in the list.
		pr.With(d.Auth.RequirePermission("Host.View")).Post("/hosts/bulk/refresh", h.bulkRefresh)
		pr.With(d.Auth.RequirePermission("Host.Edit")).Post("/hosts/bulk/maintenance", h.bulkMaintenance)
		pr.With(d.Auth.RequirePermission("Host.Edit")).Post("/hosts/bulk/tags", h.bulkTags)
		pr.With(d.Auth.RequirePermission("Host.View")).Get("/hosts/stats/status", h.statusStats)
		pr.With(d.Auth.RequirePermission("Host.View")).Get("/hosts/wg/next", h.nextWG)
		pr.With(d.Auth.RequirePermission("Host.Enroll")).Post("/hosts", h.create)
		pr.With(d.Auth.RequirePermission("Host.Edit")).Put("/hosts/{id}", h.update)
		pr.With(d.Auth.RequirePermission("Host.Delete")).Delete("/hosts/{id}", h.del)
		pr.With(d.Auth.RequirePermission("Host.Edit")).Post("/hosts/{id}/groups/{groupId}", h.addGroup)
		pr.With(d.Auth.RequirePermission("Host.Edit")).Delete("/hosts/{id}/groups/{groupId}", h.removeGroup)
		pr.With(d.Auth.RequirePermission("Host.Edit")).Get("/hosts/{id}/access", h.access)
		pr.With(d.Auth.RequirePermission("Host.Edit")).Post("/hosts/{id}/users/{userId}", h.addUser)
		pr.With(d.Auth.RequirePermission("Host.Edit")).Delete("/hosts/{id}/users/{userId}", h.removeUser)
	})
}

type handler struct{ d *app.Deps }

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	var (
		hosts []models.Host
		err   error
	)
	// Inventory.View shows all hosts; otherwise restrict to accessible hosts.
	if p.Has("Host.Enroll") || p.Has("Admin.All") {
		hosts, err = h.d.Store.ListHosts(r.Context(), limit, offset)
	} else {
		hosts, err = h.d.Store.ListAccessibleHosts(r.Context(), p.UserID, p.IsSuperAdmin)
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list hosts")
		return
	}
	if hosts == nil {
		hosts = []models.Host{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"hosts": hosts, "count": len(hosts)})
}

// refreshFacts forces the monitor to re-collect a host's pending-updates (and
// Windows software inventory) on its next sweep, instead of waiting for the hourly
// cadence — e.g. right after an operator patches the host.
func (h *handler) refreshFacts(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	p := auth.MustPrincipal(r)
	if !p.Has("Host.Enroll") && !p.Has("Admin.All") {
		if allowed, aerr := h.d.Store.UserCanAccessHost(r.Context(), p.UserID, id); aerr != nil || !allowed {
			httpx.WriteError(w, http.StatusNotFound, "host not found")
			return
		}
	}
	if err := h.d.Store.MarkHostFactsStale(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not queue refresh")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"queued": true})
}

// setMaintenance puts a host into a maintenance window (default 60 min) so its
// offline/recovered alerts and dashboard attention items are suppressed.
func (h *handler) setMaintenance(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	var rq struct {
		Minutes int `json:"minutes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&rq)
	if rq.Minutes <= 0 {
		rq.Minutes = 60
	}
	if rq.Minutes > 60*24*30 { // cap at 30 days
		rq.Minutes = 60 * 24 * 30
	}
	until := time.Now().Add(time.Duration(rq.Minutes) * time.Minute)
	if err := h.d.Store.SetHostMaintenance(r.Context(), id, &until); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not set maintenance")
		return
	}
	h.audit(r, "host.maintenance_set", id.String(), map[string]any{"minutes": rq.Minutes, "until": until})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"maintenanceUntil": until})
}

// clearMaintenance ends a host's maintenance window immediately.
func (h *handler) clearMaintenance(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	if err := h.d.Store.SetHostMaintenance(r.Context(), id, nil); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not clear maintenance")
		return
	}
	h.audit(r, "host.maintenance_clear", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"cleared": true})
}

// maxBulkHosts bounds a single bulk action so one request can't fan out without
// limit (and, for maintenance/tags, hammer the DB). The UI selects from a paged
// grid, so this is generous headroom, not a real constraint.
const maxBulkHosts = 1000

// parseHostIDs decodes and validates a bulk request's host-id list, writing the
// appropriate 400 and returning ok=false on any problem.
func parseHostIDs(w http.ResponseWriter, raw []string) ([]uuid.UUID, bool) {
	if len(raw) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "hostIds is required")
		return nil, false
	}
	if len(raw) > maxBulkHosts {
		httpx.WriteError(w, http.StatusBadRequest, "too many hosts in one request")
		return nil, false
	}
	ids := make([]uuid.UUID, 0, len(raw))
	for _, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid host id: "+s)
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, true
}

// accessibleIDs filters ids to those the principal may act on. Admin-equivalent
// principals (Host.Enroll / Admin.All) see everything; others are limited to
// hosts they can access — matching the per-host access check the single-host
// handlers apply, so a bulk action can't reach hosts a user couldn't touch one at
// a time.
func (h *handler) accessibleIDs(r *http.Request, ids []uuid.UUID) []uuid.UUID {
	p := auth.MustPrincipal(r)
	if p.Has("Host.Enroll") || p.Has("Admin.All") {
		return ids
	}
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if ok, err := h.d.Store.UserCanAccessHost(r.Context(), p.UserID, id); err == nil && ok {
			out = append(out, id)
		}
	}
	return out
}

// bulkRefresh marks each selected host's facts stale so the monitor re-collects
// pending updates (and Windows software) on its next sweep — the batch form of
// the per-host "Refresh facts" action.
func (h *handler) bulkRefresh(w http.ResponseWriter, r *http.Request) {
	var rq struct {
		HostIDs []string `json:"hostIds"`
	}
	_ = json.NewDecoder(r.Body).Decode(&rq)
	ids, ok := parseHostIDs(w, rq.HostIDs)
	if !ok {
		return
	}
	ids = h.accessibleIDs(r, ids)
	done := 0
	for _, id := range ids {
		if err := h.d.Store.MarkHostFactsStale(r.Context(), id); err == nil {
			done++
		}
	}
	h.audit(r, "host.bulk_refresh", "", map[string]any{"requested": len(ids), "applied": done})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"applied": done})
}

// bulkMaintenance sets (minutes > 0) or clears (minutes <= 0) a maintenance
// window on every selected host at once.
func (h *handler) bulkMaintenance(w http.ResponseWriter, r *http.Request) {
	var rq struct {
		HostIDs []string `json:"hostIds"`
		Minutes int      `json:"minutes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&rq)
	ids, ok := parseHostIDs(w, rq.HostIDs)
	if !ok {
		return
	}
	ids = h.accessibleIDs(r, ids)
	var until *time.Time
	if rq.Minutes > 0 {
		if rq.Minutes > 60*24*30 {
			rq.Minutes = 60 * 24 * 30
		}
		t := time.Now().Add(time.Duration(rq.Minutes) * time.Minute)
		until = &t
	}
	done := 0
	for _, id := range ids {
		if err := h.d.Store.SetHostMaintenance(r.Context(), id, until); err == nil {
			done++
		}
	}
	h.audit(r, "host.bulk_maintenance", "", map[string]any{
		"requested": len(ids), "applied": done, "minutes": rq.Minutes,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"applied": done})
}

// bulkTags adds and/or removes tags across every selected host. Adds are applied
// before removes, so passing the same tag in both is a no-op rather than ambiguous.
func (h *handler) bulkTags(w http.ResponseWriter, r *http.Request) {
	var rq struct {
		HostIDs []string `json:"hostIds"`
		Add     []string `json:"add"`
		Remove  []string `json:"remove"`
	}
	_ = json.NewDecoder(r.Body).Decode(&rq)
	ids, ok := parseHostIDs(w, rq.HostIDs)
	if !ok {
		return
	}
	add := cleanTags(rq.Add)
	remove := cleanTags(rq.Remove)
	if len(add) == 0 && len(remove) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "at least one tag to add or remove is required")
		return
	}
	ids = h.accessibleIDs(r, ids)
	done := 0
	for _, id := range ids {
		var err error
		for _, t := range add {
			if e := h.d.Store.AddHostTag(r.Context(), id, t); e != nil {
				err = e
			}
		}
		for _, t := range remove {
			if e := h.d.Store.RemoveHostTag(r.Context(), id, t); e != nil {
				err = e
			}
		}
		if err == nil {
			done++
		}
	}
	h.audit(r, "host.bulk_tags", "", map[string]any{
		"requested": len(ids), "applied": done, "add": add, "remove": remove,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"applied": done})
}

// cleanTags trims, de-dupes, and drops empty tag strings.
func cleanTags(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// software returns a Windows host's installed-software inventory.
func (h *handler) software(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	p := auth.MustPrincipal(r)
	if !p.Has("Host.Enroll") && !p.Has("Admin.All") {
		if allowed, aerr := h.d.Store.UserCanAccessHost(r.Context(), p.UserID, id); aerr != nil || !allowed {
			httpx.WriteError(w, http.StatusNotFound, "host not found")
			return
		}
	}
	items, err := h.d.Store.ListWindowsSoftware(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list software")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"software": items, "count": len(items)})
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	host, err := h.d.Store.GetHost(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return
	}
	// Same visibility rule as list(): privileged roles see every host; everyone
	// else may only view hosts they can access. 404 (not 403) so an inaccessible
	// host's existence isn't leaked.
	p := auth.MustPrincipal(r)
	if !p.Has("Host.Enroll") && !p.Has("Admin.All") {
		allowed, aerr := h.d.Store.UserCanAccessHost(r.Context(), p.UserID, id)
		if aerr != nil || !allowed {
			httpx.WriteError(w, http.StatusNotFound, "host not found")
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, host)
}

// nextWG returns the next free overlay address so the create dialog can show
// what auto-assignment would pick (and the overlay subnet).
func (h *handler) nextWG(w http.ResponseWriter, r *http.Request) {
	// Effective default endpoint: DB setting first, then the env config default.
	endpoint := h.d.Store.WireGuardEndpoint(r.Context())
	if endpoint == "" {
		endpoint = h.d.Cfg.WGJumpEndpoint
	}
	next, err := h.d.Store.NextFreeWGAddress(r.Context(), h.d.Cfg.WGJumpIP)
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"nextWgAddress": "", "subnet": h.d.Cfg.WGSubnet, "jumpEndpoint": endpoint, "exhausted": true})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"nextWgAddress": next, "subnet": h.d.Cfg.WGSubnet, "jumpEndpoint": endpoint})
}

func (h *handler) statusStats(w http.ResponseWriter, r *http.Request) {
	counts, err := h.d.Store.CountHostsByStatus(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load stats")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, counts)
}

type hostReq struct {
	Hostname     string            `json:"hostname"`
	Description  string            `json:"description"`
	Environment  string            `json:"environment"`
	Owner        string            `json:"owner"`
	Address      string            `json:"address"`
	WGAddress    string            `json:"wgAddress"`
	SSHPort      int               `json:"sshPort"`
	SSHUser      string            `json:"sshUser"`
	Tags         []string          `json:"tags"`
	AuthMethod   string            `json:"authMethod"`
	CredentialID *uuid.UUID        `json:"credentialId"`
	Protocol     string            `json:"protocol"`
	RDPPort      int               `json:"rdpPort"`
	RDPOptions   models.RDPOptions `json:"rdpOptions"`
}

func (rq hostReq) toInput() store.HostInput {
	return store.HostInput{
		Hostname: rq.Hostname, Description: rq.Description, Environment: rq.Environment,
		Owner: rq.Owner, Address: rq.Address, WGAddress: rq.WGAddress,
		SSHPort: rq.SSHPort, SSHUser: rq.SSHUser, Tags: rq.Tags,
		AuthMethod: rq.AuthMethod, CredentialID: rq.CredentialID,
		Protocol: rq.Protocol, RDPPort: rq.RDPPort, RDPOptions: rq.RDPOptions,
	}
}

// validateVaultAuth enforces that attaching a vault credential to a host requires
// a credential to be selected and the actor to have access to it (Credential.Manage
// or a manage/use grant) — so a host editor cannot bind an arbitrary secret they
// couldn't otherwise use. Returns a client-facing error message, or "" if ok.
func (h *handler) validateVaultAuth(r *http.Request, rq hostReq) string {
	if rq.AuthMethod != "vault_password" && rq.AuthMethod != "vault_ssh_key" {
		return "" // fleet_cert (or default) needs no credential
	}
	if rq.CredentialID == nil {
		return "select a credential for vault authentication"
	}
	p := auth.MustPrincipal(r)
	if p.Has("Credential.Manage") {
		return ""
	}
	acc, err := h.d.Store.UserSecretAccess(r.Context(), p.UserID, *rq.CredentialID)
	if err != nil || (acc != "use" && acc != "manage") {
		return "you do not have access to that credential"
	}
	return ""
}

// validHostname rejects control characters (CR/LF etc.), which have no place in a
// hostname and would otherwise be carried into notification email headers.
func validHostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// validSSHUser restricts the login account to a conservative POSIX username
// pattern. It becomes the shell variable LOGIN=... in the root-run enrollment
// script and the sudo/auth-principals account name, so it must not carry shell
// metacharacters. Empty is allowed — enrollment defaults it to "fleet".
func validSSHUser(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > 32 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r == '_':
			// always allowed
		case i > 0 && (r >= '0' && r <= '9' || r == '-'):
			// allowed after the first character
		default:
			return false
		}
	}
	return true
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var rq hostReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil || rq.Hostname == "" {
		httpx.WriteError(w, http.StatusBadRequest, "hostname is required")
		return
	}
	if !validHostname(rq.Hostname) {
		httpx.WriteError(w, http.StatusBadRequest, "hostname contains invalid characters")
		return
	}
	if !validSSHUser(rq.SSHUser) {
		httpx.WriteError(w, http.StatusBadRequest, "sshUser must be a valid login name ([a-z_][a-z0-9_-]*)")
		return
	}
	if msg := h.validateVaultAuth(r, rq); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	host, err := h.d.Store.CreateHost(r.Context(), rq.toInput())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create host")
		return
	}
	h.audit(r, "host.create", host.ID.String(), map[string]any{"hostname": host.Hostname})
	httpx.WriteJSON(w, http.StatusCreated, host)
}

func (h *handler) update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	var rq hostReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validHostname(rq.Hostname) {
		httpx.WriteError(w, http.StatusBadRequest, "hostname contains invalid characters")
		return
	}
	if !validSSHUser(rq.SSHUser) {
		httpx.WriteError(w, http.StatusBadRequest, "sshUser must be a valid login name ([a-z_][a-z0-9_-]*)")
		return
	}
	if msg := h.validateVaultAuth(r, rq); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	host, err := h.d.Store.UpdateHost(r.Context(), id, rq.toInput())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update host")
		return
	}
	h.audit(r, "host.update", id.String(), map[string]any{"hostname": host.Hostname})
	httpx.WriteJSON(w, http.StatusOK, host)
}

func (h *handler) del(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	if err := h.d.Store.DeleteHost(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete host")
		return
	}
	h.audit(r, "host.delete", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *handler) addGroup(w http.ResponseWriter, r *http.Request) {
	hostID, err1 := uuid.Parse(chi.URLParam(r, "id"))
	groupID, err2 := uuid.Parse(chi.URLParam(r, "groupId"))
	if err1 != nil || err2 != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if dyn, _ := h.d.Store.GroupIsDynamic(r.Context(), groupID); dyn {
		httpx.WriteError(w, http.StatusConflict, "group membership is rule-managed; edit the group's rule instead")
		return
	}
	if err := h.d.Store.AddHostToGroup(r.Context(), hostID, groupID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not add to group")
		return
	}
	h.audit(r, "host.group_add", hostID.String(), map[string]any{"groupId": groupID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

func (h *handler) removeGroup(w http.ResponseWriter, r *http.Request) {
	hostID, err1 := uuid.Parse(chi.URLParam(r, "id"))
	groupID, err2 := uuid.Parse(chi.URLParam(r, "groupId"))
	if err1 != nil || err2 != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if dyn, _ := h.d.Store.GroupIsDynamic(r.Context(), groupID); dyn {
		httpx.WriteError(w, http.StatusConflict, "group membership is rule-managed; edit the group's rule instead")
		return
	}
	if err := h.d.Store.RemoveHostFromGroup(r.Context(), hostID, groupID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not remove from group")
		return
	}
	h.audit(r, "host.group_remove", hostID.String(), map[string]any{"groupId": groupID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// access returns who can reach a host: the groups it belongs to and the users
// granted direct access. Used by the host access-management UI.
func (h *handler) access(w http.ResponseWriter, r *http.Request) {
	hostID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	host, err := h.d.Store.GetHost(r.Context(), hostID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return
	}
	users, err := h.d.Store.HostDirectUsers(r.Context(), hostID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load access")
		return
	}
	if users == nil {
		users = []models.User{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"groups": host.Groups, "users": users})
}

func (h *handler) addUser(w http.ResponseWriter, r *http.Request) {
	hostID, err1 := uuid.Parse(chi.URLParam(r, "id"))
	userID, err2 := uuid.Parse(chi.URLParam(r, "userId"))
	if err1 != nil || err2 != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.d.Store.AddUserToHost(r.Context(), hostID, userID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not grant access")
		return
	}
	h.audit(r, "host.user_add", hostID.String(), map[string]any{"userId": userID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

func (h *handler) removeUser(w http.ResponseWriter, r *http.Request) {
	hostID, err1 := uuid.Parse(chi.URLParam(r, "id"))
	userID, err2 := uuid.Parse(chi.URLParam(r, "userId"))
	if err1 != nil || err2 != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.d.Store.RemoveUserFromHost(r.Context(), hostID, userID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not revoke access")
		return
	}
	h.audit(r, "host.user_remove", hostID.String(), map[string]any{"userId": userID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "removed"})
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
