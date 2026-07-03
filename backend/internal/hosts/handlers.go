// Package hosts provides host inventory CRUD and serves as the canonical example
// of a Fleet Terminal HTTP module: construct from *app.Deps, gate every route
// with auth + RBAC middleware, and audit state changes.
package hosts

import (
	"encoding/json"
	"net/http"
	"strconv"

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
	Hostname    string   `json:"hostname"`
	Description string   `json:"description"`
	Environment string   `json:"environment"`
	Owner       string   `json:"owner"`
	Address     string   `json:"address"`
	WGAddress   string   `json:"wgAddress"`
	SSHPort     int      `json:"sshPort"`
	SSHUser     string   `json:"sshUser"`
	Tags        []string `json:"tags"`
}

func (rq hostReq) toInput() store.HostInput {
	return store.HostInput{
		Hostname: rq.Hostname, Description: rq.Description, Environment: rq.Environment,
		Owner: rq.Owner, Address: rq.Address, WGAddress: rq.WGAddress,
		SSHPort: rq.SSHPort, SSHUser: rq.SSHUser, Tags: rq.Tags,
	}
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
