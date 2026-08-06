package admin

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

func (h *handler) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := h.d.Store.ListGroups(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list groups")
		return
	}
	if groups == nil {
		groups = []models.Group{}
	}
	// Annotate with host-member counts so the Groups page can show membership at a
	// glance. Best-effort: a count failure must not blank the whole listing.
	if counts, cerr := h.d.Store.GroupHostCounts(r.Context()); cerr == nil {
		for i := range groups {
			n := counts[groups[i].ID]
			groups[i].HostCount = &n
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"groups": groups, "count": len(groups)})
}

// listGroupHosts returns the hosts that belong to a group, so membership can be
// reviewed from the Groups page instead of opening every host's access dialog.
// Identity fields only — connection details stay behind the host module.
func (h *handler) listGroupHosts(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid group id")
		return
	}
	g, err := h.d.Store.GetGroup(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such group")
		return
	}
	hosts, err := h.d.Store.GroupHostMembers(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list group hosts")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"hosts": hosts, "count": len(hosts), "dynamic": g.Rule != nil,
	})
}

// groupHostIDs parses the group and host ids and rejects the request when the
// group's membership is rule-managed — a manual edit there would be silently
// undone by the next reconcile. Mirrors the host-side guard.
func (h *handler) groupHostIDs(w http.ResponseWriter, r *http.Request) (groupID, hostID uuid.UUID, ok bool) {
	groupID, err1 := uuid.Parse(chi.URLParam(r, "id"))
	hostID, err2 := uuid.Parse(chi.URLParam(r, "hostId"))
	if err1 != nil || err2 != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return groupID, hostID, false
	}
	if dyn, _ := h.d.Store.GroupIsDynamic(r.Context(), groupID); dyn {
		httpx.WriteError(w, http.StatusConflict, "group membership is rule-managed; edit the group's rule instead")
		return groupID, hostID, false
	}
	return groupID, hostID, true
}

func (h *handler) addGroupHost(w http.ResponseWriter, r *http.Request) {
	groupID, hostID, ok := h.groupHostIDs(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.AddHostToGroup(r.Context(), hostID, groupID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not add host to group")
		return
	}
	// Same audit action as the host-side edit: one membership change, one shape.
	h.audit(r, "host.group_add", "host", hostID.String(), map[string]any{"groupId": groupID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

func (h *handler) removeGroupHost(w http.ResponseWriter, r *http.Request) {
	groupID, hostID, ok := h.groupHostIDs(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.RemoveHostFromGroup(r.Context(), hostID, groupID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not remove host from group")
		return
	}
	h.audit(r, "host.group_remove", "host", hostID.String(), map[string]any{"groupId": groupID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

type createGroupReq struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Rule        *models.GroupRule `json:"rule"` // non-empty = dynamic membership
}

func (h *handler) createGroup(w http.ResponseWriter, r *http.Request) {
	var rq createGroupReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil || rq.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	group, err := h.d.Store.CreateGroup(r.Context(), rq.Name, rq.Description)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create group")
		return
	}
	if !rq.Rule.Empty() {
		if err := h.d.Store.SetGroupRule(r.Context(), group.ID, rq.Rule); err == nil {
			_, _ = h.d.Store.RecomputeGroup(r.Context(), group.ID)
			group.Rule = rq.Rule
		}
	}
	h.audit(r, "group.create", "group", group.ID.String(), map[string]any{"name": group.Name, "dynamic": !rq.Rule.Empty()})
	httpx.WriteJSON(w, http.StatusCreated, group)
}

// updateGroup edits a group's dynamic membership rule (setting or clearing it),
// then recomputes membership. Manual host membership is managed elsewhere and is
// disabled while a rule is set.
func (h *handler) updateGroup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid group id")
		return
	}
	var rq struct {
		Rule *models.GroupRule `json:"rule"`
	}
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.d.Store.SetGroupRule(r.Context(), id, rq.Rule); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update group rule")
		return
	}
	count, _ := h.d.Store.RecomputeGroup(r.Context(), id)
	h.audit(r, "group.update", "group", id.String(), map[string]any{"dynamic": !rq.Rule.Empty(), "members": count})
	g, err := h.d.Store.GetGroup(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such group")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}

func (h *handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid group id")
		return
	}
	if err := h.d.Store.DeleteGroup(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete group")
		return
	}
	h.audit(r, "group.delete", "group", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
