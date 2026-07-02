package admin

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

func (h *handler) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.d.Store.ListUsers(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list users")
		return
	}
	if users == nil {
		users = []models.User{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"users": users, "count": len(users)})
}

func (h *handler) getUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	u, err := h.d.Store.GetUserByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "user not found")
		return
	}
	u.Roles, _ = h.d.Store.UserRoleNames(r.Context(), u.ID)
	u.Groups, _ = h.d.Store.UserGroupNames(r.Context(), u.ID)
	httpx.WriteJSON(w, http.StatusOK, u)
}

type createUserReq struct {
	Username           string `json:"username"`
	Email              string `json:"email"`
	DisplayName        string `json:"displayName"`
	Password           string `json:"password"`
	IsSuperAdmin       bool   `json:"isSuperAdmin"`
	MustChangePassword bool   `json:"mustChangePassword"`
}

func (h *handler) createUser(w http.ResponseWriter, r *http.Request) {
	var rq createUserReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil || rq.Username == "" {
		httpx.WriteError(w, http.StatusBadRequest, "username is required")
		return
	}
	if rq.Password == "" {
		httpx.WriteError(w, http.StatusBadRequest, "password is required")
		return
	}
	if rq.IsSuperAdmin && !actorSuper(r) {
		httpx.WriteError(w, http.StatusForbidden, "only a super administrator may create a super administrator")
		return
	}
	if !validEmail(rq.Email) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid email address")
		return
	}
	if err := h.d.Auth.PasswordPolicy(r.Context()).Validate(rq.Password); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(rq.Password)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "hash failed")
		return
	}
	u, err := h.d.Store.CreateUser(r.Context(), store.CreateUserParams{
		Username: rq.Username, Email: rq.Email, DisplayName: rq.DisplayName,
		PasswordHash: hash, IsSuperAdmin: rq.IsSuperAdmin, MustChangePw: rq.MustChangePassword,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create user")
		return
	}
	h.audit(r, "user.create", "user", u.ID.String(), map[string]any{"username": u.Username})
	httpx.WriteJSON(w, http.StatusCreated, u)
}

type updateUserReq struct {
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	IsDisabled  bool   `json:"isDisabled"`
}

func (h *handler) updateUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if h.guardSuperTarget(w, r, id) {
		return
	}
	var rq updateUserReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.d.Store.UpdateUser(r.Context(), id, store.UpdateUserParams{
		Email: rq.Email, DisplayName: rq.DisplayName, IsDisabled: rq.IsDisabled,
	}); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update user")
		return
	}
	h.audit(r, "user.update", "user", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if h.guardSuperTarget(w, r, id) {
		return
	}
	// Destroy live sessions first (zeroize in-RAM private keys + revoke certs)
	// before the row + cascade delete, so nothing outlives the account.
	h.d.Auth.DestroyUserSessions(r.Context(), id)
	if err := h.d.Store.DeleteUser(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete user")
		return
	}
	h.audit(r, "user.delete", "user", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

type disableReq struct {
	Disabled bool `json:"disabled"`
}

func (h *handler) disableUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if h.guardSuperTarget(w, r, id) {
		return
	}
	rq := disableReq{Disabled: true}
	_ = json.NewDecoder(r.Body).Decode(&rq)
	if err := h.d.Store.SetDisabled(r.Context(), id, rq.Disabled); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update user")
		return
	}
	// Disabling immediately ends live sessions and destroys their credentials.
	if rq.Disabled {
		h.d.Auth.DestroyUserSessions(r.Context(), id)
	}
	h.audit(r, "user.set_disabled", "user", id.String(), map[string]any{"disabled": rq.Disabled})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "disabled": rq.Disabled})
}

func (h *handler) unlockUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if err := h.d.Store.Unlock(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not unlock user")
		return
	}
	h.audit(r, "user.unlock", "user", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "unlocked"})
}

type resetPasswordReq struct {
	NewPassword        string `json:"newPassword"`
	MustChangePassword bool   `json:"mustChangePassword"`
}

func (h *handler) resetPassword(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if h.guardSuperTarget(w, r, id) {
		return
	}
	var rq resetPasswordReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil || rq.NewPassword == "" {
		httpx.WriteError(w, http.StatusBadRequest, "newPassword is required")
		return
	}
	if err := h.d.Auth.PasswordPolicy(r.Context()).Validate(rq.NewPassword); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(rq.NewPassword)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "hash failed")
		return
	}
	if err := h.d.Store.SetPasswordHash(r.Context(), id, hash); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not reset password")
		return
	}
	if rq.MustChangePassword {
		if err := h.d.Store.SetMustChangePassword(r.Context(), id, true); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not flag password change")
			return
		}
	}
	h.audit(r, "user.reset_password", "user", id.String(), map[string]any{"mustChangePassword": rq.MustChangePassword})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "password_reset"})
}

// resetMFA removes all of a user's second factors (e.g. lost authenticator).
func (h *handler) resetMFA(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if h.guardSuperTarget(w, r, id) {
		return
	}
	if err := h.d.Store.ResetUserMFA(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not reset mfa")
		return
	}
	h.audit(r, "user.reset_mfa", "user", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "mfa_reset"})
}

// terminateSessions revokes all active sessions for a user (forces re-login).
func (h *handler) terminateSessions(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	// Ends every session: zeroizes keys, revokes certs, AND closes live terminals.
	h.d.Auth.DestroyUserSessions(r.Context(), id)
	h.audit(r, "user.terminate_sessions", "user", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "sessions_terminated"})
}

// loginHistory returns recent authentication events for a user.
func (h *handler) loginHistory(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	events, err := h.d.Store.ListAuthEvents(r.Context(), &id, 100)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load history")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"events": events})
}

// setRequireMFA toggles whether a user must hold a confirmed second factor. When
// turned on, the user is forced to enroll at their next login before a session
// is issued.
func (h *handler) setRequireMFA(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	var req struct {
		Require bool `json:"require"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.d.Store.SetUserRequireMFA(r.Context(), id, req.Require); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update user")
		return
	}
	h.audit(r, "user.require_mfa", "user", id.String(), map[string]any{"require": req.Require})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "requireMfa": req.Require})
}

// userHosts lists the hosts a user can currently reach (group, direct, or active
// temporary grant) — the at-a-glance access view. Super admins reach every host.
func (h *handler) userHosts(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	u, err := h.d.Store.GetUserByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "user not found")
		return
	}
	hosts, err := h.d.Store.ListAccessibleHosts(r.Context(), id, u.IsSuperAdmin)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load hosts")
		return
	}
	if hosts == nil {
		hosts = []models.Host{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"hosts": hosts, "isSuperAdmin": u.IsSuperAdmin})
}

func (h *handler) assignRole(w http.ResponseWriter, r *http.Request) {
	userID, err1 := uuid.Parse(chi.URLParam(r, "id"))
	roleID, err2 := uuid.Parse(chi.URLParam(r, "roleId"))
	if err1 != nil || err2 != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	// Don't let a non-super-admin hand out a role that grants Admin.All (which
	// would let them escalate themselves to full access).
	if perms, _ := h.d.Store.RolePermissions(r.Context(), roleID); containsPerm(perms, permAdminAll) && !actorSuper(r) {
		httpx.WriteError(w, http.StatusForbidden, "only a super administrator may assign a role that grants Admin.All")
		return
	}
	if err := h.d.Store.AssignRole(r.Context(), userID, roleID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not assign role")
		return
	}
	h.audit(r, "user.role_assign", "user", userID.String(), map[string]any{"roleId": roleID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "assigned"})
}

func (h *handler) removeRole(w http.ResponseWriter, r *http.Request) {
	userID, err1 := uuid.Parse(chi.URLParam(r, "id"))
	roleID, err2 := uuid.Parse(chi.URLParam(r, "roleId"))
	if err1 != nil || err2 != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.d.Store.RemoveRole(r.Context(), userID, roleID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not remove role")
		return
	}
	h.audit(r, "user.role_remove", "user", userID.String(), map[string]any{"roleId": roleID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (h *handler) addUserGroup(w http.ResponseWriter, r *http.Request) {
	userID, err1 := uuid.Parse(chi.URLParam(r, "id"))
	groupID, err2 := uuid.Parse(chi.URLParam(r, "groupId"))
	if err1 != nil || err2 != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.d.Store.AddUserToGroup(r.Context(), userID, groupID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not add to group")
		return
	}
	h.audit(r, "user.group_add", "user", userID.String(), map[string]any{"groupId": groupID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

func (h *handler) removeUserGroup(w http.ResponseWriter, r *http.Request) {
	userID, err1 := uuid.Parse(chi.URLParam(r, "id"))
	groupID, err2 := uuid.Parse(chi.URLParam(r, "groupId"))
	if err1 != nil || err2 != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.d.Store.RemoveUserFromGroup(r.Context(), userID, groupID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not remove from group")
		return
	}
	h.audit(r, "user.group_remove", "user", userID.String(), map[string]any{"groupId": groupID.String()})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}
