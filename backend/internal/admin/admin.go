// Package admin provides user, role, group, and system-settings management. It
// follows the canonical Fleet Terminal HTTP module shape: construct from
// *app.Deps, gate every route with auth + RBAC middleware, and audit state
// changes through the tamper-evident audit chain.
package admin

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

// Mount attaches admin routes to r, gated by authentication and permissions.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)

		// Users
		pr.With(d.Auth.RequirePermission("User.Edit")).Get("/users", h.listUsers)
		pr.With(d.Auth.RequirePermission("User.Create")).Post("/users", h.createUser)
		pr.With(d.Auth.RequirePermission("User.Edit")).Get("/users/{id}", h.getUser)
		pr.With(d.Auth.RequirePermission("User.Edit")).Put("/users/{id}", h.updateUser)
		pr.With(d.Auth.RequirePermission("User.Delete")).Delete("/users/{id}", h.deleteUser)
		pr.With(d.Auth.RequirePermission("User.Edit")).Post("/users/{id}/disable", h.disableUser)
		pr.With(d.Auth.RequirePermission("User.Edit")).Post("/users/{id}/unlock", h.unlockUser)
		pr.With(d.Auth.RequirePermission("User.Edit")).Post("/users/{id}/require-mfa", h.setRequireMFA)
		pr.With(d.Auth.RequirePermission("User.ResetPassword")).Post("/users/{id}/reset-password", h.resetPassword)
		pr.With(d.Auth.RequirePermission("User.ResetPassword")).Post("/users/{id}/reset-mfa", h.resetMFA)
		pr.With(d.Auth.RequirePermission("Session.Terminate")).Post("/users/{id}/terminate-sessions", h.terminateSessions)
		pr.With(d.Auth.RequirePermission("User.Edit")).Get("/users/{id}/login-history", h.loginHistory)
		pr.With(d.Auth.RequirePermission("User.Edit")).Get("/users/{id}/hosts", h.userHosts)
		pr.With(d.Auth.RequirePermission("User.Edit")).Get("/users/{id}/host-access", h.hostAccess)
		pr.With(d.Auth.RequirePermission("User.Edit")).Post("/users/{id}/host-access/{hostId}/revoke", h.revokeHostAccess)
		pr.With(d.Auth.RequirePermission("User.Edit")).Post("/users/{id}/host-access/{hostId}/restore", h.restoreHostAccess)
		pr.With(d.Auth.RequirePermission("Role.Edit")).Post("/users/{id}/roles/{roleId}", h.assignRole)
		pr.With(d.Auth.RequirePermission("Role.Edit")).Delete("/users/{id}/roles/{roleId}", h.removeRole)
		pr.With(d.Auth.RequirePermission("Group.Edit")).Post("/users/{id}/groups/{groupId}", h.addUserGroup)
		pr.With(d.Auth.RequirePermission("Group.Edit")).Delete("/users/{id}/groups/{groupId}", h.removeUserGroup)

		// Roles & permissions
		pr.With(d.Auth.RequirePermission("Role.Edit")).Get("/roles", h.listRoles)
		pr.With(d.Auth.RequirePermission("Role.Create")).Post("/roles", h.createRole)
		pr.With(d.Auth.RequirePermission("Role.Delete")).Delete("/roles/{id}", h.deleteRole)
		pr.With(d.Auth.RequirePermission("Role.Edit")).Put("/roles/{id}/permissions", h.setRolePermissions)
		pr.With(d.Auth.RequirePermission("Role.Edit")).Get("/permissions", h.listPermissions)

		// Groups
		pr.With(d.Auth.RequirePermission("Group.Edit")).Get("/groups", h.listGroups)
		pr.With(d.Auth.RequirePermission("Group.Create")).Post("/groups", h.createGroup)
		pr.With(d.Auth.RequirePermission("Group.Delete")).Delete("/groups/{id}", h.deleteGroup)

		// System settings
		pr.With(d.Auth.RequirePermission("System.Configure")).Get("/settings", h.listSettings)
		pr.With(d.Auth.RequirePermission("System.Configure")).Get("/settings/{key}", h.getSetting)
		pr.With(d.Auth.RequirePermission("System.Configure")).Put("/settings/{key}", h.setSetting)
	})
}

type handler struct{ d *app.Deps }

// permAdminAll is the wildcard permission that grants everything; only a super
// admin may grant it or create/modify a super-admin, so an Administrator can't
// escalate itself beyond its own privilege.
const permAdminAll = "Admin.All"

// actorSuper reports whether the caller is a super administrator.
func actorSuper(r *http.Request) bool {
	p := auth.MustPrincipal(r)
	return p != nil && p.IsSuperAdmin
}

// validEmail rejects an email that is empty-or-single-address-safe. It refuses
// the delimiters the notifier splits recipient lists on (comma/semicolon/space)
// and control characters, so a profile email can't smuggle in extra recipients
// or inject headers. Email is optional, so "" is allowed.
func validEmail(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > 320 {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f || r == ',' || r == ';' {
			return false
		}
	}
	at := strings.IndexByte(s, '@')
	return at > 0 && at < len(s)-1
}

func containsPerm(perms []string, key string) bool {
	for _, p := range perms {
		if p == key {
			return true
		}
	}
	return false
}

// guardSuperTarget blocks a non-super-admin from mutating a super-administrator
// account (reset password/MFA, disable, delete). Returns true — and writes 403 —
// when the request must not proceed.
func (h *handler) guardSuperTarget(w http.ResponseWriter, r *http.Request, targetID uuid.UUID) bool {
	if actorSuper(r) {
		return false
	}
	if t, err := h.d.Store.GetUserByID(r.Context(), targetID); err == nil && t.IsSuperAdmin {
		httpx.WriteError(w, http.StatusForbidden, "only a super administrator may modify a super-administrator account")
		return true
	}
	return false
}

func (h *handler) audit(r *http.Request, action, targetKind, targetID string, detail map[string]any) {
	p := auth.MustPrincipal(r)
	var actorID *uuid.UUID
	var name string
	if p != nil {
		actorID = &p.UserID
		name = p.Username
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: actorID, ActorName: name, Action: action,
		TargetKind: targetKind, TargetID: targetID, Detail: detail,
	})
}
