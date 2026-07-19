package admin

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
)

// sessionPolicyKey mirrors the store's settings key for the global conditional-
// access policy. Kept local so this handler can special-case its validation
// (self-lockout guard) in the generic settings PUT.
const sessionPolicyKey = "session_policy"

// clientIP returns the request's client IP (host portion of RemoteAddr, already
// rewritten to the real client by the realIP middleware when a trusted proxy is
// configured). Empty if it can't be parsed.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	return host
}

// validateSessionPolicy checks a proposed global policy value: every allowlist
// entry must be a valid CIDR or IP, the limit must be non-negative, and — the
// key guardrail — a non-empty allowlist must include the saver's current IP, so
// an admin cannot lock everyone (including themselves) out in one PUT. Returns a
// human-readable message on rejection, or "" if the value is acceptable.
func validateSessionPolicy(raw json.RawMessage, saverIP string) string {
	var p struct {
		IPAllowlist           []string `json:"ipAllowlist"`
		MaxConcurrentSessions int      `json:"maxConcurrentSessions"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return "invalid session policy"
	}
	if p.MaxConcurrentSessions < 0 {
		return "maximum concurrent sessions cannot be negative"
	}
	if msg := validateAllowlist(p.IPAllowlist); msg != "" {
		return msg
	}
	if len(p.IPAllowlist) > 0 && !ipInAllowlist(saverIP, p.IPAllowlist) {
		return "this allowlist does not include your current IP address — you would be locked out. Add your current network before saving."
	}
	return ""
}

// validateAllowlist reports the first malformed entry (or "" if all are valid /
// the list is empty).
func validateAllowlist(entries []string) string {
	for _, c := range entries {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.Contains(c, "/") {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return "invalid CIDR in allowlist: " + c
			}
			continue
		}
		if net.ParseIP(c) == nil {
			return "invalid IP in allowlist: " + c
		}
	}
	return ""
}

func ipInAllowlist(ip string, cidrs []string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.Contains(c, "/") {
			if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(addr) {
				return true
			}
			continue
		}
		if p := net.ParseIP(c); p != nil && p.Equal(addr) {
			return true
		}
	}
	return false
}

// getUserSessionPolicy returns a user's per-user override (or null) alongside the
// current global policy, so the UI can show what the user inherits.
func (h *handler) getUserSessionPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	override, err := h.d.Store.GetUserSessionPolicy(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load policy")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"override": override,
		"global":   h.d.Store.SessionPolicy(r.Context()),
	})
}

// setUserSessionPolicy upserts a user's override. A null field inherits the
// global value; a present-but-empty ipAllowlist opts the user out of any global
// IP restriction. When an admin edits their own override, the same self-lockout
// guard as the global policy applies.
func (h *handler) setUserSessionPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	var rq struct {
		IPAllowlist           *[]string `json:"ipAllowlist"`
		MaxConcurrentSessions *int      `json:"maxConcurrentSessions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if rq.MaxConcurrentSessions != nil && *rq.MaxConcurrentSessions < 0 {
		httpx.WriteError(w, http.StatusBadRequest, "maximum concurrent sessions cannot be negative")
		return
	}
	if rq.IPAllowlist != nil {
		if msg := validateAllowlist(*rq.IPAllowlist); msg != "" {
			httpx.WriteError(w, http.StatusBadRequest, msg)
			return
		}
		// Self-lockout guard: an admin editing their own override with a non-empty
		// allowlist that excludes their current IP would lock themselves out.
		if p := auth.MustPrincipal(r); p != nil && p.UserID == id &&
			len(*rq.IPAllowlist) > 0 && !ipInAllowlist(clientIP(r), *rq.IPAllowlist) {
			httpx.WriteError(w, http.StatusBadRequest,
				"this allowlist does not include your current IP address — you would be locked out")
			return
		}
	}
	if err := h.d.Store.SetUserSessionPolicy(r.Context(), id, rq.IPAllowlist, rq.MaxConcurrentSessions); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save policy")
		return
	}
	h.audit(r, "user.session_policy_set", "user", id.String(), map[string]any{
		"hasIPAllowlist":  rq.IPAllowlist != nil,
		"maxConcurrent":   rq.MaxConcurrentSessions,
		"allowlistLength": allowlistLen(rq.IPAllowlist),
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// clearUserSessionPolicy removes a user's override so they inherit the global.
func (h *handler) clearUserSessionPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if err := h.d.Store.DeleteUserSessionPolicy(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not clear policy")
		return
	}
	h.audit(r, "user.session_policy_clear", "user", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func allowlistLen(a *[]string) int {
	if a == nil {
		return -1
	}
	return len(*a)
}
