package auth

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// Handler exposes auth HTTP endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the auth Handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Mount attaches auth routes under the given router.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/auth/login", h.login)
	r.Post("/auth/refresh", h.refresh)
	r.Post("/auth/mfa/verify", h.mfaVerify) // login step 2 (uses challenge token)
	// Forced MFA enrollment (gated by the login setup token, not a session).
	r.Post("/auth/mfa/setup/begin", h.mfaSetupBegin)
	r.Post("/auth/mfa/setup/confirm", h.mfaSetupConfirm)
	// OIDC SSO (public: browser redirects + the login-page status probe).
	r.Get("/auth/oidc/status", h.oidcStatus)
	r.Get("/auth/oidc/login", h.oidcLogin)
	r.Get("/auth/oidc/callback", h.oidcCallback)
	r.Group(func(pr chi.Router) {
		pr.Use(h.svc.RequireAuth)
		pr.Post("/auth/logout", h.logout)
		pr.Get("/auth/me", h.me)
		pr.Post("/auth/change-password", h.changePassword)
		pr.Get("/auth/mfa", h.mfaList)
		pr.Post("/auth/mfa/totp/enroll", h.mfaEnroll)
		pr.Post("/auth/mfa/totp/confirm", h.mfaConfirm)
		pr.Delete("/auth/mfa/{id}", h.mfaDelete)
		// OIDC SSO admin config.
		pr.With(h.svc.RequirePermission("System.Configure")).Get("/auth/oidc/config", h.oidcConfigGet)
		pr.With(h.svc.RequirePermission("System.Configure")).Put("/auth/oidc/config", h.oidcConfigPut)
		pr.With(h.svc.RequirePermission("System.Configure")).Get("/auth/ldap/config", h.ldapConfigGet)
		pr.With(h.svc.RequirePermission("System.Configure")).Put("/auth/ldap/config", h.ldapConfigPut)
	})
	h.mountWebAuthn(r)
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ip, ua := clientMeta(r)
	u, err := h.svc.Authenticate(r.Context(), req.Username, req.Password)
	// Fall back to LDAP/AD when local auth fails and a directory is configured.
	if err != nil && h.svc.ldapEnabled(r.Context()) {
		if lu, lerr := h.svc.authenticateLDAP(r.Context(), req.Username, req.Password); lerr == nil {
			u, err = lu, nil
		}
	}
	if err != nil {
		_ = h.svc.store.RecordAuthEvent(r.Context(), models.AuthEvent{
			Username: req.Username, Event: "login_failure", IP: ip, UserAgent: ua,
			Detail: map[string]any{"reason": err.Error()},
		})
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	// If the account has a confirmed second factor, require it before issuing a
	// session: return a short-lived challenge the client exchanges at /auth/mfa/verify.
	if hasMFA, _ := h.svc.store.HasConfirmedMFA(r.Context(), u.ID); hasMFA {
		challenge, cerr := h.svc.IssueMFAChallenge(u.ID)
		if cerr != nil {
			writeError(w, http.StatusInternalServerError, "could not start mfa")
			return
		}
		_ = h.svc.store.RecordAuthEvent(r.Context(), models.AuthEvent{
			UserID: &u.ID, Username: u.Username, Event: "mfa_challenge", IP: ip, UserAgent: ua,
		})
		writeJSON(w, http.StatusOK, map[string]any{"mfaRequired": true, "challenge": challenge})
		return
	}
	// No confirmed factor. If MFA is mandatory for this user (per-user flag or the
	// global require_mfa setting), do NOT issue a session — return a setup token
	// that authorizes one-time enrollment, which then completes login.
	if h.svc.MFARequiredFor(r.Context(), u) {
		setup, serr := h.svc.IssueMFASetupToken(u.ID)
		if serr != nil {
			writeError(w, http.StatusInternalServerError, "could not start mfa enrollment")
			return
		}
		_ = h.svc.store.RecordAuthEvent(r.Context(), models.AuthEvent{
			UserID: &u.ID, Username: u.Username, Event: "mfa_enrollment_required", IP: ip, UserAgent: ua,
		})
		writeJSON(w, http.StatusOK, map[string]any{"mfaEnrollmentRequired": true, "setupToken": setup})
		return
	}
	h.completeLogin(w, r, u, ip, ua)
}

// mfaSetupBegin starts forced MFA enrollment for a user who must have a second
// factor but has none. It is gated by the setup token from login (not a
// session) and returns a fresh TOTP secret + otpauth URL to confirm.
func (h *Handler) mfaSetupBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SetupToken string `json:"setupToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	userID, err := h.svc.ParseMFASetupToken(req.SetupToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "enrollment session expired; sign in again")
		return
	}
	u, err := h.svc.store.GetUserByID(r.Context(), userID)
	if err != nil || u.IsDisabled {
		writeError(w, http.StatusUnauthorized, "account unavailable")
		return
	}
	secret, url, err := GenerateTOTP("Fleet Terminal", u.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate secret")
		return
	}
	enc, err := h.svc.EncryptSecret(secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not protect secret")
		return
	}
	if _, err := h.svc.store.CreateTOTPPending(r.Context(), userID, "Authenticator app", enc); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store method")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "otpauthUrl": url})
}

// mfaSetupConfirm verifies the enrollment code, marks the factor confirmed, and
// completes login (issuing a session). Gated by the login setup token.
func (h *Handler) mfaSetupConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SetupToken string `json:"setupToken"`
		Code       string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	userID, err := h.svc.ParseMFASetupToken(req.SetupToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "enrollment session expired; sign in again")
		return
	}
	enc, id, err := h.svc.store.PendingTOTPSecret(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "no pending enrollment; start again")
		return
	}
	secret, err := h.svc.DecryptSecret(enc)
	if err != nil || !ValidateTOTP(secret, req.Code) {
		writeError(w, http.StatusBadRequest, "invalid verification code")
		return
	}
	if err := h.svc.store.ConfirmMFA(r.Context(), userID, id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not confirm")
		return
	}
	u, err := h.svc.store.GetUserByID(r.Context(), userID)
	if err != nil || u.IsDisabled {
		writeError(w, http.StatusUnauthorized, "account unavailable")
		return
	}
	ip, ua := clientMeta(r)
	_, _ = h.svc.store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &userID, ActorName: u.Username, Action: "auth.mfa_enroll", TargetKind: "user",
		TargetID: userID.String(), Detail: map[string]any{"kind": "totp", "forced": true},
	})
	h.completeLogin(w, r, u, ip, ua)
}

// completeLogin issues a session + tokens and writes the login response. Shared
// by the password-only path and the post-MFA path.
func (h *Handler) completeLogin(w http.ResponseWriter, r *http.Request, u *models.User, ip, ua string) {
	tokens, err := h.svc.CreateSession(r.Context(), u, ip, ua, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	_ = h.svc.store.RecordAuthEvent(r.Context(), models.AuthEvent{
		UserID: &u.ID, Username: u.Username, Event: "login_success", IP: ip, UserAgent: ua,
	})
	_, _ = h.svc.store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &u.ID, ActorName: u.Username, Action: "auth.login", IP: ip,
	})
	h.setAuthCookies(w, tokens)
	u.Roles, _ = h.svc.store.UserRoleNames(r.Context(), u.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken":        tokens.Access,
		"accessExpiresAt":    tokens.AccessExpiry,
		"csrfToken":          tokens.CSRF,
		"user":               u,
		"mustChangePassword": u.MustChangePw,
	})
}

// mfaVerify is login step 2: validate the TOTP code against the challenge.
func (h *Handler) mfaVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	userID, err := h.svc.ParseMFAChallenge(req.Challenge)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "mfa challenge expired; sign in again")
		return
	}
	// Enforce the account lockout on the MFA step too, so failed codes can't be
	// brute-forced against a still-valid challenge after the account is locked.
	u, err := h.svc.store.GetUserByID(r.Context(), userID)
	if err != nil || u.IsDisabled {
		writeError(w, http.StatusUnauthorized, "account unavailable")
		return
	}
	if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
		writeError(w, http.StatusUnauthorized, "account is locked")
		return
	}
	secrets, err := h.svc.store.ConfirmedTOTPSecrets(r.Context(), userID)
	if err != nil || !h.svc.VerifyUserTOTP(secrets, req.Code) {
		// Count MFA failures toward the same lockout policy as password failures.
		h.svc.applyFailure(r.Context(), userID)
		ip, ua := clientMeta(r)
		_ = h.svc.store.RecordAuthEvent(r.Context(), models.AuthEvent{
			UserID: &userID, Event: "mfa_failure", IP: ip, UserAgent: ua,
		})
		writeError(w, http.StatusUnauthorized, "invalid verification code")
		return
	}
	ip, ua := clientMeta(r)
	h.completeLogin(w, r, u, ip, ua)
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	rc, err := r.Cookie(RefreshCookie)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "no refresh token")
		return
	}
	// The session id is conveyed via a companion cookie set at login.
	sc, err := r.Cookie("fleet_sid")
	if err != nil {
		writeError(w, http.StatusUnauthorized, "no session")
		return
	}
	sid, err := uuid.Parse(sc.Value)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "bad session")
		return
	}
	tokens, err := h.svc.Refresh(r.Context(), sid, rc.Value)
	if err != nil {
		h.clearAuthCookies(w)
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	h.setAuthCookies(w, tokens)
	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken":     tokens.Access,
		"accessExpiresAt": tokens.AccessExpiry,
		"csrfToken":       tokens.CSRF,
	})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	p := MustPrincipal(r)
	if p != nil {
		_ = h.svc.Logout(r.Context(), p.SessionID)
		_, _ = h.svc.store.AppendAudit(r.Context(), models.AuditEvent{
			ActorID: &p.UserID, ActorName: p.Username, Action: "auth.logout",
		})
	}
	h.clearAuthCookies(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	p := MustPrincipal(r)
	u, err := h.svc.store.GetUserByID(r.Context(), p.UserID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	u.Roles, _ = h.svc.store.UserRoleNames(r.Context(), u.ID)
	u.Groups, _ = h.svc.store.UserGroupNames(r.Context(), u.ID)
	perms := make([]string, 0, len(p.Permissions))
	for k := range p.Permissions {
		perms = append(perms, k)
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "permissions": perms, "isSuperAdmin": u.IsSuperAdmin})
}

type changePwReq struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	p := MustPrincipal(r)
	var req changePwReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	hash, err := h.svc.store.GetPasswordHash(r.Context(), p.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if ok, _ := VerifyPassword(req.CurrentPassword, hash); !ok {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	if err := h.svc.PasswordPolicy(r.Context()).Validate(req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	newHash, err := HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash failed")
		return
	}
	if err := h.svc.store.SetPasswordHash(r.Context(), p.UserID, newHash); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	_, _ = h.svc.store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: "auth.password_change",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}

// mfaList returns the caller's registered factors.
func (h *Handler) mfaList(w http.ResponseWriter, r *http.Request) {
	p := MustPrincipal(r)
	methods, err := h.svc.store.ListMFA(r.Context(), p.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list mfa")
		return
	}
	if methods == nil {
		methods = []store.MFAMethod{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"methods": methods})
}

// mfaEnroll generates a new TOTP secret and stores it as pending (unconfirmed).
func (h *Handler) mfaEnroll(w http.ResponseWriter, r *http.Request) {
	p := MustPrincipal(r)
	secret, url, err := GenerateTOTP("Fleet Terminal", p.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate secret")
		return
	}
	enc, err := h.svc.EncryptSecret(secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not protect secret")
		return
	}
	if _, err := h.svc.store.CreateTOTPPending(r.Context(), p.UserID, "Authenticator app", enc); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store method")
		return
	}
	// The plaintext secret + otpauth URL are returned ONCE so the user can scan
	// the QR / record the key; they are not retrievable afterward.
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "otpauthUrl": url})
}

// mfaConfirm validates a code against the pending secret and activates the factor.
func (h *Handler) mfaConfirm(w http.ResponseWriter, r *http.Request) {
	p := MustPrincipal(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	enc, id, err := h.svc.store.PendingTOTPSecret(r.Context(), p.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "no pending enrollment; start again")
		return
	}
	secret, err := h.svc.DecryptSecret(enc)
	if err != nil || !ValidateTOTP(secret, req.Code) {
		writeError(w, http.StatusBadRequest, "invalid verification code")
		return
	}
	if err := h.svc.store.ConfirmMFA(r.Context(), p.UserID, id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not confirm")
		return
	}
	_, _ = h.svc.store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: "auth.mfa_enroll", TargetKind: "user",
		TargetID: p.UserID.String(), Detail: map[string]any{"kind": "totp"},
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "confirmed"})
}

// mfaDelete removes one of the caller's factors.
func (h *Handler) mfaDelete(w http.ResponseWriter, r *http.Request) {
	p := MustPrincipal(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.svc.store.DeleteMFA(r.Context(), p.UserID, id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not remove")
		return
	}
	_, _ = h.svc.store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: "auth.mfa_remove", TargetKind: "user",
		TargetID: p.UserID.String(),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// --- cookie + helper plumbing ---

func (h *Handler) setAuthCookies(w http.ResponseWriter, t *Tokens) {
	secure := h.svc.cfg.CookieSecure
	domain := h.svc.cfg.CookieDomain
	http.SetCookie(w, &http.Cookie{
		Name: RefreshCookie, Value: t.Refresh, Path: "/api/v1/auth", Domain: domain,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
		Expires: time.Now().Add(h.svc.cfg.RefreshTokenTTL),
	})
	http.SetCookie(w, &http.Cookie{
		Name: "fleet_sid", Value: t.Session.ID.String(), Path: "/api/v1/auth", Domain: domain,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
		Expires: time.Now().Add(h.svc.cfg.RefreshTokenTTL),
	})
	// CSRF cookie is readable by JS (double-submit), so HttpOnly is false.
	http.SetCookie(w, &http.Cookie{
		Name: CSRFCookie, Value: t.CSRF, Path: "/", Domain: domain,
		HttpOnly: false, Secure: secure, SameSite: http.SameSiteStrictMode,
		Expires: time.Now().Add(h.svc.cfg.RefreshTokenTTL),
	})
}

func (h *Handler) clearAuthCookies(w http.ResponseWriter) {
	for _, c := range []struct{ name, path string }{
		{RefreshCookie, "/api/v1/auth"}, {"fleet_sid", "/api/v1/auth"}, {CSRFCookie, "/"},
	} {
		http.SetCookie(w, &http.Cookie{Name: c.name, Value: "", Path: c.path, MaxAge: -1})
	}
}

func clientMeta(r *http.Request) (ip, ua string) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host, r.UserAgent()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
