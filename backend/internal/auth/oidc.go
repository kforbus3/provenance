package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/secretbox"
	"github.com/fleet-terminal/backend/internal/store"
)

const oidcSettingKey = "oidc"

// oidcConfig is the persisted OIDC SSO configuration.
type oidcConfig struct {
	Enabled       bool              `json:"enabled"`
	Issuer        string            `json:"issuer"`
	ClientID      string            `json:"clientId"`
	ClientSecret  string            `json:"clientSecret,omitempty"` // write-only
	SecretEnc     string            `json:"secretEnc,omitempty"`    // stored, encrypted
	Scopes        []string          `json:"scopes"`
	UsernameClaim string            `json:"usernameClaim"`
	EmailClaim    string            `json:"emailClaim"`
	GroupsClaim   string            `json:"groupsClaim"`
	DefaultRole   string            `json:"defaultRole"`
	AutoProvision bool              `json:"autoProvision"`
	GroupRoleMap  map[string]string `json:"groupRoleMap"`
	ButtonText    string            `json:"buttonText"`
}

func (c oidcConfig) scopes() []string {
	if len(c.Scopes) > 0 {
		return c.Scopes
	}
	return []string{gooidc.ScopeOpenID, "profile", "email"}
}

func (c oidcConfig) usernameClaim() string {
	if c.UsernameClaim != "" {
		return c.UsernameClaim
	}
	return "preferred_username"
}
func (c oidcConfig) emailClaim() string {
	if c.EmailClaim != "" {
		return c.EmailClaim
	}
	return "email"
}

// oidcProviderCache memoizes discovered providers (JWKS + endpoints) per issuer.
var oidcProviderCache = struct {
	mu sync.Mutex
	m  map[string]*gooidc.Provider
}{m: map[string]*gooidc.Provider{}}

func (h *Handler) oidcConfig(ctx context.Context) oidcConfig {
	var c oidcConfig
	if raw, err := h.svc.store.GetSetting(ctx, oidcSettingKey); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &c)
	}
	return c
}

func (h *Handler) oidcClientSecret(c oidcConfig) string {
	if c.SecretEnc == "" {
		return ""
	}
	s, err := secretbox.Open(h.svc.cfg.CAKeyPassphrase, c.SecretEnc)
	if err != nil {
		return ""
	}
	return string(s)
}

func (h *Handler) oidcProvider(ctx context.Context, issuer string) (*gooidc.Provider, error) {
	oidcProviderCache.mu.Lock()
	defer oidcProviderCache.mu.Unlock()
	if p, ok := oidcProviderCache.m[issuer]; ok {
		return p, nil
	}
	p, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	oidcProviderCache.m[issuer] = p
	return p, nil
}

func (h *Handler) oauthConfig(c oidcConfig, p *gooidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: h.oidcClientSecret(c),
		Endpoint:     p.Endpoint(),
		RedirectURL:  strings.TrimRight(h.svc.cfg.PublicURL, "/") + "/api/v1/auth/oidc/callback",
		Scopes:       c.scopes(),
	}
}

// oidcConfigGet returns the admin config with the client secret redacted.
func (h *Handler) oidcConfigGet(w http.ResponseWriter, r *http.Request) {
	c := h.oidcConfig(r.Context())
	secretSet := c.SecretEnc != ""
	c.ClientSecret, c.SecretEnc = "", ""
	writeJSON(w, http.StatusOK, map[string]any{"config": c, "secretSet": secretSet})
}

// oidcConfigPut saves the config, encrypting a newly-supplied client secret and
// preserving the stored one otherwise.
func (h *Handler) oidcConfigPut(w http.ResponseWriter, r *http.Request) {
	var c oidcConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cur := h.oidcConfig(r.Context())
	if c.ClientSecret != "" {
		enc, err := secretbox.Seal(h.svc.cfg.CAKeyPassphrase, []byte(c.ClientSecret))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not seal secret")
			return
		}
		c.SecretEnc = enc
	} else {
		c.SecretEnc = cur.SecretEnc
	}
	c.ClientSecret = ""
	if err := h.svc.store.SetSetting(r.Context(), oidcSettingKey, c); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save settings")
		return
	}
	// Re-discovery on next login picks up an issuer change.
	oidcProviderCache.mu.Lock()
	delete(oidcProviderCache.m, cur.Issuer)
	delete(oidcProviderCache.m, c.Issuer)
	oidcProviderCache.mu.Unlock()
	if p := MustPrincipal(r); p != nil {
		_, _ = h.svc.store.AppendAudit(r.Context(), models.AuditEvent{
			ActorID: &p.UserID, ActorName: p.Username, Action: "system.oidc_config", TargetKind: "system",
			Detail: map[string]any{"enabled": c.Enabled, "issuer": c.Issuer},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true})
}

// oidcStatus is public: the login page calls it to decide whether to show the
// SSO button.
func (h *Handler) oidcStatus(w http.ResponseWriter, r *http.Request) {
	c := h.oidcConfig(r.Context())
	btn := c.ButtonText
	if btn == "" {
		btn = "Sign in with SSO"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":    c.Enabled && c.Issuer != "" && c.ClientID != "",
		"buttonText": btn,
	})
}

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *Handler) setOIDCCookie(w http.ResponseWriter, name, val string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: val, Path: "/", HttpOnly: true,
		Secure: h.svc.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 300,
	})
}

// oidcLogin starts the authorization-code flow: it stores state/nonce/PKCE in
// short-lived cookies and redirects to the identity provider.
func (h *Handler) oidcLogin(w http.ResponseWriter, r *http.Request) {
	c := h.oidcConfig(r.Context())
	if !c.Enabled || c.Issuer == "" || c.ClientID == "" {
		http.Redirect(w, r, "/login?sso=disabled", http.StatusFound)
		return
	}
	p, err := h.oidcProvider(r.Context(), c.Issuer)
	if err != nil {
		http.Redirect(w, r, "/login?sso=error", http.StatusFound)
		return
	}
	state, nonce, verifier := randToken(), randToken(), oauth2.GenerateVerifier()
	h.setOIDCCookie(w, "oidc_state", state)
	h.setOIDCCookie(w, "oidc_nonce", nonce)
	h.setOIDCCookie(w, "oidc_verifier", verifier)
	url := h.oauthConfig(c, p).AuthCodeURL(state, gooidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusFound)
}

// oidcCallback completes the flow: validate state, exchange the code, verify the
// ID token (signature/issuer/audience/nonce), provision/find the user, issue a
// Fleet session, and redirect into the app.
func (h *Handler) oidcCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := h.oidcConfig(ctx)
	fail := func(reason string) {
		http.Redirect(w, r, "/login?sso=error", http.StatusFound)
		_ = reason
	}
	if !c.Enabled {
		fail("disabled")
		return
	}
	stateCookie, _ := r.Cookie("oidc_state")
	if stateCookie == nil || stateCookie.Value == "" || r.URL.Query().Get("state") != stateCookie.Value {
		fail("bad state")
		return
	}
	nonceCookie, _ := r.Cookie("oidc_nonce")
	verifierCookie, _ := r.Cookie("oidc_verifier")
	if nonceCookie == nil || verifierCookie == nil {
		fail("missing nonce/verifier")
		return
	}

	p, err := h.oidcProvider(ctx, c.Issuer)
	if err != nil {
		fail("provider")
		return
	}
	oauthCfg := h.oauthConfig(c, p)
	tok, err := oauthCfg.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifierCookie.Value))
	if err != nil {
		fail("exchange: " + err.Error())
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		fail("no id_token")
		return
	}
	idToken, err := p.Verifier(&gooidc.Config{ClientID: c.ClientID}).Verify(ctx, rawID)
	if err != nil {
		fail("verify: " + err.Error())
		return
	}
	if idToken.Nonce != nonceCookie.Value {
		fail("nonce mismatch")
		return
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		fail("claims")
		return
	}

	user, err := h.provisionOIDCUser(ctx, c, claims)
	if err != nil {
		http.Redirect(w, r, "/login?sso="+err.Error(), http.StatusFound)
		return
	}

	ip, ua := clientMeta(r)
	tokens, serr := h.svc.CreateSession(ctx, user, ip, ua, true) // IdP handled MFA
	if serr != nil {
		fail("session")
		return
	}
	// Clear the transient flow cookies.
	for _, n := range []string{"oidc_state", "oidc_nonce", "oidc_verifier"} {
		http.SetCookie(w, &http.Cookie{Name: n, Path: "/", MaxAge: -1})
	}
	h.setAuthCookies(w, tokens)
	_ = h.svc.store.RecordAuthEvent(ctx, models.AuthEvent{
		UserID: &user.ID, Username: user.Username, Event: "login_success", IP: ip, UserAgent: ua,
		Detail: map[string]any{"method": "oidc"},
	})
	_, _ = h.svc.store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &user.ID, ActorName: user.Username, Action: "auth.login", IP: ip,
		Detail: map[string]any{"method": "oidc"},
	})
	// The SPA re-establishes its access token from the refresh cookie on load.
	http.Redirect(w, r, "/", http.StatusFound)
}

func claimString(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// provisionOIDCUser finds (by username then email) or provisions an external
// account from the verified claims, and syncs group→role mappings additively.
func (h *Handler) provisionOIDCUser(ctx context.Context, c oidcConfig, claims map[string]any) (*models.User, error) {
	username := claimString(claims, c.usernameClaim())
	email := claimString(claims, c.emailClaim())
	if username == "" {
		username = email
	}
	if username == "" {
		return nil, errors.New("no_username")
	}
	display := claimString(claims, "name")

	user, err := h.svc.store.GetUserByUsername(ctx, username)
	if err != nil && email != "" {
		user, err = h.svc.store.GetUserByEmail(ctx, email)
	}
	if err != nil {
		if !c.AutoProvision {
			return nil, errors.New("not_provisioned")
		}
		pwHash := randToken() + randToken() // unusable local password
		user, err = h.svc.store.CreateUser(ctx, store.CreateUserParams{
			Username: username, Email: email, DisplayName: display,
			PasswordHash: pwHash, AuthSource: "oidc",
		})
		if err != nil {
			return nil, errors.New("provision_failed")
		}
		role := c.DefaultRole
		if role == "" {
			role = "Read-Only"
		}
		_ = h.svc.store.AssignRoleByName(ctx, user.ID, role)
	}
	if user.IsDisabled {
		return nil, errors.New("disabled")
	}
	// Group → role mapping (additive): assign Fleet roles for matching IdP groups.
	if len(c.GroupRoleMap) > 0 {
		for _, g := range claimStrings(claims, c.GroupsClaim) {
			if role, ok := c.GroupRoleMap[g]; ok && role != "" {
				_ = h.svc.store.AssignRoleByName(ctx, user.ID, role)
			}
		}
	}
	return user, nil
}

func claimStrings(claims map[string]any, key string) []string {
	if key == "" {
		return nil
	}
	raw, ok := claims[key]
	if !ok {
		return nil
	}
	var out []string
	switch v := raw.(type) {
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = v
	case string:
		out = []string{v}
	}
	return out
}
