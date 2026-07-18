// Package scim implements a SCIM 2.0 (RFC 7643/7644) provisioning endpoint so an
// identity provider (Okta, Azure AD, etc.) can create, update, and — critically —
// deprovision Fleet user accounts automatically. It pairs with SAML SSO: SCIM
// manages the account lifecycle, SAML authenticates the login.
//
// Authentication is a dedicated static bearer token (prefix "scim_"), issued from
// the admin UI and stored only as a hash. This is intentionally independent of the
// interactive-session and flt_ service-account schemes so the provisioning
// credential can be rotated without touching either.
package scim

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/models"
)

const scimSettingKey = "scim"

// scimConfig is the persisted SCIM provisioning configuration. Only the token
// hash is stored — the plaintext token is shown once, at issuance.
type scimConfig struct {
	Enabled     bool   `json:"enabled"`
	TokenHash   string `json:"tokenHash,omitempty"` // sha256 hex of the bearer token
	DefaultRole string `json:"defaultRole"`         // role for newly provisioned users
	AuthSource  string `json:"authSource"`          // how provisioned users log in: saml (default) | oidc | ldap
}

func (c scimConfig) authSource() string {
	switch c.AuthSource {
	case "oidc", "ldap", "saml":
		return c.AuthSource
	default:
		return "saml"
	}
}

func (c scimConfig) defaultRole() string {
	if c.DefaultRole != "" {
		return c.DefaultRole
	}
	return "Read-Only"
}

type handler struct{ d *app.Deps }

// Mount registers the admin config routes (session + System.Configure) and the
// SCIM 2.0 protocol routes (SCIM bearer token).
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}

	// Admin management of the SCIM integration.
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("System.Configure"))
		pr.Get("/scim/config", h.configGet)
		pr.Put("/scim/config", h.configPut)
		pr.Post("/scim/token", h.issueToken)
		pr.Delete("/scim/token", h.revokeToken)
	})

	// SCIM 2.0 protocol surface, authenticated by the provisioning bearer token.
	r.Group(func(pr chi.Router) {
		pr.Use(h.requireSCIMToken)
		pr.Get("/scim/v2/ServiceProviderConfig", h.serviceProviderConfig)
		pr.Get("/scim/v2/ResourceTypes", h.resourceTypes)
		pr.Get("/scim/v2/Schemas", h.schemas)
		pr.Get("/scim/v2/Users", h.listUsers)
		pr.Post("/scim/v2/Users", h.createUser)
		pr.Get("/scim/v2/Users/{id}", h.getUser)
		pr.Put("/scim/v2/Users/{id}", h.replaceUser)
		pr.Patch("/scim/v2/Users/{id}", h.patchUser)
		pr.Delete("/scim/v2/Users/{id}", h.deleteUser)
	})
}

func (h *handler) config(ctx context.Context) scimConfig {
	var c scimConfig
	if raw, err := h.d.Store.GetSetting(ctx, scimSettingKey); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &c)
	}
	return c
}

// requireSCIMToken authenticates a SCIM request against the issued token's hash.
func (h *handler) requireSCIMToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := h.config(r.Context())
		if !c.Enabled || c.TokenHash == "" {
			writeSCIMError(w, http.StatusUnauthorized, "SCIM provisioning is not enabled")
			return
		}
		tok := bearerToken(r)
		if tok == "" {
			writeSCIMError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		want, _ := hex.DecodeString(c.TokenHash)
		got := sha256.Sum256([]byte(tok))
		if len(want) != len(got) || subtle.ConstantTimeCompare(want, got[:]) != 1 {
			writeSCIMError(w, http.StatusUnauthorized, "invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}

// baseURL is the SCIM service root advertised to the IdP.
func (h *handler) baseURL() string {
	return strings.TrimRight(h.d.Cfg.PublicURL, "/") + "/api/v1/scim/v2"
}

// ---- Admin config ----------------------------------------------------------

func (h *handler) configGet(w http.ResponseWriter, r *http.Request) {
	c := h.config(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":     c.Enabled,
		"tokenSet":    c.TokenHash != "",
		"defaultRole": c.defaultRole(),
		"authSource":  c.authSource(),
		"baseUrl":     h.baseURL(),
	})
}

func (h *handler) configPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled     bool   `json:"enabled"`
		DefaultRole string `json:"defaultRole"`
		AuthSource  string `json:"authSource"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	c := h.config(r.Context())
	c.Enabled = in.Enabled
	c.DefaultRole = in.DefaultRole
	c.AuthSource = in.AuthSource
	if err := h.d.Store.SetSetting(r.Context(), scimSettingKey, c); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not save settings"})
		return
	}
	h.audit(r, "system.scim_config", map[string]any{"enabled": c.Enabled})
	writeJSON(w, http.StatusOK, map[string]any{"saved": true})
}

// issueToken generates a new provisioning token, storing only its hash and
// returning the plaintext exactly once.
func (h *handler) issueToken(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not generate token"})
		return
	}
	token := "scim_" + base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(token))

	c := h.config(r.Context())
	c.TokenHash = hex.EncodeToString(sum[:])
	c.Enabled = true
	if err := h.d.Store.SetSetting(r.Context(), scimSettingKey, c); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not save token"})
		return
	}
	h.audit(r, "system.scim_token_issue", nil)
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "baseUrl": h.baseURL()})
}

func (h *handler) revokeToken(w http.ResponseWriter, r *http.Request) {
	c := h.config(r.Context())
	c.TokenHash = ""
	c.Enabled = false
	if err := h.d.Store.SetSetting(r.Context(), scimSettingKey, c); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not revoke token"})
		return
	}
	h.audit(r, "system.scim_token_revoke", nil)
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

func (h *handler) audit(r *http.Request, action string, detail map[string]any) {
	p := auth.MustPrincipal(r)
	if p == nil {
		return
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: action, TargetKind: "system", Detail: detail,
	})
}

// ---- JSON helpers ----------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeSCIM(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	writeSCIM(w, status, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  strconv.Itoa(status), // RFC 7644 §3.12: status is a string
		"detail":  detail,
	})
}
