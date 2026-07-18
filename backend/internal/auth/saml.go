package auth

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"net/http"
	"strings"

	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

const samlSettingKey = "saml"

// samlConfig is the persisted SAML 2.0 Service Provider configuration. The IdP
// certificate is a public signing certificate (used to verify assertion
// signatures), so nothing here is secret — no secretbox sealing is needed.
type samlConfig struct {
	Enabled         bool              `json:"enabled"`
	IdPEntityID     string            `json:"idpEntityId"`    // IdP issuer/entity ID
	IdPSSOURL       string            `json:"idpSsoUrl"`      // IdP SSO (redirect binding) URL
	IdPCertificate  string            `json:"idpCertificate"` // PEM (or base64 DER) signing cert
	SPEntityID      string            `json:"spEntityId"`     // our entity ID (audience); defaults to the metadata URL
	UsernameAttr    string            `json:"usernameAttr"`   // empty = use the assertion NameID
	EmailAttr       string            `json:"emailAttr"`
	DisplayNameAttr string            `json:"displayNameAttr"`
	GroupsAttr      string            `json:"groupsAttr"`
	DefaultRole     string            `json:"defaultRole"`
	AutoProvision   bool              `json:"autoProvision"` // gate: create users just-in-time on first login
	GroupRoleMap    map[string]string `json:"groupRoleMap"`
	ButtonText      string            `json:"buttonText"`
}

func (c samlConfig) enabled() bool {
	return c.Enabled && c.IdPSSOURL != "" && c.IdPEntityID != "" && c.IdPCertificate != ""
}

func (h *Handler) samlConfig(ctx context.Context) samlConfig {
	var c samlConfig
	if raw, err := h.svc.store.GetSetting(ctx, samlSettingKey); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &c)
	}
	return c
}

// spEntityID returns the configured SP entity ID, defaulting to our metadata URL.
func (h *Handler) spEntityID(c samlConfig) string {
	if c.SPEntityID != "" {
		return c.SPEntityID
	}
	return strings.TrimRight(h.svc.cfg.PublicURL, "/") + "/api/v1/auth/saml/metadata"
}

func (h *Handler) samlACSURL() string {
	return strings.TrimRight(h.svc.cfg.PublicURL, "/") + "/api/v1/auth/saml/acs"
}

// parseIDPCert accepts a PEM certificate or a bare base64 DER blob and returns
// the parsed X.509 certificate.
func parseIDPCert(certPEM string) (*x509.Certificate, error) {
	certPEM = strings.TrimSpace(certPEM)
	if certPEM == "" {
		return nil, errors.New("no certificate")
	}
	der := []byte(nil)
	if block, _ := pem.Decode([]byte(certPEM)); block != nil {
		der = block.Bytes
	} else {
		// Not PEM-wrapped: treat the body as base64 DER (strip any whitespace).
		clean := strings.Join(strings.Fields(certPEM), "")
		b, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			return nil, errors.New("certificate is neither PEM nor base64 DER")
		}
		der = b
	}
	return x509.ParseCertificate(der)
}

// samlSP builds the Service Provider from config. The IdP certificate is parsed
// into the signature-validation store when present; metadata generation works
// without it.
func (h *Handler) samlSP(c samlConfig) (*saml2.SAMLServiceProvider, error) {
	certStore := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{}}
	if c.IdPCertificate != "" {
		cert, err := parseIDPCert(c.IdPCertificate)
		if err != nil {
			return nil, err
		}
		certStore.Roots = append(certStore.Roots, cert)
	}
	spID := h.spEntityID(c)
	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      c.IdPSSOURL,
		IdentityProviderIssuer:      c.IdPEntityID,
		ServiceProviderIssuer:       spID,
		AssertionConsumerServiceURL: h.samlACSURL(),
		SignAuthnRequests:           false, // baseline: unsigned request, IdP-signed assertion
		AudienceURI:                 spID,
		IDPCertificateStore:         certStore,
	}, nil
}

// samlStatus is public: the login page calls it to decide whether to show the
// SAML sign-in button.
func (h *Handler) samlStatus(w http.ResponseWriter, r *http.Request) {
	c := h.samlConfig(r.Context())
	btn := c.ButtonText
	if btn == "" {
		btn = "Sign in with SAML"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":    c.enabled(),
		"buttonText": btn,
	})
}

// samlLogin starts SP-initiated SSO: redirect the browser to the IdP with a
// deflate+base64 AuthnRequest (HTTP-Redirect binding).
func (h *Handler) samlLogin(w http.ResponseWriter, r *http.Request) {
	c := h.samlConfig(r.Context())
	if !c.enabled() {
		http.Redirect(w, r, "/login?sso=disabled", http.StatusFound)
		return
	}
	sp, err := h.samlSP(c)
	if err != nil {
		http.Redirect(w, r, "/login?sso=error", http.StatusFound)
		return
	}
	url, err := sp.BuildAuthURL(samlRelay(r.URL.Query().Get("returnTo")))
	if err != nil {
		http.Redirect(w, r, "/login?sso=error", http.StatusFound)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

// samlACS consumes the IdP's SAML Response (HTTP-POST binding). It validates the
// signature, audience, and time bounds, provisions/finds the user, issues a Fleet
// session, and redirects into the app. Handles both SP- and IdP-initiated flows.
func (h *Handler) samlACS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := h.samlConfig(ctx)
	ip, ua := clientMeta(r)
	fail := func(reason string) {
		_ = h.svc.store.RecordAuthEvent(ctx, models.AuthEvent{
			Event: "login_failure", IP: ip, UserAgent: ua,
			Detail: map[string]any{"method": "saml", "reason": reason},
		})
		http.Redirect(w, r, "/login?sso=error", http.StatusFound)
	}
	if !c.enabled() {
		http.Redirect(w, r, "/login?sso=disabled", http.StatusFound)
		return
	}
	sp, err := h.samlSP(c)
	if err != nil {
		fail("sp_build")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail("bad_form")
		return
	}
	info, err := sp.RetrieveAssertionInfo(r.FormValue("SAMLResponse"))
	if err != nil {
		fail("assertion_invalid")
		return
	}
	// gosaml2 reports non-fatal validation problems (time/audience) as warnings —
	// treat them as hard failures for a login credential.
	if info.WarningInfo != nil && (info.WarningInfo.InvalidTime || info.WarningInfo.NotInAudience) {
		fail("assertion_untrusted")
		return
	}

	user, err := h.provisionSAMLUser(ctx, c, info)
	if err != nil {
		http.Redirect(w, r, "/login?sso="+err.Error(), http.StatusFound)
		return
	}

	tokens, serr := h.svc.CreateSession(ctx, user, ip, ua, true) // IdP handled MFA
	if serr != nil {
		fail("session")
		return
	}
	h.setAuthCookies(w, tokens)
	_ = h.svc.store.RecordAuthEvent(ctx, models.AuthEvent{
		UserID: &user.ID, Username: user.Username, Event: "login_success", IP: ip, UserAgent: ua,
		Detail: map[string]any{"method": "saml"},
	})
	_, _ = h.svc.store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &user.ID, ActorName: user.Username, Action: "auth.login", IP: ip,
		Detail: map[string]any{"method": "saml"},
	})
	http.Redirect(w, r, samlRelay(r.FormValue("RelayState")), http.StatusFound)
}

// samlMetadata serves the SP metadata XML the IdP needs to register this app.
func (h *Handler) samlMetadata(w http.ResponseWriter, r *http.Request) {
	c := h.samlConfig(r.Context())
	sp, err := h.samlSP(c)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not build metadata")
		return
	}
	md, err := sp.Metadata()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not build metadata")
		return
	}
	out, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not encode metadata")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}

// samlConfigGet returns the admin config. The IdP certificate is public, so
// nothing is redacted.
func (h *Handler) samlConfigGet(w http.ResponseWriter, r *http.Request) {
	c := h.samlConfig(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"config":      c,
		"acsUrl":      h.samlACSURL(),
		"spEntityId":  h.spEntityID(c),
		"metadataUrl": strings.TrimRight(h.svc.cfg.PublicURL, "/") + "/api/v1/auth/saml/metadata",
	})
}

// samlConfigPut saves the config after validating the IdP certificate parses.
func (h *Handler) samlConfigPut(w http.ResponseWriter, r *http.Request) {
	var c samlConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if c.IdPCertificate != "" {
		if _, err := parseIDPCert(c.IdPCertificate); err != nil {
			writeError(w, http.StatusBadRequest, "IdP certificate is not valid PEM or base64 DER")
			return
		}
	}
	if err := h.svc.store.SetSetting(r.Context(), samlSettingKey, c); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save settings")
		return
	}
	if p := MustPrincipal(r); p != nil {
		_, _ = h.svc.store.AppendAudit(r.Context(), models.AuditEvent{
			ActorID: &p.UserID, ActorName: p.Username, Action: "system.saml_config", TargetKind: "system",
			Detail: map[string]any{"enabled": c.Enabled, "idpEntityId": c.IdPEntityID},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true})
}

// provisionSAMLUser finds (by username then email) or just-in-time provisions an
// external account from a validated, IdP-signed assertion, and syncs group→role
// mappings additively. Because the assertion is signed by the trusted IdP, its
// attributes (including email) are authoritative — unlike an unsigned OIDC email
// claim, no separate "verified" gate is needed.
func (h *Handler) provisionSAMLUser(ctx context.Context, c samlConfig, info *saml2.AssertionInfo) (*models.User, error) {
	username := ""
	if c.UsernameAttr != "" {
		username = samlAttrFirst(info.Values, c.UsernameAttr)
	}
	if username == "" {
		username = strings.TrimSpace(info.NameID)
	}
	if username == "" {
		return nil, errors.New("no_username")
	}
	email := samlAttrFirst(info.Values, c.EmailAttr)
	display := samlAttrFirst(info.Values, c.DisplayNameAttr)

	// Only ever resolve to an account this SAML provider owns; a matched account
	// with a different AuthSource is a hard error, not a silent takeover (mirrors
	// the OIDC provisioning guard).
	user, err := h.svc.store.GetUserByUsername(ctx, username)
	if err == nil && user.AuthSource != "saml" {
		return nil, errors.New("account_conflict")
	}
	if err != nil && email != "" {
		user, err = h.svc.store.GetUserByEmail(ctx, email)
		if err == nil && user.AuthSource != "saml" {
			return nil, errors.New("account_conflict")
		}
	}
	if err != nil {
		if !c.AutoProvision {
			return nil, errors.New("not_provisioned")
		}
		pwHash := randToken() + randToken() // unusable local password
		user, err = h.svc.store.CreateUser(ctx, store.CreateUserParams{
			Username: username, Email: email, DisplayName: display,
			PasswordHash: pwHash, AuthSource: "saml",
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
	if len(c.GroupRoleMap) > 0 {
		for _, g := range samlAttrValues(info.Values, c.GroupsAttr) {
			if role, ok := c.GroupRoleMap[g]; ok && role != "" {
				_ = h.svc.store.AssignRoleByName(ctx, user.ID, role)
			}
		}
	}
	return user, nil
}

// samlAttrValues returns all trimmed, non-empty values of a SAML assertion
// attribute (by Name).
func samlAttrValues(vals saml2.Values, name string) []string {
	if name == "" {
		return nil
	}
	attr, ok := vals[name]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(attr.Values))
	for _, v := range attr.Values {
		if s := strings.TrimSpace(v.Value); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func samlAttrFirst(vals saml2.Values, name string) string {
	if vs := samlAttrValues(vals, name); len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// samlRelay sanitizes a RelayState/returnTo into a safe same-site path, guarding
// against open redirects. Anything not a simple absolute path falls back to "/".
func samlRelay(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return "/"
	}
	return s
}
