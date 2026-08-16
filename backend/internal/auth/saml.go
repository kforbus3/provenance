package auth

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/google/uuid"

	"github.com/kforbus3/Moorgate/backend/internal/models"
	"github.com/kforbus3/Moorgate/backend/internal/secretbox"
	"github.com/kforbus3/Moorgate/backend/internal/store"
)

// samlLogoutStatusSuccess is the SAML top-level status the SP returns to an
// IdP-initiated LogoutRequest once the local Fleet session has been terminated.
const samlLogoutStatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

// samlNameIDFormatUnspecified is the NameID Format asserted on SP-built
// LogoutRequests. The ACS does not surface the Format the IdP originally used,
// so we send "unspecified"; most IdPs treat SLO NameID matching leniently, and
// the local session is torn down regardless of whether the IdP accepts it.
const samlNameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

const samlSettingKey = "saml"

// samlAssertionTTL bounds how long a consumed assertion ID is remembered for
// replay detection. It comfortably exceeds a typical assertion validity window
// (a few minutes), so a captured SAMLResponse cannot be re-POSTed to the ACS to
// mint a second session while its signature is still time-valid.
const samlAssertionTTL = 10 * time.Minute

// assertionReplayCache is an in-memory, per-process record of assertion IDs that
// have already been consumed at the ACS. gosaml2 validates the signature, audience
// and time bounds of an assertion but does NOT track one-time use, so without this
// a valid signed SAMLResponse could be replayed until it expired. NOTE: the cache
// is per-process; a multi-replica deployment behind a load balancer would need a
// shared store (e.g. Redis) to close the window across replicas — documented as a
// known limitation. It still closes the single-node window that had no guard.
type assertionReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time // assertion ID -> expiry
	ttl  time.Duration
}

func newAssertionReplayCache(ttl time.Duration) *assertionReplayCache {
	return &assertionReplayCache{seen: map[string]time.Time{}, ttl: ttl}
}

// observe records id and reports whether it is a replay (already seen and not yet
// expired). It opportunistically evicts expired entries so the map cannot grow
// without bound.
func (c *assertionReplayCache) observe(id string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.seen {
		if now.After(exp) {
			delete(c.seen, k)
		}
	}
	if exp, ok := c.seen[id]; ok && now.Before(exp) {
		return true // replay
	}
	c.seen[id] = now.Add(c.ttl)
	return false
}

// samlReplayCache is the process-wide assertion replay guard for the ACS.
var samlReplayCache = newAssertionReplayCache(samlAssertionTTL)

// samlConfig is the persisted SAML 2.0 Service Provider configuration. The IdP
// certificate is a public signing certificate (used to verify assertion
// signatures) and most fields are non-secret, but the SP signing private key IS
// secret: it is supplied via SPPrivateKey (write-only) and persisted encrypted in
// SPPrivateKeyEnc — the plaintext is never stored or echoed back.
type samlConfig struct {
	Enabled         bool              `json:"enabled"`
	IdPEntityID     string            `json:"idpEntityId"`               // IdP issuer/entity ID
	IdPSSOURL       string            `json:"idpSsoUrl"`                 // IdP SSO (redirect binding) URL
	IdPCertificate  string            `json:"idpCertificate"`            // PEM (or base64 DER) signing cert
	IdPSLOURL       string            `json:"idpSloUrl"`                 // IdP Single Logout endpoint ("" disables SLO)
	IdPSLOBinding   string            `json:"idpSloBinding"`             // "redirect" (default) or "post"; informational
	SPEntityID      string            `json:"spEntityId"`                // our entity ID (audience); defaults to the metadata URL
	SPCertificate   string            `json:"spCertificate"`             // PEM SP signing cert (public; published in metadata)
	SPPrivateKey    string            `json:"spPrivateKey,omitempty"`    // write-only: PEM PKCS1/PKCS8/SEC1 signing key
	SPPrivateKeyEnc string            `json:"spPrivateKeyEnc,omitempty"` // stored, secretbox-sealed
	UsernameAttr    string            `json:"usernameAttr"`              // empty = use the assertion NameID
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

// samlSLOURL is the SP's Single Logout service endpoint (where the IdP delivers
// LogoutResponses to our requests, and IdP-initiated LogoutRequests).
func (h *Handler) samlSLOURL() string {
	return strings.TrimRight(h.svc.cfg.PublicURL, "/") + "/api/v1/auth/saml/slo"
}

// spPrivateKey returns the decrypted SP signing private key PEM, or "" when none
// is configured (or it cannot be unsealed). The plaintext is never logged.
func (h *Handler) spPrivateKey(c samlConfig) string {
	if c.SPPrivateKeyEnc == "" {
		return ""
	}
	s, err := secretbox.Open(h.svc.cfg.CAKeyPassphrase, c.SPPrivateKeyEnc)
	if err != nil {
		return ""
	}
	return string(s)
}

// parseSPPrivateKey accepts a PEM PKCS#1 (RSA), PKCS#8, or SEC1 (EC) private key
// and returns it as a crypto.Signer for XML-DSig signing.
func parseSPPrivateKey(keyPEM string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(keyPEM)))
	if block == nil {
		return nil, errors.New("SP private key is not valid PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("SP private key type is not a signer")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("SP private key is not PKCS#1, PKCS#8, or SEC1 PEM")
}

// parseSPKeyPair builds a gosaml2 signing key store from the SP private key and
// certificate PEMs. Both are required.
func parseSPKeyPair(keyPEM, certPEM string) (*saml2.KeyStore, error) {
	if strings.TrimSpace(keyPEM) == "" || strings.TrimSpace(certPEM) == "" {
		return nil, errors.New("SP signing key and certificate are both required")
	}
	signer, err := parseSPPrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	cert, err := parseIDPCert(certPEM) // parses a PEM/base64-DER X.509 cert
	if err != nil {
		return nil, errors.New("SP certificate is not valid PEM or base64 DER")
	}
	return &saml2.KeyStore{Signer: signer, Cert: cert.Raw}, nil
}

// spSigningKeyStore returns the configured SP signing key store, or (nil, nil)
// when no SP key is configured (metadata + unsigned requests still work). A
// configured-but-invalid key pair returns an error.
func (h *Handler) spSigningKeyStore(c samlConfig) (*saml2.KeyStore, error) {
	priv := h.spPrivateKey(c)
	if priv == "" || strings.TrimSpace(c.SPCertificate) == "" {
		return nil, nil
	}
	return parseSPKeyPair(priv, c.SPCertificate)
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
	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      c.IdPSSOURL,
		IdentityProviderIssuer:      c.IdPEntityID,
		IdentityProviderSLOURL:      c.IdPSLOURL,
		ServiceProviderIssuer:       spID,
		AssertionConsumerServiceURL: h.samlACSURL(),
		ServiceProviderSLOURL:       h.samlSLOURL(),
		AudienceURI:                 spID,
		IDPCertificateStore:         certStore,
		NameIdFormat:                samlNameIDFormatUnspecified,
	}
	// Load the SP signing key store when one is configured. With a key present the
	// SP signs AuthnRequests and SLO LogoutRequests/Responses; without one, metadata
	// generation and unsigned AuthnRequests still work. The ACS always requires the
	// assertion itself to be IdP-signed, which is the security-critical direction.
	ks, err := h.spSigningKeyStore(c)
	if err != nil {
		return nil, err
	}
	if ks != nil {
		if err := sp.SetSPSigningKeyStore(ks); err != nil {
			return nil, err
		}
		sp.SignAuthnRequests = true
	}
	return sp, nil
}

// samlSPCanSign reports whether the SP holds a signing key. Signed SLO is only
// attempted when this is true (most IdPs reject unsigned logout messages); it is
// derived from SignAuthnRequests, which samlSP sets together with the key store.
func samlSPCanSign(sp *saml2.SAMLServiceProvider) bool {
	return sp.SignAuthnRequests
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
	// One-time use: reject a signed assertion whose ID we have already consumed
	// within the replay window (gosaml2 validates signature/time/audience but not
	// single-use). An assertion with no ID cannot be replay-tracked, so it is
	// refused rather than trusted.
	now := time.Now()
	for _, a := range info.Assertions {
		if a.ID == "" || samlReplayCache.observe(a.ID, now) {
			fail("assertion_replay")
			return
		}
	}

	user, err := h.provisionSAMLUser(ctx, c, info)
	if err != nil {
		http.Redirect(w, r, "/login?sso="+err.Error(), http.StatusFound)
		return
	}

	tokens, serr := h.svc.CreateSession(ctx, user, ip, ua, true) // IdP handled MFA
	if serr != nil {
		if PolicyDenied(serr) {
			_ = h.svc.store.RecordAuthEvent(ctx, models.AuthEvent{
				UserID: &user.ID, Username: user.Username, Event: "login_blocked", IP: ip, UserAgent: ua,
				Detail: map[string]any{"method": "saml"},
			})
			http.Redirect(w, r, "/login?sso=blocked", http.StatusFound)
			return
		}
		fail("session")
		return
	}
	h.setAuthCookies(w, tokens)
	// Remember the IdP's subject NameID + SessionIndex so an SP-initiated logout can
	// build a matching LogoutRequest later (the Fleet session table doesn't carry
	// SAML identifiers, and this stays entirely within the auth package).
	h.setSAMLLogoutCookies(w, info.NameID, info.SessionIndex)
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

// setSAMLLogoutCookies records the SAML subject NameID and SessionIndex from a
// successful login so a later SP-initiated logout can reference them. They are
// scoped to /api/v1/auth (like the session cookies) and SameSite=Lax so a
// same-site top-level navigation to the logout endpoint still carries them.
func (h *Handler) setSAMLLogoutCookies(w http.ResponseWriter, nameID, sessionIndex string) {
	if nameID == "" {
		return
	}
	exp := time.Now().Add(h.svc.cfg.RefreshTokenTTL)
	for _, ck := range []struct{ name, val string }{
		{"saml_nameid", nameID},
		{"saml_sessidx", sessionIndex},
	} {
		//nolint:gosec // SAML SLO cookie: SameSite=Lax is required so it survives the IdP-initiated top-level logout navigation; HttpOnly set, Secure deployment-controlled.
		http.SetCookie(w, &http.Cookie{
			Name: ck.name, Value: ck.val, Path: "/api/v1/auth", Domain: h.svc.cfg.CookieDomain,
			HttpOnly: true, Secure: h.svc.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, Expires: exp,
		})
	}
}

func (h *Handler) clearSAMLLogoutCookies(w http.ResponseWriter) {
	for _, name := range []string{"saml_nameid", "saml_sessidx"} {
		//nolint:gosec // deletion cookie (MaxAge<0) for the SAML SLO cookies; carries matching HttpOnly/SameSite, Secure deployment-controlled.
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/api/v1/auth", Domain: h.svc.cfg.CookieDomain, MaxAge: -1,
			HttpOnly: true, Secure: h.svc.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
		})
	}
}

// revokeLocalSession best-effort terminates the current Fleet session named by the
// fleet_sid cookie. Shared by both SLO endpoints: local logout is guaranteed even
// when the IdP round-trip cannot be completed. Returns the session id string (for
// audit) if one was present.
func (h *Handler) revokeLocalSession(ctx context.Context, r *http.Request) {
	if sc, err := r.Cookie("fleet_sid"); err == nil {
		if sid, perr := uuid.Parse(sc.Value); perr == nil {
			_ = h.svc.Logout(ctx, sid)
		}
	}
}

// samlLogout is SP-initiated Single Logout (public browser GET, no Fleet principal
// in context). It ALWAYS revokes the local Fleet session first; then, when SLO is
// fully configured (enabled, an IdP SLO endpoint, an SP signing key, and a
// remembered subject NameID), it builds a signed LogoutRequest and redirects the
// browser to the IdP's SLO endpoint. Otherwise it falls back to a plain local
// logout — mirroring how oidcLogout degrades when no end_session_endpoint exists.
func (h *Handler) samlLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := h.samlConfig(ctx)

	h.revokeLocalSession(ctx, r)

	var nameID, sessionIndex string
	if ck, err := r.Cookie("saml_nameid"); err == nil {
		nameID = ck.Value
	}
	if ck, err := r.Cookie("saml_sessidx"); err == nil {
		sessionIndex = ck.Value
	}
	h.clearAuthCookies(w)
	h.clearSAMLLogoutCookies(w)

	// Attempt IdP SLO only when everything needed for a signed LogoutRequest is
	// present. Any failure past this point degrades to local-only logout.
	if c.enabled() && c.IdPSLOURL != "" && nameID != "" {
		if sp, err := h.samlSP(c); err == nil && samlSPCanSign(sp) {
			if doc, derr := sp.BuildLogoutRequestDocument(nameID, sessionIndex); derr == nil {
				if u, uerr := sp.BuildLogoutURLRedirect(samlRelay("/login"), doc); uerr == nil {
					http.Redirect(w, r, u, http.StatusFound)
					return
				}
			}
		}
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// samlSLO is the SP Single Logout service endpoint — the SLO counterpart of the
// ACS. It handles two IdP messages over the HTTP-Redirect/POST bindings:
//
//   - a LogoutResponse (the IdP's reply to our SP-initiated LogoutRequest): the
//     local session was already ended in samlLogout, so it just lands on /login;
//   - an IdP-initiated LogoutRequest: it terminates the local Fleet session and,
//     when an SP signing key is configured, replies with a signed LogoutResponse
//     redirected back to the IdP.
//
// Local logout is guaranteed regardless of the IdP message's validity. NOTE: the
// session cookies are SameSite=Strict, so a front-channel IdP-initiated request
// arriving cross-site may not carry fleet_sid; SP-initiated logout (the common
// path) revokes the session before leaving our origin, so this only affects pure
// IdP-initiated SLO — a documented limitation of front-channel SLO under Strict.
func (h *Handler) samlSLO(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := h.samlConfig(ctx)

	h.revokeLocalSession(ctx, r)
	h.clearAuthCookies(w)
	h.clearSAMLLogoutCookies(w)

	_ = r.ParseForm()
	// IdP-initiated logout: validate the signed LogoutRequest and answer with a
	// signed LogoutResponse when we can. Never fail the user's logout on an IdP
	// message problem — the local session is already gone.
	if req := r.FormValue("SAMLRequest"); req != "" {
		if sp, err := h.samlSP(c); err == nil && samlSPCanSign(sp) {
			if lr, verr := sp.ValidateEncodedLogoutRequestPOST(req); verr == nil {
				if doc, berr := sp.BuildLogoutResponseDocument(samlLogoutStatusSuccess, lr.ID); berr == nil {
					if u, uerr := sp.BuildLogoutURLRedirect(samlRelay(r.FormValue("RelayState")), doc); uerr == nil {
						http.Redirect(w, r, u, http.StatusFound)
						return
					}
				}
			}
		}
	}
	// A LogoutResponse to our own request (or anything unverifiable): local logout is
	// already complete, so just return to the login page.
	http.Redirect(w, r, "/login", http.StatusFound)
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

// samlConfigGet returns the admin config. The IdP certificate and SP certificate
// are public; the SP signing private key is a secret and is never echoed — only a
// boolean spKeySet flag reports whether one is stored.
func (h *Handler) samlConfigGet(w http.ResponseWriter, r *http.Request) {
	c := h.samlConfig(r.Context())
	spKeySet := c.SPPrivateKeyEnc != ""
	c.SPPrivateKey, c.SPPrivateKeyEnc = "", ""
	writeJSON(w, http.StatusOK, map[string]any{
		"config":      c,
		"spKeySet":    spKeySet,
		"acsUrl":      h.samlACSURL(),
		"sloUrl":      h.samlSLOURL(),
		"spEntityId":  h.spEntityID(c),
		"metadataUrl": strings.TrimRight(h.svc.cfg.PublicURL, "/") + "/api/v1/auth/saml/metadata",
	})
}

// samlConfigPut saves the config after validating the IdP certificate parses. A
// newly-supplied SP signing key is validated against the SP certificate and sealed
// before storage; when omitted, the previously-stored sealed key is preserved.
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
	cur := h.samlConfig(r.Context())
	if c.SPPrivateKey != "" {
		// Validate the key parses together with the SP certificate before sealing.
		if _, err := parseSPKeyPair(c.SPPrivateKey, c.SPCertificate); err != nil {
			writeError(w, http.StatusBadRequest, "SP signing key/certificate invalid: "+err.Error())
			return
		}
		enc, err := secretbox.Seal(h.svc.cfg.CAKeyPassphrase, []byte(c.SPPrivateKey))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not seal SP key")
			return
		}
		c.SPPrivateKeyEnc = enc
	} else {
		c.SPPrivateKeyEnc = cur.SPPrivateKeyEnc
	}
	c.SPPrivateKey = "" // never persist the plaintext
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
// external account from a validated, IdP-signed assertion, and authoritatively
// reconciles group→role mappings. Because the assertion is signed by the trusted IdP, its
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
	if err == nil && idpAccountConflict(user, "saml") {
		return nil, errors.New("account_conflict")
	}
	if err != nil && email != "" {
		user, err = h.svc.store.GetUserByEmail(ctx, email)
		if err == nil && idpAccountConflict(user, "saml") {
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
	// Group → role mapping, authoritative for IdP-managed roles: assign the roles
	// the assertion's current groups grant and revoke the IdP-managed roles they no
	// longer grant, leaving locally-assigned roles intact (see reconcileGroupRoles).
	h.svc.reconcileGroupRoles(ctx, user.ID, c.GroupRoleMap, samlAttrValues(info.Values, c.GroupsAttr))
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
