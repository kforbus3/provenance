package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

// waUser adapts a Fleet user + its stored passkeys to the webauthn.User interface.
type waUser struct {
	id          uuid.UUID
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { b, _ := u.id.MarshalBinary(); return b }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *waUser) WebAuthnIcon() string                       { return "" }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// waSession bundles WebAuthn ceremony state with the target user.
type waSession struct {
	data    *webauthn.SessionData
	userID  uuid.UUID
	expires time.Time
}

type waStore struct {
	mu       sync.Mutex
	sessions map[string]waSession
}

func (s *waStore) put(userID uuid.UUID, data *webauthn.SessionData) string {
	key := randKey()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = map[string]waSession{}
	}
	// Opportunistic cleanup of expired ceremonies.
	for k, v := range s.sessions {
		if time.Now().After(v.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[key] = waSession{data: data, userID: userID, expires: time.Now().Add(5 * time.Minute)}
	return key
}

func (s *waStore) take(key string) (waSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sessions[key]
	if ok {
		delete(s.sessions, key)
	}
	if ok && time.Now().After(v.expires) {
		return waSession{}, false
	}
	return v, ok
}

func randKey() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// webAuthn lazily builds the relying-party instance from config.
func (s *Service) webAuthn() (*webauthn.WebAuthn, error) {
	s.waOnce.Do(func() {
		s.wa, s.waErr = webauthn.New(&webauthn.Config{
			RPID:          s.cfg.WebAuthnRPID,
			RPDisplayName: s.cfg.WebAuthnRPName,
			RPOrigins:     s.cfg.WebAuthnOrigins,
		})
	})
	return s.wa, s.waErr
}

// loadWAUser builds a waUser, returning the per-credential store IDs so sign
// counts can be persisted after a successful assertion.
func (s *Service) loadWAUser(r *http.Request, userID uuid.UUID) (*waUser, map[string]uuid.UUID, error) {
	u, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		return nil, nil, err
	}
	stored, err := s.store.WebAuthnCredentials(r.Context(), userID)
	if err != nil {
		return nil, nil, err
	}
	wu := &waUser{id: u.ID, name: u.Username, displayName: u.DisplayName}
	if wu.displayName == "" {
		wu.displayName = u.Username
	}
	idToRow := map[string]uuid.UUID{}
	for _, sc := range stored {
		var c webauthn.Credential
		if json.Unmarshal(sc.JSON, &c) != nil {
			continue
		}
		wu.creds = append(wu.creds, c)
		idToRow[base64.RawStdEncoding.EncodeToString(c.ID)] = sc.ID
	}
	return wu, idToRow, nil
}

// --- registration (authenticated) ---

func (h *Handler) webauthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	p := MustPrincipal(r)
	wa, err := h.svc.webAuthn()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webauthn not configured")
		return
	}
	wu, _, err := h.svc.loadWAUser(r, p.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load user")
		return
	}
	// FIPS: restrict the credential algorithms the authenticator may use to
	// ES256 (P-256) and RS256 — excluding EdDSA (Ed25519), which is not in the
	// FIPS-approved WebAuthn set. Default profile advertises the library's full set.
	var regOpts []webauthn.RegistrationOption
	if h.svc.cfg.FIPSMode {
		regOpts = append(regOpts, webauthn.WithCredentialParameters([]protocol.CredentialParameter{
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
		}))
	}
	options, sessionData, err := wa.BeginRegistration(wu, regOpts...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	key := h.svc.waStore.put(p.UserID, sessionData)
	writeJSON(w, http.StatusOK, map[string]any{"sessionKey": key, "options": options})
}

func (h *Handler) webauthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	p := MustPrincipal(r)
	wa, err := h.svc.webAuthn()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webauthn not configured")
		return
	}
	sess, ok := h.svc.waStore.take(r.URL.Query().Get("s"))
	if !ok || sess.userID != p.UserID {
		writeError(w, http.StatusBadRequest, "registration session expired")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid attestation")
		return
	}
	wu, _, err := h.svc.loadWAUser(r, p.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load user")
		return
	}
	cred, err := wa.CreateCredential(wu, *sess.data, parsed)
	if err != nil {
		writeError(w, http.StatusBadRequest, "registration failed: "+err.Error())
		return
	}
	blob, _ := json.Marshal(cred)
	if _, err := h.svc.store.AddWebAuthnCredential(r.Context(), p.UserID, "Passkey", blob); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store passkey")
		return
	}
	_, _ = h.svc.store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: "auth.mfa_enroll",
		TargetKind: "user", TargetID: p.UserID.String(), Detail: map[string]any{"kind": "webauthn"},
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
}

// --- login assertion (after the password step's MFA challenge) ---

func (h *Handler) webauthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Challenge string `json:"challenge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	userID, err := h.svc.ParseMFAChallenge(req.Challenge)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "challenge expired; sign in again")
		return
	}
	wa, err := h.svc.webAuthn()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webauthn not configured")
		return
	}
	wu, _, err := h.svc.loadWAUser(r, userID)
	if err != nil || len(wu.creds) == 0 {
		writeError(w, http.StatusBadRequest, "no passkeys registered")
		return
	}
	options, sessionData, err := wa.BeginLogin(wu)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	key := h.svc.waStore.put(userID, sessionData)
	writeJSON(w, http.StatusOK, map[string]any{"sessionKey": key, "options": options})
}

func (h *Handler) webauthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	wa, err := h.svc.webAuthn()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webauthn not configured")
		return
	}
	sess, ok := h.svc.waStore.take(r.URL.Query().Get("s"))
	if !ok {
		writeError(w, http.StatusBadRequest, "login session expired")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid assertion")
		return
	}
	wu, idToRow, err := h.svc.loadWAUser(r, sess.userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load user")
		return
	}
	cred, err := wa.ValidateLogin(wu, *sess.data, parsed)
	if err != nil {
		ip, ua := clientMeta(r)
		_ = h.svc.store.RecordAuthEvent(r.Context(), models.AuthEvent{
			UserID: &sess.userID, Event: "mfa_failure", IP: ip, UserAgent: ua,
			Detail: map[string]any{"kind": "webauthn"},
		})
		writeError(w, http.StatusUnauthorized, "passkey verification failed")
		return
	}
	// go-webauthn flags a sign-count regression rather than failing the ceremony;
	// treat it as a possible cloned authenticator and refuse.
	if cred.Authenticator.CloneWarning {
		ip, ua := clientMeta(r)
		_ = h.svc.store.RecordAuthEvent(r.Context(), models.AuthEvent{
			UserID: &sess.userID, Event: "mfa_failure", IP: ip, UserAgent: ua,
			Detail: map[string]any{"kind": "webauthn", "reason": "clone_warning"},
		})
		writeError(w, http.StatusUnauthorized, "passkey verification failed (authenticator may be cloned)")
		return
	}
	// Persist the updated sign count to detect cloned authenticators.
	if rowID, ok := idToRow[base64.RawStdEncoding.EncodeToString(cred.ID)]; ok {
		blob, _ := json.Marshal(cred)
		_ = h.svc.store.UpdateWebAuthnCredential(r.Context(), rowID, blob)
	}
	u, err := h.svc.store.GetUserByID(r.Context(), sess.userID)
	if err != nil || u.IsDisabled {
		writeError(w, http.StatusUnauthorized, "account unavailable")
		return
	}
	ip, ua := clientMeta(r)
	h.completeLogin(w, r, u, ip, ua)
}

// mountWebAuthn registers passkey routes (called from Mount).
func (h *Handler) mountWebAuthn(r chi.Router) {
	r.Post("/auth/mfa/webauthn/login/begin", h.webauthnLoginBegin)
	r.Post("/auth/mfa/webauthn/login/finish", h.webauthnLoginFinish)
	r.Group(func(pr chi.Router) {
		pr.Use(h.svc.RequireAuth)
		pr.Post("/auth/mfa/webauthn/register/begin", h.webauthnRegisterBegin)
		pr.Post("/auth/mfa/webauthn/register/finish", h.webauthnRegisterFinish)
	})
}
