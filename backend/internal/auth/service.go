package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// Common authentication errors surfaced to handlers.
var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountDisabled    = errors.New("account is disabled")
	ErrAccountLocked      = errors.New("account is locked")
	ErrSessionInvalid     = errors.New("session invalid or expired")
)

// SessionHook is invoked after a session is created (login) or destroyed
// (logout), letting the SSH identity layer mint/zeroize ephemeral credentials
// without auth importing that layer (avoids an import cycle).
type SessionHook func(ctx context.Context, userID, sessionID uuid.UUID, username string)

// Service holds auth dependencies and orchestrates login/session lifecycle.
type Service struct {
	store *store.Store
	cfg   *config.Config
	log   *slog.Logger

	onSessionCreated   SessionHook
	onSessionDestroyed SessionHook
	ensureCredential   SessionHook

	// WebAuthn relying-party instance (lazily initialized) + ceremony sessions.
	waOnce  sync.Once
	wa      *webauthn.WebAuthn
	waErr   error
	waStore waStore
}

// SetSessionHooks registers identity lifecycle callbacks.
func (s *Service) SetSessionHooks(created, destroyed SessionHook) {
	s.onSessionCreated = created
	s.onSessionDestroyed = destroyed
}

// SetEnsureCredential registers a callback invoked on each authenticated request
// to guarantee the session has a live ephemeral SSH credential, re-issuing one
// if it is missing (e.g. after a backend restart wiped the in-RAM vault).
func (s *Service) SetEnsureCredential(fn SessionHook) { s.ensureCredential = fn }

// NewService constructs the auth Service.
func NewService(st *store.Store, cfg *config.Config, log *slog.Logger) *Service {
	return &Service{store: st, cfg: cfg, log: log}
}

// Tokens bundles freshly issued credentials returned to the transport layer.
type Tokens struct {
	Access       string
	Refresh      string
	CSRF         string
	RefreshHash  string
	AccessExpiry time.Time
	Session      *models.Session
}

// Authenticate verifies credentials and returns the user on success, applying
// lockout policy. It does not create a session (the handler does, after MFA).
// dummyVerify runs an argon2id verify against a fixed dummy hash so that failed
// logins take the same time whether or not the account exists (anti-enumeration).
func dummyVerify(password string) {
	_, _ = VerifyPassword(password, "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
}

func (s *Service) Authenticate(ctx context.Context, username, password string) (*models.User, error) {
	u, err := s.store.GetUserByUsername(ctx, username)
	if err != nil {
		dummyVerify(password)
		return nil, ErrInvalidCredentials
	}
	// Run the dummy verify on every pre-password early return so response time
	// doesn't reveal whether an account exists or its state. Unknown, disabled, and
	// external (SSO) accounts all return the same generic error to prevent user
	// enumeration; a locked account keeps its distinct message (the state is
	// self-inflicted and operationally useful to surface).
	if u.IsDisabled {
		dummyVerify(password)
		return nil, ErrInvalidCredentials
	}
	if u.AuthSource != "" && u.AuthSource != "local" {
		dummyVerify(password)
		return nil, ErrInvalidCredentials
	}
	if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
		dummyVerify(password)
		return nil, ErrAccountLocked
	}
	hash, err := s.store.GetPasswordHash(ctx, u.ID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	ok, err := VerifyPassword(password, hash)
	if err != nil || !ok {
		s.applyFailure(ctx, u.ID)
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

func (s *Service) applyFailure(ctx context.Context, userID uuid.UUID) {
	max, lockMin := s.lockoutPolicy(ctx)
	if _, err := s.store.RecordLoginFailure(ctx, userID, max, time.Duration(lockMin)*time.Minute); err != nil {
		s.log.Warn("record login failure", "err", err)
	}
}

// PasswordPolicy returns the active password policy from the settings store,
// falling back to DefaultPolicy when unset. Read fresh on every call so changes
// in Settings take effect immediately (no restart).
func (s *Service) PasswordPolicy(ctx context.Context) PasswordPolicy {
	p := DefaultPolicy
	var raw json.RawMessage
	if err := s.store.Pool().QueryRow(ctx,
		`SELECT value FROM settings WHERE key='password_policy'`).Scan(&raw); err == nil {
		_ = json.Unmarshal(raw, &p) // overlays only the fields present in the setting
	}
	return p
}

func (s *Service) lockoutPolicy(ctx context.Context) (maxFailed, lockoutMinutes int) {
	maxFailed, lockoutMinutes = 5, 15
	var raw json.RawMessage
	if err := s.store.Pool().QueryRow(ctx,
		`SELECT value FROM settings WHERE key='lockout_policy'`).Scan(&raw); err == nil {
		var p struct {
			Max  int `json:"max_failed"`
			Lock int `json:"lockout_minutes"`
		}
		if json.Unmarshal(raw, &p) == nil {
			if p.Max > 0 {
				maxFailed = p.Max
			}
			if p.Lock > 0 {
				lockoutMinutes = p.Lock
			}
		}
	}
	return
}

// CreateSession issues a session plus access/refresh/CSRF tokens for a user.
func (s *Service) CreateSession(ctx context.Context, u *models.User, ip, ua string, mfaPassed bool) (*Tokens, error) {
	refresh, refreshHash, err := NewRefreshToken()
	if err != nil {
		return nil, err
	}
	expires := time.Now().Add(s.cfg.RefreshTokenTTL)
	sess, err := s.store.CreateSession(ctx, u.ID, refreshHash, ip, ua, mfaPassed, expires)
	if err != nil {
		return nil, err
	}
	access, err := IssueAccessToken(s.cfg.JWTSecret, u.ID, sess.ID, u.Username, s.cfg.AccessTokenTTL)
	if err != nil {
		return nil, err
	}
	csrf, err := NewCSRFToken()
	if err != nil {
		return nil, err
	}
	if err := s.store.RecordLoginSuccess(ctx, u.ID); err != nil {
		s.log.Warn("record login success", "err", err)
	}
	if s.onSessionCreated != nil {
		s.onSessionCreated(ctx, u.ID, sess.ID, u.Username)
	}
	return &Tokens{
		Access: access, Refresh: refresh, CSRF: csrf, RefreshHash: refreshHash,
		AccessExpiry: time.Now().Add(s.cfg.AccessTokenTTL), Session: sess,
	}, nil
}

// Refresh rotates a refresh token and issues a new access token. The old refresh
// token is invalidated (rotation) to detect token theft/replay.
func (s *Service) Refresh(ctx context.Context, sessionID uuid.UUID, presentedRefresh string) (*Tokens, error) {
	sess, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		return nil, ErrSessionInvalid
	}
	if sess.RevokedAt != nil || sess.ExpiresAt.Before(time.Now()) {
		return nil, ErrSessionInvalid
	}
	storedHash, err := s.store.GetSessionRefreshHash(ctx, sessionID)
	if err != nil || storedHash != HashToken(presentedRefresh) {
		// Possible replay of a rotated token: revoke the session defensively.
		_ = s.store.RevokeSession(ctx, sessionID)
		return nil, ErrSessionInvalid
	}
	u, err := s.store.GetUserByID(ctx, sess.UserID)
	if err != nil || u.IsDisabled {
		return nil, ErrSessionInvalid
	}
	newRefresh, newHash, err := NewRefreshToken()
	if err != nil {
		return nil, err
	}
	expires := time.Now().Add(s.cfg.RefreshTokenTTL)
	if err := s.store.RotateRefresh(ctx, sessionID, newHash, expires); err != nil {
		return nil, err
	}
	access, err := IssueAccessToken(s.cfg.JWTSecret, u.ID, sessionID, u.Username, s.cfg.AccessTokenTTL)
	if err != nil {
		return nil, err
	}
	csrf, _ := NewCSRFToken()
	return &Tokens{
		Access: access, Refresh: newRefresh, CSRF: csrf, RefreshHash: newHash,
		AccessExpiry: time.Now().Add(s.cfg.AccessTokenTTL), Session: sess,
	}, nil
}

// Logout revokes a session and triggers ephemeral credential destruction.
func (s *Service) Logout(ctx context.Context, sessionID uuid.UUID) error {
	return s.endSession(ctx, sessionID)
}

// endSession revokes a session AND destroys its in-RAM private key and revokes
// its certificates (KRL). Used by logout, idle/absolute timeout, and account
// disable/delete so credentials never outlive the session.
func (s *Service) endSession(ctx context.Context, sessionID uuid.UUID) error {
	if s.onSessionDestroyed != nil {
		s.onSessionDestroyed(ctx, uuid.Nil, sessionID, "")
	}
	return s.store.RevokeSession(ctx, sessionID)
}

// DestroyUserSessions ends every active session for a user — zeroizing each
// session's private key and revoking its certificates. Call before disabling or
// deleting an account so the user's credentials are immediately useless.
func (s *Service) DestroyUserSessions(ctx context.Context, userID uuid.UUID) {
	s.destroyUserSessions(ctx, userID, uuid.Nil)
}

// DestroyUserSessionsExcept ends all of a user's sessions except one (typically
// the caller's own), used on a self-service password change so the user stays
// logged in on the current device while every other session is invalidated.
func (s *Service) DestroyUserSessionsExcept(ctx context.Context, userID, keep uuid.UUID) {
	s.destroyUserSessions(ctx, userID, keep)
}

func (s *Service) destroyUserSessions(ctx context.Context, userID, keep uuid.UUID) {
	sessions, err := s.store.ListUserSessions(ctx, userID)
	if err != nil {
		s.log.Warn("destroy user sessions: list", "err", err)
		return
	}
	for _, sess := range sessions {
		if keep != uuid.Nil && sess.ID == keep {
			continue
		}
		_ = s.endSession(ctx, sess.ID)
	}
}

// ReapStaleSessions ends sessions that have gone idle past SessionIdleTTL or
// exceeded SessionAbsoluteTTL, applying the SAME bounds as loadPrincipal. Unlike
// the lazy per-request check, this runs from a background loop so a live but
// idle terminal/SFTP connection — which issues no further HTTP requests — is
// still force-closed (via endSession → onSessionDestroyed → Live.Close) once it
// goes idle. Returns the number of sessions ended.
func (s *Service) ReapStaleSessions(ctx context.Context) int {
	if s.cfg.SessionIdleTTL <= 0 && s.cfg.SessionAbsoluteTTL <= 0 {
		return 0
	}
	stale, err := s.store.ListStaleSessions(ctx, s.cfg.SessionIdleTTL, s.cfg.SessionAbsoluteTTL)
	if err != nil {
		s.log.Warn("reap stale sessions: list", "err", err)
		return 0
	}
	for _, sess := range stale {
		if err := s.endSession(ctx, sess.ID); err != nil {
			s.log.Warn("reap stale sessions: end", "session", sess.ID, "err", err)
		}
	}
	if len(stale) > 0 {
		s.log.Info("reaped stale sessions", "count", len(stale))
	}
	return len(stale)
}

// loadPrincipal builds a Principal from a validated session, resolving permissions.
func (s *Service) loadPrincipal(ctx context.Context, claims *Claims) (*Principal, error) {
	sess, err := s.store.GetSession(ctx, claims.SessionID)
	if err != nil || sess.RevokedAt != nil || sess.ExpiresAt.Before(time.Now()) {
		return nil, ErrSessionInvalid
	}
	// End the session — AND destroy its ephemeral SSH credentials — when it goes
	// idle, or when it exceeds the absolute maximum lifetime (a hard cap that
	// rolling token refresh cannot extend).
	if s.cfg.SessionIdleTTL > 0 && time.Since(sess.LastSeenAt) > s.cfg.SessionIdleTTL {
		s.endSession(ctx, sess.ID)
		return nil, ErrSessionInvalid
	}
	if s.cfg.SessionAbsoluteTTL > 0 && time.Since(sess.CreatedAt) > s.cfg.SessionAbsoluteTTL {
		s.endSession(ctx, sess.ID)
		return nil, ErrSessionInvalid
	}
	u, err := s.store.GetUserByID(ctx, claims.UserID)
	if err != nil || u.IsDisabled {
		// Disabled/removed account: tear down credentials too.
		s.endSession(ctx, sess.ID)
		return nil, ErrSessionInvalid
	}
	perms, err := s.store.UserPermissions(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	_ = s.store.TouchSession(ctx, sess.ID)
	// Guarantee the session has a live ephemeral SSH credential (re-issued if the
	// in-RAM vault was cleared by a restart), so SSH/SFTP keep working.
	if s.ensureCredential != nil {
		s.ensureCredential(ctx, u.ID, sess.ID, u.Username)
	}
	return &Principal{
		UserID: u.ID, SessionID: sess.ID, Username: u.Username,
		IsSuperAdmin: u.IsSuperAdmin, Permissions: perms,
		MustChangePw: u.MustChangePw,
	}, nil
}

// Store exposes the underlying store for handlers that need it.
func (s *Service) Store() *store.Store { return s.store }

// Config exposes config for handlers/middleware.
func (s *Service) Config() *config.Config { return s.cfg }
