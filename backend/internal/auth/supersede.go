package auth

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// RevokeSupersededSession ends the session the caller's browser is replacing.
//
// Logging in always created a session and never looked at the one the browser
// was already holding. So signing in again from the same tab left the previous
// session alive: its cookie had just been overwritten, so no browser could reach
// it, but the server was never told and kept it valid for its full lifetime.
//
// That is how one operator ended up with two "active sign-ins" after a single
// upgrade — and, repeated over enough upgrades, how the list fills with sessions
// nobody is using and no one can tell apart from the real one.
//
// Proof of ownership is required, not just a session id: the browser must present
// the refresh token whose hash the row stores, and the session must belong to the
// user who just authenticated. Without the hash check this would be a way to end
// somebody else's session by naming it — a denial of service dressed as a
// convenience. With it, the only session that can be revoked is the one the
// caller demonstrably already held.
//
// Best-effort and silent: a login must not fail because the previous session
// could not be tidied away.
func (s *Service) RevokeSupersededSession(ctx context.Context, r *http.Request, userID uuid.UUID) {
	rc, err := r.Cookie(RefreshCookie)
	if err != nil || rc.Value == "" {
		return
	}
	sc, err := r.Cookie("fleet_sid")
	if err != nil {
		return
	}
	sid, err := uuid.Parse(sc.Value)
	if err != nil {
		return
	}
	sess, err := s.store.GetSession(ctx, sid)
	if err != nil || sess.RevokedAt != nil || sess.UserID != userID {
		return
	}
	storedHash, err := s.store.GetSessionRefreshHash(ctx, sid)
	if err != nil || storedHash != HashToken(rc.Value) {
		return
	}
	// endSession, not store.RevokeSession: the abandoned session may still hold a
	// live terminal and valid certificates, and leaving those behind is the same
	// mistake in a quieter form.
	if err := s.endSession(ctx, sid); err != nil {
		s.log.Warn("could not end the superseded session", "session", sid, "err", err)
	}
}
