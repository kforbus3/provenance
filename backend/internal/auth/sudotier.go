package auth

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

// SudoGrantStore is the narrow slice of the store this needs: one question,
// asked on the connection path.
type SudoGrantStore interface {
	HasSudoGrant(ctx context.Context, userID, hostID uuid.UUID) (bool, error)
}

// MaySudo reports whether a connection should land in the host's privileged
// account: the standing permission, or an approved time-boxed grant for this
// host.
//
// The grant half is what makes Host.Sudo usable as a restriction. Without it the
// only route to root for a login-only user is an administrator adding Host.Sudo
// to their role -- fleet-wide, indefinite, and with nothing to take it back --
// so in practice operators either hold it permanently, which defeats the tier,
// or are granted it once and never lose it.
//
// Asked per connection, never cached on the session: an expiry that only applied
// to connections opened after it would not be an expiry, and a terminal opened a
// minute before a grant lapsed would hold root for as long as it stayed open.
//
// A store that cannot answer denies. Failing open here would turn a database
// blip into fleet-wide root, and the standing permission is checked first, so an
// operator who is meant to have sudo is unaffected either way.
func MaySudo(ctx context.Context, st SudoGrantStore, log *slog.Logger, p *Principal, hostID uuid.UUID) bool {
	if p == nil {
		return false
	}
	if p.IsSuperAdmin || p.Has("Host.Sudo") {
		return true
	}
	if st == nil || hostID == uuid.Nil {
		return false
	}
	ok, err := st.HasSudoGrant(ctx, p.UserID, hostID)
	if err != nil {
		if log != nil {
			log.Warn("sudo grant lookup failed; denying root for this connection",
				"user", p.Username, "host", hostID, "err", err)
		}
		return false
	}
	return ok
}
