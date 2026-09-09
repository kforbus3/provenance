package auth

import (
	"context"

	"github.com/google/uuid"
)

// HostAccessStore is the one store method this check needs. A narrow interface
// rather than the store itself, so auth does not depend on the store package —
// which would be a cycle, since the store's callers all depend on auth.
type HostAccessStore interface {
	UserCanAccessHost(ctx context.Context, userID, hostID uuid.UUID) (bool, error)
}

// CanAccessHost reports whether a principal may act on a host.
//
// This existed five times, byte-identical, under three different names:
// canAccessHost in playbook, winscript and command; canSee in imaging; canAccess
// in scan. Every copy is authorization — the gate deciding whether a
// host-group-scoped operator may run a playbook against a machine, image it, or
// scan it — and authorization duplicated five ways is a fix applied four times
// and forgotten once.
//
// The error is deliberately swallowed into "no". A store failure here must deny
// rather than allow: this is the only thing standing between a scoped operator
// and a host outside their groups, and an access check that fails open is worse
// than one that fails loudly.
func CanAccessHost(ctx context.Context, store HostAccessStore, p *Principal, hostID uuid.UUID) bool {
	if p == nil {
		return false
	}
	if p.IsSuperAdmin {
		return true
	}
	ok, err := store.UserCanAccessHost(ctx, p.UserID, hostID)
	return err == nil && ok
}
