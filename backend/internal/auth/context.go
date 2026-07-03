package auth

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type ctxKey int

const principalKey ctxKey = iota

// Principal is the authenticated identity attached to a request context.
type Principal struct {
	UserID       uuid.UUID
	SessionID    uuid.UUID
	Username     string
	IsSuperAdmin bool
	Permissions  map[string]bool
	// MustChangePw is set when the account is flagged to change its password
	// before it may use the rest of the API (enforced in RequireAuth).
	MustChangePw bool
}

// Has reports whether the principal holds a permission. Super admins and holders
// of the Admin.All wildcard implicitly hold every permission.
func (p *Principal) Has(perm string) bool {
	if p == nil {
		return false
	}
	if p.IsSuperAdmin || p.Permissions["Admin.All"] {
		return true
	}
	return p.Permissions[perm]
}

// withPrincipal returns a context carrying the principal.
func withPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// FromContext returns the request principal, if any.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey).(*Principal)
	return p, ok
}

// MustPrincipal returns the principal or nil.
func MustPrincipal(r *http.Request) *Principal {
	p, _ := FromContext(r.Context())
	return p
}

// Cookie names used by the auth layer.
const (
	RefreshCookie = "fleet_refresh"
	CSRFCookie    = "fleet_csrf"
)
