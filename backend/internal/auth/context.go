package auth

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type ctxKey int

const (
	principalKey ctxKey = iota
	fedPrincipalKey
)

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

// WithFederatedPrincipal attaches a hub-authorized principal to a context under a
// dedicated key. The federation site-ingress synthesizes this principal from a
// verified, hub-signed acting-user assertion, then dispatches the request through
// the site's own router; RequireAuth honors it in place of a bearer token (see
// RequireAuth). A dedicated key ensures a normal request can never carry one, so
// this can only ever be set by the federation layer over an authenticated link.
func WithFederatedPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, fedPrincipalKey, p)
}

// federatedPrincipal returns a federation-injected principal, if present.
func federatedPrincipal(ctx context.Context) *Principal {
	p, _ := ctx.Value(fedPrincipalKey).(*Principal)
	return p
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
