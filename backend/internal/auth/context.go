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
	// TenantID is the account's home tenant (multi-tenancy). All of the account's
	// requests are scoped to it, except a provider admin who has switched into a
	// customer tenant's context (see RequireAuth). Zero value = the provider tenant.
	TenantID uuid.UUID
}

// ProviderTenantID is the fixed id of the seeded provider (default) tenant — the MSP
// itself, and the tenant all data belongs to in single-tenant mode. Kept in sync with
// migration 0051.
var ProviderTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// IsProviderAdmin reports whether the principal may operate across tenants: a member of
// the provider tenant who holds Tenant.Manage (or is a super admin).
func (p *Principal) IsProviderAdmin() bool {
	if p == nil {
		return false
	}
	return p.TenantID == ProviderTenantID && (p.IsSuperAdmin || p.Has("Tenant.Manage"))
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
