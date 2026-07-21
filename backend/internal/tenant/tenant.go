// Package tenant carries the per-request tenant scope used by Postgres row-level
// security. The effective scope is put on the request context and read by the pgxpool
// BeforeAcquire hook, which sets the `app.tenant_id` GUC on the connection so every
// query is filtered by the RLS policies — with no per-query changes.
//
// Semantics (only relevant when FLEET_MULTI_TENANCY is on; with the flag off the pool
// always sets Bypass so behavior is unchanged):
//   - WithID   → scope to one tenant (a normal authenticated request).
//   - WithBypass → cross-tenant (background sweeps, migrations, the provider console
//     listing all tenants). RLS is satisfied for every row.
//   - unmarked → "" → RLS matches NOTHING (deny). This makes a request that forgot to
//     set a tenant fail closed rather than leak, so tenant scoping is opt-out-safe.
package tenant

import "context"

// GUC is the Postgres session setting the RLS policies read.
const GUC = "app.tenant_id"

// Bypass is the sentinel that satisfies every RLS policy (cross-tenant access).
const Bypass = "bypass"

type ctxKey struct{}

// WithID scopes ctx to a single tenant (its UUID string).
func WithID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// WithBypass marks ctx as cross-tenant — for background/internal work that legitimately
// spans tenants (the monitor sweep, schedulers, migrations, the provider console).
func WithBypass(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, Bypass)
}

// GUCValue returns the value to set for app.tenant_id for ctx: a tenant UUID, Bypass,
// or "" (deny) when nothing was set.
func GUCValue(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKey{}).(string); ok {
		return v
	}
	return ""
}
