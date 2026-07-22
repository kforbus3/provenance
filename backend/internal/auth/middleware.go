package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/tenant"
)

// RequireAuth validates the bearer access token and attaches the Principal.
// Requests without a valid session receive 401.
func (s *Service) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Federation: a request dispatched by the site-ingress carries a principal
		// synthesized from a verified hub-signed assertion (no bearer token). Honor
		// it in place of token auth so the request flows through the normal routes
		// and RequirePermission checks. Only the federation layer can set this key.
		if fp := federatedPrincipal(r.Context()); fp != nil {
			next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), fp)))
			return
		}
		tok := bearerToken(r)
		if tok == "" {
			unauthorized(w, "missing access token")
			return
		}
		// Authenticating is a cross-tenant lookup (we don't yet know the caller's
		// tenant), so resolve the principal with RLS bypassed. The request is then
		// re-scoped to the caller's tenant below, before any handler runs.
		authCtx := tenant.WithBypass(r.Context())
		var p *Principal
		if strings.HasPrefix(tok, APITokenPrefix) {
			// Service-account API token (for automation/CI): authenticate against
			// the api_tokens table rather than parsing a JWT session.
			var err error
			p, err = s.authenticateAPIToken(authCtx, tok)
			if err != nil {
				unauthorized(w, "invalid api token")
				return
			}
		} else {
			claims, err := ParseAccessToken(s.cfg.JWTSecret, tok)
			if err != nil {
				unauthorized(w, "invalid access token")
				return
			}
			p, err = s.loadPrincipal(authCtx, claims)
			if err != nil {
				unauthorized(w, "session invalid")
				return
			}
		}
		// An account flagged to change its password may only reach the auth
		// endpoints (change-password, logout, profile, MFA) until it does so —
		// server-side enforcement so the flag can't be bypassed by ignoring the UI.
		if p.MustChangePw && !strings.Contains(r.URL.Path, "/api/v1/auth/") {
			forbidden(w, "password change required")
			return
		}
		// Scope the request to the caller's tenant so row-level security filters every
		// query. A provider admin may act within a customer tenant by selecting it via
		// the X-Fleet-Tenant header (audited by the tenant API).
		effective := p.TenantID
		if effective == uuid.Nil {
			effective = ProviderTenantID
		}
		if sel := r.Header.Get("X-Fleet-Tenant"); sel != "" && p.IsProviderAdmin() {
			if tid, err := uuid.Parse(sel); err == nil {
				effective = tid
			}
		}
		ctx := tenant.WithID(withPrincipal(r.Context(), p), effective.String())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission ensures the principal holds a permission. The backend is the
// sole authority for authorization — frontend checks are advisory only.
func (s *Service) RequirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := MustPrincipal(r)
			if p == nil {
				unauthorized(w, "authentication required")
				return
			}
			if !p.Has(perm) {
				forbidden(w, "missing permission: "+perm)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CSRF note: there is intentionally no CSRF-enforcing middleware. State-changing
// API calls authenticate with a Bearer access token in the Authorization header,
// which a cross-site attacker cannot forge (the browser never attaches it
// automatically); the only cookie-authenticated endpoints (refresh/logout) use a
// SameSite=Strict cookie, so the browser won't send it on a cross-site request.
// A readable double-submit token is still issued (fleet_csrf cookie + login
// response) so explicit double-submit enforcement can be layered on later without
// re-plumbing, but it is not required by the current design.

// WSToken extracts the access token from a WebSocket upgrade request. Browsers
// cannot set an Authorization header on a WebSocket, so the token is carried in the
// Sec-WebSocket-Protocol subprotocol ("fleet-bearer, <token>") — which, unlike a
// ?token= query parameter, never appears in the request URL or in reverse-proxy
// access logs. It falls back to the legacy ?token= query param for older clients
// and non-browser callers. respHeader is what to pass to Upgrade: when the token
// came from the subprotocol it echoes the "fleet-bearer" marker (required, or the
// browser handshake fails); it is nil when the token came from the query param.
func (s *Service) WSToken(r *http.Request) (token string, respHeader http.Header) {
	const marker = "fleet-bearer"
	var protos []string
	for _, h := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(h, ",") {
			if p = strings.TrimSpace(p); p != "" {
				protos = append(protos, p)
			}
		}
	}
	for i, p := range protos {
		if p == marker && i+1 < len(protos) {
			// Build via Set so the key is canonicalized: gorilla's Upgrade echoes the
			// response subprotocol by calling responseHeader.Get, which canonicalizes
			// the lookup key — a raw non-canonical map key would be missed and the
			// server would fail to echo the subprotocol.
			resp := http.Header{}
			resp.Set("Sec-WebSocket-Protocol", marker)
			return protos[i+1], resp
		}
	}
	return r.URL.Query().Get("token"), nil
}

// AuthenticateToken validates a raw access token and returns its Principal. Used
// by the WebSocket endpoints, where browsers cannot set an Authorization header;
// the token arrives via the Sec-WebSocket-Protocol subprotocol (see WSToken) or,
// for older/non-browser clients, a query parameter.
func (s *Service) AuthenticateToken(ctx context.Context, tokenStr string) (*Principal, error) {
	claims, err := ParseAccessToken(s.cfg.JWTSecret, tokenStr)
	if err != nil {
		return nil, err
	}
	// Cross-tenant lookup (see RequireAuth); callers scope their work to p.TenantID.
	return s.loadPrincipal(tenant.WithBypass(ctx), claims)
}

// TenantScope returns ctx scoped to the principal's tenant so row-level security
// filters every subsequent query. Token-authenticated endpoints (the WebSocket
// terminal/events/watch, streaming downloads, enrollment agent) resolve the principal
// under bypass via AuthenticateToken and DON'T pass through RequireAuth, so — under
// multi-tenancy — they MUST call this before ANY tenant-scoped DB access or RLS denies
// the row (e.g. a host lookup returns "not found"). It applies to any context,
// including a detached context.Background() used for work that must outlive the
// request (session-end audit, recording writes) — those need the tenant too. No-op
// when multi-tenancy is off (the pool's BeforeAcquire hook bypasses RLS regardless).
// WebSocket clients can't send the X-Fleet-Tenant switch header, so this scopes to the
// principal's home tenant; a provider admin reaches only their own tenant over a socket.
func (s *Service) TenantScope(ctx context.Context, p *Principal) context.Context {
	return s.TenantScopeID(ctx, p.TenantID)
}

// TenantScopeID is TenantScope by tenant id, for detached contexts (e.g. an RDP
// disconnect callback) that no longer hold the *Principal but stashed its tenant.
func (s *Service) TenantScopeID(ctx context.Context, tenantID uuid.UUID) context.Context {
	if tenantID == uuid.Nil {
		tenantID = ProviderTenantID
	}
	return tenant.WithID(ctx, tenantID.String())
}

// TenantBypass runs the wrapped handlers with row-level security bypassed — for
// pre-authentication endpoints (login, SSO callbacks, bootstrap) that must look up or
// create accounts before the caller's tenant is known. New accounts created under it
// default to the provider tenant. No effect when multi-tenancy is off.
func TenantBypass(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(tenant.WithBypass(r.Context())))
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

func unauthorized(w http.ResponseWriter, msg string) {
	writeError(w, http.StatusUnauthorized, msg)
}

func forbidden(w http.ResponseWriter, msg string) {
	writeError(w, http.StatusForbidden, msg)
}
