package auth

import (
	"context"
	"net/http"
	"strings"
)

// RequireAuth validates the bearer access token and attaches the Principal.
// Requests without a valid session receive 401.
func (s *Service) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			unauthorized(w, "missing access token")
			return
		}
		claims, err := ParseAccessToken(s.cfg.JWTSecret, tok)
		if err != nil {
			unauthorized(w, "invalid access token")
			return
		}
		p, err := s.loadPrincipal(r.Context(), claims)
		if err != nil {
			unauthorized(w, "session invalid")
			return
		}
		// An account flagged to change its password may only reach the auth
		// endpoints (change-password, logout, profile, MFA) until it does so —
		// server-side enforcement so the flag can't be bypassed by ignoring the UI.
		if p.MustChangePw && !strings.Contains(r.URL.Path, "/api/v1/auth/") {
			forbidden(w, "password change required")
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
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

// RequireCSRF enforces the double-submit cookie pattern for state-changing,
// cookie-authenticated requests (refresh/logout). Bearer-only API calls that
// don't rely on cookies are exempt.
func (s *Service) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(CSRFCookie)
		header := r.Header.Get("X-CSRF-Token")
		if err != nil || header == "" || cookie.Value != header {
			forbidden(w, "csrf validation failed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AuthenticateToken validates a raw access token and returns its Principal. Used
// by the WebSocket terminal endpoint, where browsers cannot set an Authorization
// header and pass the short-lived token via a query parameter instead.
func (s *Service) AuthenticateToken(ctx context.Context, tokenStr string) (*Principal, error) {
	claims, err := ParseAccessToken(s.cfg.JWTSecret, tokenStr)
	if err != nil {
		return nil, err
	}
	return s.loadPrincipal(ctx, claims)
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
