package api

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"github.com/kforbus3/Moorgate/backend/internal/auth"
	"github.com/kforbus3/Moorgate/backend/internal/httpx"
)

// csrfProtect enforces double-submit CSRF validation on cookie-authenticated,
// state-changing requests.
//
// The threat is a cross-site request that rides the browser's ambient session
// cookies. Two request shapes are therefore exempt:
//
//   - Safe methods (GET/HEAD/OPTIONS/TRACE) change no state.
//   - Bearer-token requests: a cross-site attacker cannot set an Authorization
//     header, and the browser never attaches one automatically, so these are not
//     forgeable. This covers the entire normal SPA/API surface, which authenticates
//     with the access token in the Authorization header.
//
// What remains — a mutating request that carries the session refresh cookie but NO
// bearer token — is exactly the cookie-authenticated surface (notably /auth/refresh).
// For those, the JS-readable double-submit token (fleet_csrf cookie, set at login and
// echoed to the SPA) must be reflected back in the X-CSRF-Token header and match the
// cookie. A cross-site page can neither read the cookie (to copy it into the header)
// nor is it sent the SameSite=Strict cookie on a cross-site request, so it cannot
// satisfy both halves.
func csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if csrfSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			next.ServeHTTP(w, r)
			return
		}
		// No ambient session cookie ⇒ nothing cookie-authenticated to protect (login,
		// bootstrap, SSO callbacks authenticate from the request body, not a cookie).
		if _, err := r.Cookie(auth.RefreshCookie); err != nil {
			next.ServeHTTP(w, r)
			return
		}
		cookie, cerr := r.Cookie(auth.CSRFCookie)
		header := r.Header.Get("X-CSRF-Token")
		if cerr != nil || cookie.Value == "" || header == "" ||
			subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
			httpx.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "missing or invalid CSRF token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfSafeMethod reports whether a method is CSRF-safe (state-non-changing).
func csrfSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// metricsGuard restricts /metrics access. When no trusted-proxy networks are
// configured it is a no-op (metrics stay open — the common internal-scrape case).
// When TrustedProxies IS configured, only loopback and those networks may scrape,
// so an internet-exposed instance does not serve its metrics to arbitrary clients.
func metricsGuard(trustedCIDRs []string) func(http.Handler) http.Handler {
	var nets []*net.IPNet
	for _, c := range trustedCIDRs {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
			nets = append(nets, n)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(nets) == 0 {
				next.ServeHTTP(w, r) // no allowlist configured: default open
				return
			}
			host := r.RemoteAddr
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			ip := net.ParseIP(host)
			if ip != nil && (ip.IsLoopback() || ipInAny(ip, nets)) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		})
	}
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
