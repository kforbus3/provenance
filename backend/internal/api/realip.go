package api

import (
	"net"
	"net/http"
	"strings"
)

// realIP rewrites r.RemoteAddr to the real client IP from X-Forwarded-For, but
// ONLY when the direct peer is a trusted proxy (per FLEET_TRUSTED_PROXIES). XFF
// from an untrusted peer is ignored, so an attacker cannot spoof the header to
// get a fresh rate-limit bucket per request (which previously defeated the auth
// throttle and poisoned audit-log IPs) — chi's stock middleware.RealIP trusted
// the client-supplied header unconditionally.
//
// When the peer is trusted, the client is the right-most XFF entry that is not
// itself a trusted proxy — i.e. the address the outermost trusted proxy saw the
// connection come from. That defeats a spoofed left-most entry.
func realIP(cidrs []string) func(http.Handler) http.Handler {
	var trusted []*net.IPNet
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
			trusted = append(trusted, n)
		}
	}
	inTrusted := func(ip net.IP) bool {
		for _, n := range trusted {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ip := clientFromXFF(r, inTrusted); ip != "" {
				r.RemoteAddr = net.JoinHostPort(ip, "0")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// securityHeaders adds baseline response headers to every backend response. The
// SPA itself is served (and framed/CSP-protected) by the frontend nginx; these
// cover the API and the backend's own HTML routes (which set their own CSP).
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func clientFromXFF(r *http.Request, trusted func(net.IP) bool) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil || !trusted(peer) {
		return "" // direct peer is not a trusted proxy → keep the real RemoteAddr
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			continue
		}
		if trusted(ip) {
			continue // skip chained trusted proxies
		}
		return ip.String() // first untrusted from the right = the real client
	}
	return ""
}
