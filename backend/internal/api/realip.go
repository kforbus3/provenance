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
// When the peer is trusted, the client is the entry `hops` from the RIGHT of
// the header — the address the outermost trusted proxy actually observed. A
// caller can prepend as many invented entries as it likes and never reach that
// position, so a spoofed left-most entry is ignored.
//
// It counts hops rather than deciding which entries "look like" proxies, which
// is what this used to do: it walked right and skipped every entry inside
// FLEET_TRUSTED_PROXIES. That reads sensibly and is wrong, because the default
// trusted list is the whole of RFC1918 — the proxy sits on a Docker bridge or
// the LAN, so it must. Every private client was therefore classified as a proxy
// and skipped, the walk ran out of entries, and the function returned nothing:
//
//	XFF "10.10.0.77", peer 172.18.0.1  ->  ""  (RemoteAddr stays 172.18.0.1)
//
// So every operator in the building was recorded as the proxy. That is one
// shared auth rate-limit bucket for the entire organisation, an IP allowlist
// that evaluates the proxy instead of the caller, an audit log that records
// where a request was relayed rather than where it came from, and — the symptom
// that surfaced it — imaged machines recorded at the Docker bridge address and
// then offered as hosts to add at that address.
//
// It was also spoofable in the case it was written to prevent. With a LAN
// client at 10.10.0.77 sending "1.2.3.4", the header became "1.2.3.4, 10.10.0.77";
// the walk skipped the real (private) client and returned the invented one.
//
// The number of proxies in front of this server is a fact about the deployment.
// It cannot be inferred from address ranges, so it is configuration, defaulting
// to 1 — the shipped compose has exactly one nginx in front of the backend.
func realIP(cidrs []string, hops int) func(http.Handler) http.Handler {
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
			if ip := clientFromXFF(r, inTrusted, hops); ip != "" {
				r.RemoteAddr = net.JoinHostPort(ip, "0")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// securityHeaders adds baseline response headers to every backend response. The
// SPA itself is served (and framed/CSP-protected) by the frontend nginx; these
// cover the API and the backend's own HTML routes (which set their own CSP).
//
// hsts enables Strict-Transport-Security. It is gated on the caller (production /
// secure-cookie deployments) so a plaintext local-http dev server does not pin the
// browser to HTTPS for two years and lock the developer out of http://localhost.
func securityHeaders(hsts bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

func clientFromXFF(r *http.Request, trusted func(net.IP) bool, hops int) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil || !trusted(peer) {
		return "" // direct peer is not a trusted proxy → keep the real RemoteAddr
	}

	// Unparseable entries are dropped rather than counted. A proxy that writes
	// "unknown" (some do, for a client it could not resolve) would otherwise
	// shift the hop count by one and hand back the wrong address.
	var chain []net.IP
	for _, p := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		if ip := net.ParseIP(strings.TrimSpace(p)); ip != nil {
			chain = append(chain, ip)
		}
	}
	if len(chain) == 0 {
		return ""
	}

	if hops < 1 {
		hops = 1
	}
	i := len(chain) - hops
	// Fewer entries than the deployment says it has proxies: a request that
	// reached the server without passing through all of them, or a
	// misconfiguration. Take the left-most, the closest to the origin on offer.
	// Returning "" here would fall back to the peer address, which is the
	// failure being fixed.
	if i < 0 {
		i = 0
	}
	return chain[i].String()
}
