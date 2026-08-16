// Package wsorigin provides a shared WebSocket Origin check used by every upgrader
// in the backend. Browsers attach an Origin header to a WebSocket handshake and the
// same-origin policy does NOT cover WebSockets, so an upgrader that accepts every
// Origin is open to cross-site WebSocket hijacking. This helper closes that: it
// requires a browser-supplied Origin to match the deployment's public URL, while
// still allowing non-browser Go clients (the enrollment agent bridge, the
// federation site link) that legitimately send no Origin header at all.
package wsorigin

import (
	"net/http"
	"net/url"
	"strings"
)

// Allowed reports whether a WebSocket upgrade request may proceed. A request with no
// Origin header is allowed (non-browser client). A request WITH an Origin is allowed
// only when it matches publicURL's scheme+host (case-insensitive). When publicURL is
// empty/unparseable it fails closed for any browser Origin.
func Allowed(r *http.Request, publicURL string) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true // non-browser client (agent, federation link) — no Origin to check
	}
	want := normalize(publicURL)
	if want == "" {
		return false // misconfigured public URL: refuse browser origins rather than allow all
	}
	return normalize(origin) == want
}

// Check adapts Allowed into the func(*http.Request) bool shape gorilla/websocket's
// Upgrader.CheckOrigin expects, binding it to a fixed public URL.
func Check(publicURL string) func(*http.Request) bool {
	want := normalize(publicURL)
	return func(r *http.Request) bool {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			return true
		}
		if want == "" {
			return false
		}
		return normalize(origin) == want
	}
}

// normalize reduces a URL/Origin to a lowercase "scheme://host[:port]" for comparison.
// It returns "" for anything without both a scheme and a host.
func normalize(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}
