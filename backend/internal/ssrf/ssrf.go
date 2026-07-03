// Package ssrf validates operator-supplied URLs/addresses that the backend
// fetches or connects to, to blunt server-side request forgery.
//
// These integrations (Ollama, notification webhooks, syslog/HTTP audit
// forwarding) are configured by admins and legitimately point at services on the
// PRIVATE network, so RFC1918/ULA ranges are intentionally allowed. What is
// refused is the set of targets that are never a legitimate integration and are
// the real SSRF prizes: the cloud metadata endpoint (link-local 169.254/16,
// fe80::/10), loopback (127/8, ::1), the unspecified address, and multicast.
package ssrf

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SafeClient returns an http.Client that re-validates every redirect target with
// ValidateURL, so an allowed initial URL cannot 30x-redirect to a disallowed
// address (metadata/loopback/link-local). Redirect depth is capped. Callers must
// still call ValidateURL on the initial URL before the request. (Note: this does
// not close a DNS-rebinding TOCTOU between validation and dial — that would need a
// validating DialContext — but it removes the redirect-follow bypass.)
func SafeClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return ValidateURL(req.URL.String())
		},
	}
}

// ValidateURL checks scheme (http/https) and that the host does not resolve to a
// disallowed address.
func ValidateURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https")
	}
	return ValidateHost(u.Hostname())
}

// ValidateHostPort validates a "host:port" address (e.g. a syslog collector).
func ValidateHostPort(addr string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		host = strings.TrimSpace(addr)
	}
	return ValidateHost(host)
}

// ValidateHost resolves host and refuses if any resolved IP is disallowed.
func ValidateHost(host string) error {
	if host == "" {
		return fmt.Errorf("missing host")
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("could not resolve host %q", host)
	}
	for _, ip := range ips {
		if disallowed(ip) {
			return fmt.Errorf("host %q resolves to a disallowed address (metadata/loopback)", host)
		}
	}
	return nil
}

func disallowed(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast()
}
