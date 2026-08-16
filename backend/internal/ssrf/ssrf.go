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
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SafeClient returns an http.Client hardened against SSRF three ways: it caps and
// re-validates redirects (an allowed initial URL cannot 30x-redirect to a
// disallowed address), and its transport uses a validating DialContext that
// re-resolves the host at dial time, refuses any disallowed IP, and connects to
// the validated IP directly — so a DNS answer cannot change between an earlier
// ValidateURL check and the actual dial (the DNS-rebinding TOCTOU). Callers should
// still call ValidateURL on the initial URL for an early, clear rejection.
func SafeClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return ValidateURL(req.URL.String())
		},
		Transport: &http.Transport{
			DialContext:           safeDialContext(&net.Dialer{Timeout: timeout}),
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
}

// safeDialContext resolves the requested host, refuses the connection if ANY
// resolved IP is disallowed (metadata/loopback/link-local/unspecified/multicast),
// then dials a validated IP directly. Dialing the resolved IP — rather than
// handing the hostname back to the dialer to resolve again — is what closes the
// DNS-rebinding window: the connection lands on exactly the address that was
// checked.
func safeDialContext(d *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("could not resolve host %q", host)
		}
		for _, ip := range ips {
			if disallowed(ip.IP) {
				return nil, fmt.Errorf("host %q resolves to a disallowed address (metadata/loopback)", host)
			}
		}
		var lastErr error
		for _, ip := range ips {
			conn, derr := d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if derr == nil {
				return conn, nil
			}
			lastErr = derr
		}
		return nil, lastErr
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
