package enrollment

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
)

// wgKeyRe matches a base64-encoded 32-byte WireGuard/Curve25519 public key: 43
// base64 chars followed by a single '=' pad. Every legitimate `wg pubkey` output
// has this exact shape, and it contains no shell metacharacters.
var wgKeyRe = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

// endpointHostRe restricts an endpoint host to IP/hostname-safe characters. It is
// deliberately permissive about hostname RFC-compliance (allows `_`) but excludes
// every shell metacharacter, so the value is safe to interpolate into a script.
var endpointHostRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// validatePeerInputs rejects values that would be unsafe to interpolate into the
// jump-host peer script, which runs as root via `sudo sh -c`. hostPub comes from
// the (untrusted) host being enrolled or an operator paste; wgIP and hostEndpoint
// derive from host/config data. Any legitimate WireGuard key, overlay IP, and
// endpoint passes; anything carrying shell metacharacters (`'`, `;`, `$`, backtick,
// newline, …) is rejected before it can reach the shell.
func validatePeerInputs(hostPub, hostEndpoint, wgIP string) error {
	if !wgKeyRe.MatchString(hostPub) {
		return fmt.Errorf("host returned a malformed WireGuard public key")
	}
	if net.ParseIP(wgIP) == nil {
		return fmt.Errorf("invalid overlay IP address %q", wgIP)
	}
	host, port, err := net.SplitHostPort(hostEndpoint)
	if err != nil {
		return fmt.Errorf("invalid host endpoint %q", hostEndpoint)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("invalid endpoint port in %q", hostEndpoint)
	}
	if net.ParseIP(host) == nil && !endpointHostRe.MatchString(host) {
		return fmt.Errorf("invalid endpoint host in %q", hostEndpoint)
	}
	return nil
}
