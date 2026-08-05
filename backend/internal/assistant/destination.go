package assistant

import (
	"context"
	"net"
	"net/netip"
	"net/url"
)

// Where the model actually runs.
//
// The assistant hands a model privileged material: host inventory, session
// history, audit entries, whatever the caller's permissions reach. Every part of
// this product's documentation says "a local Ollama instance", and the settings
// page says data never leaves your network — but the URL is free text, and
// nothing stops it naming a host on the internet. A promise the code does not
// keep is worse than no promise, so the code checks it and says what it found.
//
// This classifies rather than blocks. An operator with a model server one rack
// over has a legitimate reason for a non-loopback address, and Fleet is not in a
// position to know whose network is whose. What it can do is refuse to claim the
// data stayed home when it did not.

// destination describes where the configured Ollama URL points.
type destination struct {
	// Host is the hostname or address from the URL, for display.
	Host string `json:"host,omitempty"`
	// External is true when the destination is a public address — that is, when
	// asking a question sends fleet data off the local network.
	External bool `json:"external"`
	// Resolved is the address the host resolved to, when that differs from Host.
	Resolved string `json:"resolved,omitempty"`
}

// classifyDestination reports whether a configured Ollama URL points somewhere
// off the local network. An unparseable or unresolvable URL is reported as not
// external: it is not evidence of egress, and the reachability check already
// tells the operator it does not work.
func classifyDestination(ctx context.Context, raw string) destination {
	if raw == "" {
		return destination{}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return destination{}
	}
	host := u.Hostname()
	d := destination{Host: host}

	if ip, err := netip.ParseAddr(host); err == nil {
		d.External = !isLocal(ip)
		return d
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return d
	}
	// Any public answer makes it external: the client may use any of them.
	for _, a := range addrs {
		if !isLocal(a) {
			d.External = true
			d.Resolved = a.String()
			return d
		}
	}
	return d
}

// isLocal reports whether an address is one that keeps traffic on the operator's
// own network: loopback, RFC 1918 and its IPv6 equivalent, link-local, and the
// shared address space carriers and overlay networks use.
func isLocal(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	if ip.Is4() {
		b := ip.As4()
		// 100.64.0.0/10 — carrier NAT, and the range Tailscale hands out.
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return true
		}
	}
	return false
}
