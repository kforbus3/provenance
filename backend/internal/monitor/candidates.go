package monitor

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// unresolvableTTL is how long a hostname that did not resolve is left out of the
// candidates before it is tried again. Long enough that a sweep every 30 seconds does
// not ask DNS the same question, short enough that a name added to DNS is picked up
// within minutes.
const unresolvableTTL = 10 * time.Minute

// unresolvableNames caches hostnames that DNS says do not exist.
type unresolvableNames struct {
	mu    sync.Mutex
	until map[string]time.Time
	// lookup is net.DefaultResolver.LookupHost unless a test replaces it.
	lookup func(ctx context.Context, host string) ([]string, error)
}

// notFound reports whether name definitely does not resolve, asking DNS at most once
// per unresolvableTTL. Only a definite answer counts: a timeout or a server failure
// says nothing about the name, and dropping a candidate on that would turn a DNS blip
// into a host that cannot be reached.
func (u *unresolvableNames) notFound(ctx context.Context, name string, now time.Time) bool {
	u.mu.Lock()
	if t, ok := u.until[name]; ok && now.Before(t) {
		u.mu.Unlock()
		return true
	}
	lookup := u.lookup
	u.mu.Unlock()
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := lookup(lctx, name)
	var dnsErr *net.DNSError
	missing := errors.As(err, &dnsErr) && dnsErr.IsNotFound
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.until == nil {
		u.until = map[string]time.Time{}
	}
	if missing {
		u.until[name] = now.Add(unresolvableTTL)
	} else {
		delete(u.until, name)
	}
	return missing
}

// probeCandidates is the addresses a probe races: overlay, LAN address, hostname.
//
// The hostname is dropped when DNS says it does not exist and the host has another
// address to try. The access point is recorded as "wap" with a working IP address,
// and the jump host cannot resolve "wap" -- so every sweep spent a dial on a name
// that could never answer, and the jump host logged "connect_to wap: unknown host"
// every couple of minutes, for ever. The backend and the jump host resolve through
// the same Docker DNS, so the backend's answer is the jump host's.
//
// A hostname that is the host's only address is always kept: failing on it says
// something true, and leaving nothing to try would say nothing.
func (m *Monitor) probeCandidates(ctx context.Context, h *models.Host) []string {
	all := dedupe([]string{h.WGAddress, h.Address, h.Hostname})
	if len(all) < 2 || h.Hostname == "" || net.ParseIP(h.Hostname) != nil {
		return all
	}
	if h.Hostname == h.WGAddress || h.Hostname == h.Address {
		return all
	}
	if !m.unresolvable.notFound(ctx, h.Hostname, time.Now()) {
		return all
	}
	out := make([]string, 0, len(all)-1)
	for _, a := range all {
		if a != h.Hostname {
			out = append(out, a)
		}
	}
	return out
}
