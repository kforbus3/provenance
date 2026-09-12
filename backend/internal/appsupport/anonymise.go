package appsupport

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Consistent pseudonymisation of IP addresses.
//
// Hostnames stay: they are what makes a bundle readable, and an operator sending
// one already knows their own estate. Addresses go, because a bundle is sent
// somewhere and an address map of somebody's network is not the sort of thing to
// hand over to read a log.
//
// The important property is that the SAME address becomes the same pseudonym
// everywhere in the bundle. Without that, the relationships are gone: "this host
// talked to the same peer twice", "the gateway and the failing route are the same
// machine", "these forty log lines are one client" — all of which is the actual
// diagnostic content of an address. Randomising each occurrence would technically
// anonymise and would also make the bundle useless.
//
// The mapping is per BUNDLE, not global. Within one bundle it is perfectly
// consistent; two bundles from the same instance use different pseudonyms, so a
// recipient holding both cannot line them up into a longer-lived picture of the
// network. That is a deliberate trade: comparing two bundles by address is not
// something support does, and cross-bundle correlation is exactly what an address
// map is good for.
//
// Replacements come from the ranges RFC 5737 and RFC 3849 reserve for
// documentation, so anything reading the bundle can tell at a glance that an
// address is not real.

// ipv4 requires four octets, each within range. That bound is what keeps version
// strings out of it: linuxserver tags like 4.0.19.2979 and 6.3.0.10514 have a
// final component far above 255 and are left alone.
var (
	ipv4 = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)
	// Conservative: at least three groups and a colon-colon or five colons, so
	// ordinary "key: value" text and MAC addresses are not caught.
	ipv6 = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,7}(?::|[0-9a-fA-F]{1,4})(?:%[0-9a-zA-Z]+)?\b`)
)

// Anonymiser maps real addresses to stable pseudonyms for one bundle.
type Anonymiser struct {
	mu   sync.Mutex
	seen map[string]string
	n4   int
	n6   int
}

func NewAnonymiser() *Anonymiser {
	return &Anonymiser{seen: map[string]string{}}
}

// keep reports addresses that carry no information about somebody's network and
// are highly diagnostic: loopback, the unspecified address, and broadcast.
//
// Replacing 127.0.0.1 would turn "the backend cannot reach its own database" into
// a puzzle, and reveals nothing about anybody.
func keep(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsUnspecified() ||
		ip.Equal(net.IPv4bcast) || ip.IsMulticast() && ip.IsLinkLocalMulticast()
}

// Map returns the stable pseudonym for one address.
func (a *Anonymiser) Map(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return s
	}
	if keep(ip) {
		return s
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if got, ok := a.seen[ip.String()]; ok {
		return got
	}
	var out string
	if ip.To4() != nil {
		a.n4++
		// 198.51.100.0/24 then 203.0.113.0/24 (RFC 5737), then a wider marker so
		// a very large bundle still produces something obviously not real.
		switch {
		case a.n4 <= 254:
			out = fmt.Sprintf("198.51.100.%d", a.n4)
		case a.n4 <= 508:
			out = fmt.Sprintf("203.0.113.%d", a.n4-254)
		default:
			out = fmt.Sprintf("192.0.2.%d", (a.n4-508)%254+1)
		}
	} else {
		a.n6++
		out = fmt.Sprintf("2001:db8::%x", a.n6) // RFC 3849
	}
	a.seen[ip.String()] = out
	return out
}

// Text replaces every address in free text, consistently.
func (a *Anonymiser) Text(s string) string {
	out := ipv6.ReplaceAllStringFunc(s, func(m string) string {
		// The regex is deliberately loose; ParseIP is the arbiter, and Map returns
		// the input unchanged when it is not an address.
		return a.Map(m)
	})
	out = ipv4.ReplaceAllStringFunc(out, func(m string) string {
		for _, part := range strings.Split(m, ".") {
			if n, err := strconv.Atoi(part); err != nil || n > 255 {
				return m // a version string, not an address
			}
		}
		return a.Map(m)
	})
	return out
}

// Count is how many distinct addresses were replaced, for the bundle's manifest.
// An operator should be able to see that anonymisation happened and how much of
// it there was.
func (a *Anonymiser) Count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.seen)
}
