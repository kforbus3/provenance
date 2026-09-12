package appsupport

import (
	"fmt"
	"net"
	"regexp"
	"sort"
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

// Anonymiser maps real addresses and hostnames to stable pseudonyms for one
// bundle.
//
// Off unless asked for. A bundle going to somebody who already knows the estate —
// which is the common case — is more useful with the real names in it, and
// masking has a cost that is easy to underestimate (see MaskHostnames).
type Anonymiser struct {
	mu      sync.Mutex
	enabled bool
	seen    map[string]string
	hosts   map[string]string
	order   []string // hostnames longest-first, so a suffix match cannot win
	n4      int
	n6      int
}

// NewAnonymiser returns one that does nothing. Collect turns it on when asked.
func NewAnonymiser() *Anonymiser {
	return &Anonymiser{seen: map[string]string{}, hosts: map[string]string{}}
}

// Enable turns replacement on. Without it every method returns its input.
func (a *Anonymiser) Enable() { a.enabled = true }

// MaskHostnames registers the fleet's hostnames for replacement.
//
// Only names this instance actually manages are masked. Matching arbitrary
// hostname-shaped words would catch every domain in every log line, and most of
// those belong to other people.
//
// The cost worth knowing about: a hostname that is also an ordinary word gets
// replaced wherever it appears, including where it did not mean the host. On a
// real fleet those were `docker`, `ai`, `python` and `repo` — so with masking on,
// a line about the docker daemon reads as a line about host-4. That is the price
// of masking rather than a defect in it, and the manifest says which names were
// ambiguous so a reader can allow for it.
//
// Assigned in sorted order, so the mapping is stable for a given fleet within a
// bundle rather than depending on which log line happened to mention a host first.
func (a *Anonymiser) MaskHostnames(names []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	clean := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		// A one-character hostname would match inside almost every word. Left
		// alone, and reported, rather than shredding the bundle.
		if len(n) < 2 {
			continue
		}
		clean = append(clean, n)
	}
	sort.Strings(clean)
	for i, n := range clean {
		if _, ok := a.hosts[n]; ok {
			continue
		}
		a.hosts[n] = fmt.Sprintf("host-%d", i+1)
	}
	a.order = append(a.order[:0], clean...)
	// Longest first: masking "db" before "db.example.com" would leave a mangled
	// half-replaced name behind.
	sort.Slice(a.order, func(i, j int) bool { return len(a.order[i]) > len(a.order[j]) })
}

// AmbiguousHostnames are the registered names that are also ordinary words, and
// so will be replaced in places that had nothing to do with the host.
func (a *Anonymiser) AmbiguousHostnames() []string {
	common := map[string]bool{
		"docker": true, "ai": true, "python": true, "repo": true, "node": true,
		"web": true, "db": true, "mail": true, "proxy": true, "cache": true,
		"backup": true, "test": true, "dev": true, "prod": true, "build": true,
		"router": true, "gateway": true, "server": true, "storage": true,
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for n := range a.hosts {
		if common[strings.ToLower(n)] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
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
	if !a.enabled {
		return s
	}
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

// Text replaces every address and known hostname in free text, consistently.
func (a *Anonymiser) Text(s string) string {
	if !a.enabled {
		return s
	}
	out := a.maskHosts(s)
	out = ipv6.ReplaceAllStringFunc(out, func(m string) string {
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

// maskHosts replaces registered hostnames on word boundaries.
func (a *Anonymiser) maskHosts(s string) string {
	a.mu.Lock()
	order := append([]string(nil), a.order...)
	hosts := make(map[string]string, len(a.hosts))
	for k, v := range a.hosts {
		hosts[k] = v
	}
	a.mu.Unlock()

	for _, name := range order {
		re, err := regexp.Compile(`\b` + regexp.QuoteMeta(name) + `\b`)
		if err != nil {
			continue
		}
		s = re.ReplaceAllString(s, hosts[name])
	}
	return s
}

// Count is how many distinct addresses were replaced, for the bundle's manifest.
// An operator should be able to see that anonymisation happened and how much of
// it there was.
func (a *Anonymiser) Count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.seen)
}
