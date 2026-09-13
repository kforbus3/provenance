package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientFromXFF(t *testing.T) {
	// Trust the 10/8 range (a stand-in for the reverse-proxy network).
	mw := realIP([]string{"10.0.0.0/8"}, 1)
	var got string
	h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.RemoteAddr
	}))

	call := func(remote, xff string) string {
		got = ""
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		h.ServeHTTP(nil, r)
		return got
	}

	// Untrusted public peer: XFF is IGNORED (can't spoof), RemoteAddr kept.
	if a := call("203.0.113.9:5555", "1.1.1.1"); a != "203.0.113.9:5555" {
		t.Errorf("untrusted peer XFF should be ignored, got %q", a)
	}
	// Trusted proxy: single XFF entry is the client.
	if a := call("10.0.0.5:5555", "198.51.100.7"); a != "198.51.100.7:0" {
		t.Errorf("trusted proxy should use XFF client, got %q", a)
	}
	// Chained proxies. With one hop configured, the client is the right-most
	// entry -- here the inner proxy, because there are two proxies and the
	// deployment says one.
	//
	// This assertion used to expect 198.51.100.7: the code skipped entries
	// inside the trusted ranges, so it stepped over 10.0.0.9 by itself. That
	// looked like it handled chains for free and it did not. The same rule
	// skipped a genuine CLIENT on 10.0.0.0/8 -- which is every private
	// deployment, since the trusted list must contain RFC1918 for the proxy to
	// be trusted at all -- and it let a client inside those ranges pick its own
	// recorded address by prepending one. A count cannot be reached from the
	// left, so it fixes both; the cost is that a second proxy has to be
	// declared rather than inferred.
	if a := call("10.0.0.5:5555", "6.6.6.6, 198.51.100.7, 10.0.0.9"); a != "10.0.0.9:0" {
		t.Errorf("one hop should take the right-most entry, got %q", a)
	}
	// The same header, with the second proxy declared.
	two := realIP([]string{"10.0.0.0/8"}, 2)
	var got2 string
	h2 := two(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got2 = r.RemoteAddr }))
	r2, _ := http.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "10.0.0.5:5555"
	r2.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7, 10.0.0.9")
	h2.ServeHTTP(nil, r2)
	if got2 != "198.51.100.7:0" {
		t.Errorf("two hops should reach the client, got %q", got2)
	}
	// Trusted peer but no XFF: keep RemoteAddr.
	if a := call("10.0.0.5:5555", ""); a != "10.0.0.5:5555" {
		t.Errorf("no XFF should keep RemoteAddr, got %q", a)
	}
}

// Every one of these is a private client address, which is the case the
// original tests never covered and the only case the shipped default ever sees.
//
// PROV_TRUSTED_PROXIES defaults to the whole of RFC1918, because the reverse
// proxy sits on a Docker bridge or the LAN. The chain walk then skipped any XFF
// entry inside those ranges as "another proxy" — so for a client on the LAN it
// skipped the client, ran out of entries, and returned nothing at all. Every
// operator in the building was recorded as the proxy.
//
// That is not cosmetic. It is one shared auth rate-limit bucket for the whole
// organisation (one person mistyping a password throttles everyone), an IP
// allowlist that evaluates the proxy rather than the caller, and an audit log
// that records where the request was relayed rather than where it came from.

const dockerPeer = "172.18.0.1:44321"

func TestPrivateClientBehindAProxyIsNotDiscarded(t *testing.T) {
	// A LAN operator, one nginx hop. The single XFF entry is the client.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = dockerPeer
	r.Header.Set("X-Forwarded-For", "10.10.0.77")

	got := clientFromXFF(r, inDefaultTrusted, 1)
	if got != "10.10.0.77" {
		t.Fatalf("client IP = %q, want 10.10.0.77 — a private client must not be "+
			"mistaken for a proxy and thrown away", got)
	}
}

func TestImagedMachineOnTheImagingNetworkKeepsItsAddress(t *testing.T) {
	// The concrete case: a machine on the imaging LAN reporting through the
	// provisioning nginx. Recorded as 172.18.0.1, it was offered as the address
	// to add the host at, which is a host record pointing at a Docker bridge.
	r := httptest.NewRequest(http.MethodPost, "/api/imaging/report", nil)
	r.RemoteAddr = dockerPeer
	r.Header.Set("X-Forwarded-For", "192.168.50.160")

	if got := clientFromXFF(r, inDefaultTrusted, 1); got != "192.168.50.160" {
		t.Fatalf("machine address = %q, want 192.168.50.160", got)
	}
}

// The header is attacker-controlled up to the point the outermost trusted proxy
// appends what it actually saw. Taking a fixed number of hops from the right
// means a client cannot reach the entry that is used, however many it invents.
func TestASpoofedLeftHandEntryIsIgnored(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = dockerPeer
	// The client sent "1.2.3.4"; nginx appended the address it really saw.
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9, 10.10.0.77")

	got := clientFromXFF(r, inDefaultTrusted, 1)
	if got != "10.10.0.77" {
		t.Fatalf("client IP = %q, want 10.10.0.77 — the address the proxy itself "+
			"observed, not one the caller supplied", got)
	}
}

// Two proxies is a real deployment (an external load balancer in front of the
// SPA's nginx). It has to be stated rather than guessed: the previous code
// guessed by treating private addresses as proxies, which is what broke the
// one-hop case that everybody actually runs.
func TestTwoHopsIsConfigurable(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = dockerPeer
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.10.0.5")

	if got := clientFromXFF(r, inDefaultTrusted, 2); got != "203.0.113.9" {
		t.Fatalf("with 2 hops: got %q, want 203.0.113.9", got)
	}
}

// More hops configured than entries present means the header is shorter than
// the deployment claims — a direct request that bypassed a proxy, or a
// misconfiguration. Take the left-most rather than nothing: it is the closest
// thing to the origin that is on offer, and returning "" would silently fall
// back to the peer, which is the bug this replaces.
func TestMoreHopsThanEntriesTakesTheLeftmost(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = dockerPeer
	r.Header.Set("X-Forwarded-For", "10.10.0.5")

	if got := clientFromXFF(r, inDefaultTrusted, 3); got != "10.10.0.5" {
		t.Fatalf("got %q, want 10.10.0.5", got)
	}
}

func TestUntrustedPeerIsStillIgnoredEntirely(t *testing.T) {
	// Unchanged and load-bearing: a direct caller must not be able to set its
	// own recorded address by sending the header.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.50:9999"
	r.Header.Set("X-Forwarded-For", "10.10.0.77")

	if got := clientFromXFF(r, inDefaultTrusted, 1); got != "" {
		t.Fatalf("accepted XFF from an untrusted peer: %q", got)
	}
}

func TestGarbageEntriesAreSkippedWithoutLosingTheClient(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = dockerPeer
	r.Header.Set("X-Forwarded-For", "not-an-ip, 10.10.0.77, unknown")

	if got := clientFromXFF(r, inDefaultTrusted, 1); got != "10.10.0.77" {
		t.Fatalf("got %q, want 10.10.0.77", got)
	}
}

// inDefaultTrusted mirrors the shipped PROV_TRUSTED_PROXIES default, so these
// tests fail the way production would rather than the way a hand-picked CIDR
// list would.
func inDefaultTrusted(ip net.IP) bool {
	for _, c := range []string{
		"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12",
		"192.168.0.0/16", "fc00::/7",
	} {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}
