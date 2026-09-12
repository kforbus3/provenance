package appsupport

import (
	"strings"
	"testing"
)

// The property that makes an anonymised bundle still worth reading: the SAME
// address becomes the same pseudonym everywhere.
//
// Without it the relationships are gone — "this host talked to the same peer
// twice", "the gateway and the failing route are the same machine", "these forty
// lines are one client" — which is the actual diagnostic content of an address.
// Randomising each occurrence anonymises perfectly and leaves nothing to read.
func TestTheSameAddressAlwaysBecomesTheSamePseudonym(t *testing.T) {
	a := NewAnonymiser()
	in := `10.10.0.120 connected
10.10.0.5 refused
10.10.0.120 retried
10.10.0.111 routed via 10.10.0.5`
	out := a.Text(in)

	if strings.Contains(out, "10.10.0.") {
		t.Fatalf("a real address survived:\n%s", out)
	}
	lines := strings.Split(out, "\n")
	first := strings.Fields(lines[0])[0] // 10.10.0.120
	third := strings.Fields(lines[2])[0] // 10.10.0.120 again
	if first != third {
		t.Errorf("the same address got two pseudonyms (%s vs %s) — the fact that "+
			"it is the same machine is exactly what a reader needs", first, third)
	}
	second := strings.Fields(lines[1])[0] // 10.10.0.5
	if second == first {
		t.Error("two different addresses collapsed to one pseudonym, which invents " +
			"a relationship that is not there")
	}
	// And the repeat of .5 on the last line matches its first appearance.
	if !strings.Contains(lines[3], second) {
		t.Errorf("a repeated address was not mapped consistently:\n%s", lines[3])
	}
	if a.Count() != 3 {
		t.Errorf("counted %d distinct addresses, want 3", a.Count())
	}
}

func TestPseudonymsAreObviouslyNotReal(t *testing.T) {
	// A reader must be able to tell at a glance that an address is a placeholder,
	// or they will go and try to connect to it.
	a := NewAnonymiser()
	out := a.Text("peer 192.168.1.50 and 172.16.0.9")
	for _, want := range []string{"198.51.100."} {
		if !strings.Contains(out, want) {
			t.Errorf("pseudonyms should come from the documentation ranges, got %q", out)
		}
	}
}

func TestLoopbackAndUnspecifiedSurvive(t *testing.T) {
	// Replacing 127.0.0.1 turns "the backend cannot reach its own database" into a
	// puzzle, and reveals nothing about anybody.
	a := NewAnonymiser()
	in := "listening on 0.0.0.0:8080; db at 127.0.0.1:5432; ::1 also"
	out := a.Text(in)
	for _, keep := range []string{"0.0.0.0:8080", "127.0.0.1:5432", "::1"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%s should be kept — it is diagnostic and identifies nobody:\n%s", keep, out)
		}
	}
}

func TestPortsAndSurroundingTextAreKept(t *testing.T) {
	a := NewAnonymiser()
	out := a.Text(`10.10.0.120:55050 - "GET /api/v1/hosts HTTP/1.1" 200`)
	if !strings.Contains(out, ":55050") {
		t.Errorf("the port was lost, and a port is diagnostic:\n%s", out)
	}
	if !strings.Contains(out, `"GET /api/v1/hosts HTTP/1.1" 200`) {
		t.Errorf("surrounding text was altered:\n%s", out)
	}
}

// The trap: version strings look like addresses.
func TestVersionStringsAreNotMistakenForAddresses(t *testing.T) {
	a := NewAnonymiser()
	versions := []string{
		"4.0.19.2979-ls320", // sonarr
		"6.3.0.10514-ls312", // radarr
		"2.5.2.5491-ls155",  // prowlarr
		"3.1.0.4875-ls36",   // lidarr
		"upgraded to 1.2.15",
	}
	for _, v := range versions {
		if got := a.Text(v); got != v {
			t.Errorf("a version string was treated as an address:\n  in:  %s\n  out: %s", v, got)
		}
	}
	if a.Count() != 0 {
		t.Errorf("%d 'addresses' found in version strings", a.Count())
	}
}

func TestIPv6IsMappedToo(t *testing.T) {
	a := NewAnonymiser()
	out := a.Text("peer fd00:1234:5678::1 and again fd00:1234:5678::1")
	if strings.Contains(out, "fd00:1234") {
		t.Errorf("an IPv6 address survived:\n%s", out)
	}
	if !strings.Contains(out, "2001:db8::") {
		t.Errorf("IPv6 should map into the documentation prefix:\n%s", out)
	}
	// Consistency holds for v6 as well.
	parts := strings.Fields(out)
	if parts[1] != parts[len(parts)-1] {
		t.Errorf("the same IPv6 address got two pseudonyms:\n%s", out)
	}
}

func TestTwoBundlesDoNotShareAMapping(t *testing.T) {
	// Per-bundle, deliberately: a recipient holding two bundles should not be able
	// to line them up into a longer-lived picture of the network.
	a, b := NewAnonymiser(), NewAnonymiser()
	_ = a.Text("10.10.0.5")
	out := b.Text("10.10.0.9 then 10.10.0.5")
	// In b, .9 was seen first, so .5 cannot have b's first pseudonym.
	if strings.HasPrefix(out, "198.51.100.1 ") && strings.HasSuffix(out, "198.51.100.1") {
		t.Error("mappings are shared between anonymisers")
	}
}
