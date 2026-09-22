package api

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A revocation list must never be built from a query that failed.
//
// RevokedSerials returns (nil, error). The loop discarded the error, so a transient
// database failure left serials nil — and krl.Build is perfectly happy to produce a
// VALID, EMPTY revocation list from no serials. That list then went out to every
// enrolled host, erasing fleet-wide revocation enforcement including the certificate
// revoked a moment earlier, with nothing logged and no job failure recorded.
//
// AllHosts had the same shape with a different ending: nil hosts meant the push loop
// ran over nothing and returned pushed=0, failed=0, err=nil. The caller reads that as
// a clean success and advances lastHash, suppressing the retry for up to an hour while
// the fleet still holds the old list.
//
// Asserted on the source because the behaviour lives in a loop over SSH pushes to real
// hosts. What matters is that no path from a discarded error reaches krl.Build.
func TestTheKRLIsNeverBuiltFromDiscardedErrors(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)

	for _, fn := range []string{"func (s *Server) krlLoop", "func (s *Server) distributeKRL"} {
		seg := funcSegment(body, fn)
		if seg == "" {
			t.Fatalf("%s not found — this test no longer guards what it claims", fn)
		}
		// The three loads that feed a KRL push. Each must capture its error.
		for _, call := range []string{"RevokedSerials", "ListActiveCAPublicKeys", "AllHosts"} {
			discarded := regexp.MustCompile(`,\s*_\s*:?=\s*s\.Store\.` + call + `\(`)
			if discarded.MatchString(seg) {
				t.Errorf("%s discards the error from %s. A nil result here does not fail the "+
					"build: it produces a valid EMPTY revocation list (or an empty host list) "+
					"and pushes it, which silently disarms revocation across the fleet.", fn, call)
			}
		}
	}
}

// And the careful half must stay careful: a partial push must not advance lastHash.
func TestAPartialPushDoesNotMarkDistributionComplete(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	seg := funcSegment(string(src), "func (s *Server) krlLoop")
	if !strings.Contains(seg, "if failed > 0 {") {
		t.Error("the partial-failure guard is gone; hosts that never installed the list " +
			"would be skipped on the next tick and left revocation-blind")
	}
	// lastHash may only advance after that guard has returned.
	iFailed := strings.Index(seg, "if failed > 0 {")
	iAdvance := strings.Index(seg, "lastHash = hash")
	if iFailed < 0 || iAdvance < 0 || iAdvance < iFailed {
		t.Error("lastHash advances before the partial-failure check")
	}
}

func funcSegment(src, sig string) string {
	i := strings.Index(src, sig)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	if end := strings.Index(rest, "\n}\n"); end > 0 {
		return rest[:end]
	}
	return rest
}
