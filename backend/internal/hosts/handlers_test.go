package hosts

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestCleanTags(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"trims and drops empty", []string{" prod ", "", "  "}, []string{"prod"}},
		{"dedupes preserving order", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"nil in empty out", nil, []string{}},
		{"already clean", []string{"web", "db"}, []string{"web", "db"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cleanTags(c.in); !reflect.DeepEqual(got, c.want) {
				t.Errorf("cleanTags(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// Deleting a host must revoke its overlay certificate whether or not a teardown was
// asked for.
//
// On a certificate overlay the certificate IS the credential. Deleting the host row
// cascades overlay_clients away, which is the only record of which serial belonged to
// it — so a delete that does not revoke leaves a live certificate that can never be
// revoked afterwards.
//
// Demonstrated on a QA host before this was fixed: deleted from Provenance, its OpenVPN
// client restarted, and the jump host accepted the fresh handshake, returned the same
// pinned address and carried traffic. The host was gone from the control plane and
// still on the network.
//
// The delete handler is wired through app.Deps and needs a store to run, so this
// asserts on the source: the call must not be gated on teardown. That is the whole of
// the defect — the reasoning in the comment above it was already correct, and only the
// condition disagreed.
func TestDeleteRevokesOverlayCertsRegardlessOfTeardown(t *testing.T) {
	src, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)

	i := strings.Index(body, "RevokeHostOverlayCerts != nil")
	if i < 0 {
		t.Fatal("the delete path no longer calls RevokeHostOverlayCerts — this test no " +
			"longer guards what it claims to")
	}
	// The condition, back to the start of its line.
	start := strings.LastIndex(body[:i], "\n") + 1
	cond := strings.TrimSpace(body[start : i+len("RevokeHostOverlayCerts != nil")])
	if strings.Contains(cond, "teardown") {
		t.Errorf("overlay revocation is gated on teardown: %q\n"+
			"A delete without teardown then removes the serial (overlay_clients cascades) "+
			"and leaves a certificate that is both live and unrevokable. Teardown means "+
			"\"go and clean that machine\"; revocation means \"stop accepting this "+
			"credential\" and must not depend on reaching anything.", cond)
	}
}
