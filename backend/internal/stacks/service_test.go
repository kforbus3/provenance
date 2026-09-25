package stacks

import (
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/store"
)

// Drift is the question neither half of the old setup could answer.
//
// A git repository knows what SHOULD run and never learns whether the deploy
// landed; the host knows what IS running and has no opinion about what was
// intended. Keeping both and comparing them is the whole reason the deployment
// state is a separate table from the definition: a tool that tracked only the
// definition would report success for a deploy that never happened.
func TestDriftComparesIntendedAgainstConfirmed(t *testing.T) {
	rev := func(n int) *int { return &n }
	cases := []struct {
		name      string
		stack     store.ContainerStack
		wantDrift bool
	}{
		{"never deployed", store.ContainerStack{Revision: 1, Enabled: true}, true},
		{"host confirmed an older revision",
			store.ContainerStack{Revision: 3, Deployed: rev(2), DeployState: "deployed", Enabled: true}, true},
		{"deploy failed, even at the right revision",
			store.ContainerStack{Revision: 3, Deployed: rev(3), DeployState: "failed", Enabled: true}, true},
		{"in sync",
			store.ContainerStack{Revision: 3, Deployed: rev(3), DeployState: "deployed", Enabled: true}, false},
		// Keycloak on 2026-09-24: both sides said revision 5, the host ran TLS, the
		// stored copy was the old plain-HTTP file.
		{"changed on the host at the same revision",
			store.ContainerStack{Revision: 5, Deployed: rev(5), DeployState: "deployed", Enabled: true, HostDiffers: true}, true},
		{"disabled stacks are not drift",
			store.ContainerStack{Revision: 3, Deployed: rev(1), DeployState: "deployed", Enabled: false}, false},
	}
	for _, c := range cases {
		got := driftsFrom(c.stack)
		if got != c.wantDrift {
			t.Errorf("%s: drift=%v, want %v", c.name, got, c.wantDrift)
		}
	}
}

// The compose the host receives must be the compose that was stored, byte for
// byte. Anything else means what runs is not what was reviewed.
func TestDeploySendsTheStoredComposeVerbatim(t *testing.T) {
	compose := "services:\n  a:\n    image: nginx@sha256:abc\n    command: [\"sh\",\"-c\",\"echo $$HOME\"]\n"
	script := RenderScript("/opt/stacks/web", compose, 4, false, "")
	if !strings.Contains(script, compose) {
		t.Error("the compose file was altered between the database and the host")
	}
	// And the revision the host records must be the one being deployed, or the
	// drift comparison above is comparing against a number nobody set.
	if !strings.Contains(script, "'4'") {
		t.Error("the applied revision is not written to the host")
	}
}
