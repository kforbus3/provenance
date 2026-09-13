package imaging

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The agent is a shell script shipped inside every image. What it sends is a
// wire contract this code does not get to choose, and both halves live in this
// repository -- which makes them look like one thing that can be changed
// together, and they are not. A machine only takes a correction via an update it
// must first authenticate to receive.
//
// So these read the real ab-agent.sh and check the server agrees with it. Not a
// copy of it, and not a list of strings restated here: a test that asserts the
// server matches a constant written beside it would have passed happily while
// the agent sent something else, which is exactly what happened.

const agentScript = "../../../builder/overlay/usr/local/sbin/ab-agent.sh"

func readAgent(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(agentScript)
	if err != nil {
		t.Fatalf("reading the shipped agent: %v", err)
	}
	return string(raw)
}

// The header the agent puts its token in must be the header the server reads.
//
// Getting this wrong is silent and total. PROV_AGENT_TOKEN is set exactly when
// the control plane is reachable from a network that is not the provisioning
// one, so a mismatch 401s every heartbeat from every machine at once and the
// only symptom is a fleet that quietly stops reporting.
func TestTheServerReadsTheHeaderTheAgentSends(t *testing.T) {
	src := readAgent(t)

	// Every -H the agent passes to curl, taken from the script itself.
	found := regexp.MustCompile(`-H "([A-Za-z0-9-]+): \$TOKEN"`).FindAllStringSubmatch(src, -1)
	if len(found) == 0 {
		t.Fatal("no token header found in ab-agent.sh; if the agent stopped sending one, " +
			"this test needs rewriting rather than deleting")
	}

	for _, m := range found {
		header := m[1]
		t.Run(header, func(t *testing.T) {
			svc := &Service{}
			req := httptest.NewRequest(http.MethodPost, "/imaging/heartbeat", nil)
			req.Header.Set(header, "the-shared-secret")
			if !agentTokenOK(req, "the-shared-secret") {
				t.Fatalf("ab-agent.sh sends its token in %q and the server does not accept "+
					"that header. Setting PROV_AGENT_TOKEN would reject every machine in "+
					"the fleet, and they would simply stop checking in.", header)
			}
			// And the guard has to still be a guard.
			bad := httptest.NewRequest(http.MethodPost, "/imaging/heartbeat", nil)
			bad.Header.Set(header, "not-the-secret")
			if agentTokenOK(bad, "the-shared-secret") {
				t.Fatal("a wrong token was accepted")
			}
			empty := httptest.NewRequest(http.MethodPost, "/imaging/heartbeat", nil)
			if agentTokenOK(empty, "the-shared-secret") {
				t.Fatal("a missing token was accepted")
			}
			_ = svc
		})
	}
}

// The agent posts to a fixed path, derived from its configured server. The
// server must serve that exact path, unversioned, or a fleet imaged before any
// rename can never reach the control plane again.
func TestTheServerServesThePathTheAgentPostsTo(t *testing.T) {
	src := readAgent(t)
	found := regexp.MustCompile(`\$\{SERVER%/\}(/[a-z/]+)`).FindAllStringSubmatch(src, -1)
	if len(found) == 0 {
		t.Fatal("no control-plane path found in ab-agent.sh")
	}
	seen := map[string]bool{}
	for _, m := range found {
		path := m[1]
		if seen[path] {
			continue
		}
		seen[path] = true
		// MountMachineCompat is what puts these outside /api/v1. If a path the
		// agent uses is not registered there, it is registered nowhere a machine
		// can reach.
		handlers, err := os.ReadFile("handlers.go")
		if err != nil {
			t.Fatalf("reading handlers: %v", err)
		}
		compat := string(handlers)
		i := strings.Index(compat, "func MountMachineCompat(")
		if i < 0 {
			t.Fatal("MountMachineCompat is gone; the unversioned machine paths are the " +
				"wire contract and cannot simply be dropped")
		}
		if !strings.Contains(compat[i:], `"`+path+`"`) {
			t.Errorf("ab-agent.sh posts to %q, which MountMachineCompat does not register. "+
				"Machines already in the field can only ever reach this path.", path)
		}
	}
}
