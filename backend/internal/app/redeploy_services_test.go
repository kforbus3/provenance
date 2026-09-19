package app

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every locally built service must be in the redeploy target, or its code never
// ships.
//
// builder-runner and dockerproxy were missing, and the failure is silent in the
// worst way: the fix is committed, the deploy reports success, and the old code
// keeps serving because nothing rebuilt it. A sidecar-cleanup fix was "deployed"
// to a container that had been running for 27 hours.
//
// The jump host is excluded deliberately — recreating it drops the overlay and
// takes every host offline — and redeploy-single says so itself.
func TestEveryBuiltServiceIsRedeployed(t *testing.T) {
	compose, err := os.ReadFile("../../../deploy/compose/docker-compose.yml")
	if err != nil {
		t.Skipf("compose file not readable from here: %v", err)
	}
	mk, err := os.ReadFile("../../../Makefile")
	if err != nil {
		t.Skipf("Makefile not readable from here: %v", err)
	}

	// Services that build an image from this repo.
	svc := regexp.MustCompile(`(?m)^  ([a-z0-9-]+):\s*$`)
	build := regexp.MustCompile(`(?m)^\s+build:`)
	lines := strings.Split(string(compose), "\n")
	current := ""
	built := map[string]bool{}
	for _, l := range lines {
		if m := svc.FindStringSubmatch(l); m != nil {
			current = m[1]
		}
		if build.MatchString(l) && current != "" {
			built[current] = true
		}
	}
	if len(built) == 0 {
		t.Fatal("found no services with a build stanza — the parse is wrong, not the compose file")
	}

	// The redeploy-single recipe specifically. Matching any `up -d --build` line
	// picks up `up-single`, which passes no service list at all (it rebuilds
	// everything), and the test then reads as "nothing is covered" — which is how
	// this test failed on a correct Makefile the first time it ran.
	var target string
	inTarget := false
	for _, l := range strings.Split(string(mk), "\n") {
		if strings.HasPrefix(l, "redeploy-single:") {
			inTarget = true
			continue
		}
		if inTarget {
			if strings.Contains(l, "up -d --build") {
				target = l
				break
			}
			// A new target started before any build line: the recipe changed shape.
			if len(l) > 0 && l[0] != '\t' && l[0] != ' ' && strings.Contains(l, ":") {
				break
			}
		}
	}
	if target == "" {
		t.Fatal("redeploy-single has no `up -d --build` line — the recipe changed shape")
	}

	for name := range built {
		if name == "jumphost" {
			continue // excluded on purpose; see redeploy-single
		}
		if !strings.Contains(target, name) {
			t.Errorf("%s builds an image from this repo but no redeploy target rebuilds it — "+
				"a fix to it would deploy silently as a no-op", name)
		}
	}
}
