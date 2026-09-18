package containerupdate

import (
	"strings"
	"testing"
)

// An orphaned container must not halt a fleet-wide rollout.
//
// The real case: /root/aptlywebui had its `caddy` service replaced by nginx. The
// new container was healthy; the six-day-old caddy container was still running
// beside it, still carrying `com.docker.compose.service=caddy`, because the
// project had been brought up without --remove-orphans. Provenance saw a
// container on caddy:2-alpine, offered a rebuild, and `compose up -d caddy`
// could not work -- there is no such service any more.
//
// Refusing is right. Failing the HOST was not: nothing about that orphan will
// ever succeed, so it stopped every other host in the run for no gain.
func TestAnOrphanedContainerDoesNotHaltTheRollout(t *testing.T) {
	if !unreachableProject("...\n::NOSERVICE::\n") {
		t.Error("an orphaned container still fails its host, which halts the whole rollout")
	}
	// The cases that were already inapplicable must stay that way.
	for _, marker := range []string{"::NODIR::", "::NOACCESS::"} {
		if !unreachableProject("x\n" + marker + "\n") {
			t.Errorf("%s stopped being treated as inapplicable", marker)
		}
	}
	// And a plain failure must still fail.
	if unreachableProject("some compose error\n[exit code 1]\n") {
		t.Error("an ordinary failure was treated as inapplicable")
	}
}

// The message has to describe what is actually wrong. It used to say "this is
// not the project they came from", which was false: it WAS that project, the
// project had moved on without the container.
func TestTheOrphanMessageNamesTheRealCause(t *testing.T) {
	msg := inPlaceFailure("/root/aptlywebui", []string{"caddy"}, "::NOSERVICE::")
	for _, want := range []string{"/root/aptlywebui", `"caddy"`, "--remove-orphans", "renamed or replaced"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message is missing %q, so it does not say what to do:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "not the project they came from") {
		t.Error("the message still blames the wrong thing")
	}
}
