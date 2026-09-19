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

// A compose project assembled from an OVERLAY must be driven by its own files.
//
// keith's aptly stack is docker-compose.yml plus docker-compose.tls-ui.yml, and
// the caddy service exists only in the overlay. The script used to cd into the
// working directory and let compose discover files by their default names, which
// finds docker-compose.yml alone — no caddy service in it, so `config --services`
// never lists it, the script exits ::NOSERVICE::, and the engine concluded the
// container was an orphan that no rollout could ever update. The container was
// ordinary, and its own labels named both files.
//
// Every compose invocation has to carry the flags, not just the check: a `pull`
// or an `up` without them acts on a different (default-discovered) project.
func TestTheProjectsOwnComposeFilesAreUsed(t *testing.T) {
	files := []string{"/root/aptlywebui/docker-compose.yml", "/root/aptlywebui/docker-compose.tls-ui.yml"}
	s := inPlaceScript("/root/aptlywebui", "aptlywebui", files, []string{"caddy"})

	for _, f := range files {
		if !strings.Contains(s, "-f '"+f+"'") {
			t.Errorf("script does not pass -f %s, so compose rediscovers the default file:\n%s", f, s)
		}
		if !strings.Contains(s, "[ -f '"+f+"' ]") {
			t.Errorf("script does not check that %s exists here — a project deployed from "+
				"inside a container records paths this host does not have", f)
		}
	}
	if !strings.Contains(s, "-p 'aptlywebui'") {
		t.Errorf("the project is not named, so the operation could land on another project:\n%s", s)
	}
	// Every compose invocation must go through the wrapper, or a pull or an up
	// would act on a different (default-discovered) project than the one checked.
	for _, verb := range []string{"_run config --services", "_run pull", "_run up -d"} {
		if !strings.Contains(s, verb) {
			t.Errorf("%q is missing, so that step bypasses the project's own files:\n%s", verb, s)
		}
	}
	// The flags must reach compose as written, not as a word-split variable: that
	// is how a quoted path becomes a literal quote character in an argument.
	if strings.Contains(s, "$_f") || strings.Contains(s, "$_p") {
		t.Errorf("flags are expanded from a variable, which cannot preserve quoting:\n%s", s)
	}
}

// And a container with no recorded files keeps working exactly as before: the
// flags collapse to empty and compose discovers the default file itself.
func TestNoRecordedFilesFallsBackToDiscovery(t *testing.T) {
	s := inPlaceScript("/opt/stacks/site", "", nil, []string{"web"})
	if strings.Contains(s, "-f '") {
		t.Errorf("a -f flag appeared with no recorded files:\n%s", s)
	}
	if !strings.Contains(s, "_run() { $_c") {
		t.Errorf("the wrapper does not fall back to plain compose:\n%s", s)
	}
}
