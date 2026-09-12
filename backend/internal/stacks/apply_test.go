package stacks

import (
	"strings"
	"testing"
)

// A compose file is full of shell metacharacters and must survive verbatim.
//
// ${VAR:-default}, $$ for a literal dollar, backticks in a healthcheck command --
// all ordinary in a compose file. If any of it is expanded on the way to the host,
// what runs is not what was reviewed, and the difference is invisible until
// something breaks in production.
func TestRenderScriptDoesNotExpandTheComposeFile(t *testing.T) {
	compose := strings.Join([]string{
		"services:",
		"  app:",
		"    image: nginx@sha256:abc",
		"    environment:",
		"      - HOME=${HOME:-/root}",
		"      - LITERAL=$$notavariable",
		"    healthcheck:",
		"      test: [\"CMD-SHELL\", \"curl -f http://localhost || exit 1\"]",
	}, "\n")

	got := renderScript("/opt/stacks/web", compose, 7)

	// Quoted delimiter: the shell must not touch anything inside.
	if !strings.Contains(got, "<<'PROVENANCE_COMPOSE_EOF'") {
		t.Error("the heredoc delimiter is not quoted, so the shell will expand " +
			"${VAR} and $$ inside the compose file and write something other than " +
			"what was reviewed")
	}
	if !strings.Contains(got, "HOME=${HOME:-/root}") {
		t.Error("the compose body was altered on the way through")
	}

	// Written aside and moved, never edited in place: a half-written compose file
	// is a stack that will not come up.
	if !strings.Contains(got, ".docker-compose.yml.new") || !strings.Contains(got, "mv -f") {
		t.Error("the compose file is written in place rather than moved into place")
	}
	// The previous revision is kept, or a rollback has nothing to restore.
	if !strings.Contains(got, "docker-compose.yml.prev") {
		t.Error("the previous revision is not preserved, so rollback has nothing to use")
	}
	// The revision is readable from the host itself.
	if !strings.Contains(got, ".provenance-revision") {
		t.Error("the applied revision is not recorded on the host, so a drifted " +
			"host cannot be identified without trusting the control plane")
	}
	// The file is the desired state: something it no longer mentions must go.
	if !strings.Contains(got, "--remove-orphans") {
		t.Error("containers dropped from the compose file would linger")
	}
}

// Paths reach a privileged shell. The stack name is validated before it reaches
// the database, but validation lives in another file and one bug away is not far
// enough for a string that becomes a command.
func TestShellQuote(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"/opt/stacks/web", `'/opt/stacks/web'`},
		{"/opt/stacks/a b", `'/opt/stacks/a b'`},
		{`/opt/stacks/it's`, `'/opt/stacks/it'\''s'`},
		{"/opt/stacks/x; rm -rf /", `'/opt/stacks/x; rm -rf /'`},
		{"/opt/stacks/$(id)", `'/opt/stacks/$(id)'`},
		{"/opt/stacks/`id`", "'/opt/stacks/`id`'"},
	} {
		if got := shellQuote(c.in); got != c.want {
			t.Errorf("shellQuote(%q) = %s, want %s", c.in, got, c.want)
		}
	}

	// And end to end: a hostile path must appear only inside quotes.
	got := renderScript(`/opt/stacks/x'; rm -rf /; '`, "services: {}", 1)
	if strings.Contains(got, "; rm -rf /; \n") {
		t.Error("a quoted path escaped its quoting and became a command")
	}
}

func TestRollbackScriptRefusesWithoutAPreviousRevision(t *testing.T) {
	got := rollbackScript("/opt/stacks/web")
	if !strings.Contains(got, "docker-compose.yml.prev") {
		t.Fatal("rollback does not reference the preserved revision")
	}
	// Refusing loudly beats bringing the stack up from whatever is currently on
	// disk, which is the thing being rolled back.
	if !strings.Contains(got, "exit 1") {
		t.Error("rollback with nothing to restore does not fail; it would re-apply " +
			"the revision being rolled back and report success")
	}
}
