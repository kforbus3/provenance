package stacks

import (
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/store"
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

	got := RenderScript("/opt/stacks/web", compose, 7, false, "")

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
	got := RenderScript(`/opt/stacks/x'; rm -rf /; '`, "services: {}", 1, false, "")
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

func TestAnOrdinaryDeployDoesNotPull(t *testing.T) {
	// `up -d` already fetches anything the host does not have. Pulling every
	// image on every deploy would make a one-line compose edit as slow as a full
	// update, for no change in what ends up running.
	got := RenderScript("/opt/stacks/web", "services: {}", 1, false, "")
	if strings.Contains(got, "$_c pull") {
		t.Errorf("an ordinary deploy pulled:\n%s", got)
	}
}

func TestAnUpdateDeployPullsFirst(t *testing.T) {
	// The whole point when a tag has MOVED — the same 1.0.0 rebuilt on a patched
	// base image. Without a pull, `up -d` finds the tag already present locally
	// and starts the old bytes again: the deploy reports success, the digest
	// never changes, and a rollout marches a no-op across the fleet while every
	// host stays on the vulnerable image.
	got := RenderScript("/opt/stacks/web", "services: {}", 1, true, "")
	pull := strings.Index(got, "$_c pull")
	up := strings.Index(got, "$_c up -d")
	if pull < 0 {
		t.Fatalf("an update deploy did not pull:\n%s", got)
	}
	if pull > up {
		t.Errorf("pulled after bringing the stack up, which starts the old image first:\n%s", got)
	}
	// Both compose flavours, or a host on the older binary silently never pulls.
	// The binary is chosen once into $_c, so the check is that the fallback is
	// still offered rather than that a literal command appears twice.
	if !strings.Contains(got, `_c="docker-compose"`) {
		t.Errorf("the docker-compose fallback is gone, so an older host fails:\n%s", got)
	}
}

func TestAnUpdateRolloutTouchesOnlyItsOwnService(t *testing.T) {
	// The blast radius, which is the part an operator cannot undo.
	//
	// A stack deploy is about the whole file, so pressing Deploy brings up the
	// whole project — that is what was asked for. An update rollout is about ONE
	// image. On a host running a model server, a vector database, a speech
	// recogniser and five other things, updating curl would have restarted all of
	// them.
	got := RenderScript("/opt/stacks/site", "services: {}", 3, true, "web")

	if !strings.Contains(got, "$_c pull 'web'") {
		t.Errorf("did not pull just the service:\n%s", got)
	}
	if !strings.Contains(got, "$_c up -d --no-deps 'web'") {
		t.Errorf("did not bring up just the service:\n%s", got)
	}
	// --remove-orphans deletes containers the file no longer defines. That is a
	// whole-project decision, and making it as a side effect of updating one image
	// would remove things nobody mentioned.
	if strings.Contains(got, "--remove-orphans") {
		t.Errorf("a single-service deploy removed orphans:\n%s", got)
	}
	// One binary is chosen up front and used for everything, so there is no
	// second code path that could silently do the whole project.
	if strings.Contains(got, "docker compose up -d --remove-orphans") {
		t.Errorf("a whole-project bring-up survives alongside the narrowed one:\n%s", got)
	}
}

func TestAnOrdinaryDeployStillBringsUpTheWholeProject(t *testing.T) {
	got := RenderScript("/opt/stacks/site", "services: {}", 3, false, "")
	if !strings.Contains(got, "up -d --remove-orphans") {
		t.Errorf("a stack deploy should still be the whole file:\n%s", got)
	}
}

func TestAServiceNameCannotEscapeIntoTheScript(t *testing.T) {
	got := RenderScript("/opt/x", "services: {}", 1, true, "web'; rm -rf /; '")
	if strings.Contains(got, "rm -rf /;") && !strings.Contains(got, `'\''`) {
		t.Errorf("a service name reached the shell unquoted:\n%s", got)
	}
}

// `docker compose pull` has no --remove-orphans flag. Passing it failed the
// whole deploy with "unknown flag" and exit 16 before a single image was
// fetched, and it only ever fired on a WHOLE-project pulling deploy — which is
// why it survived until seven rollouts hit it at once.
func TestPullIsNotGivenAnUpOnlyFlag(t *testing.T) {
	script := RenderScript("/opt/stacks/app", "services:\n  web:\n    image: nginx:1.27\n", 3, true, "")
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "pull") && strings.Contains(line, "--remove-orphans") {
			t.Errorf("pull was given an up-only flag: %q", line)
		}
	}
	// The up still removes orphans: a container the file no longer names must
	// not be left running.
	if !strings.Contains(script, "up -d --remove-orphans") {
		t.Error("a whole-project up must still remove orphans")
	}
}

func TestANarrowedPullNamesTheServiceAndNothingElse(t *testing.T) {
	script := RenderScript("/opt/stacks/app",
		"services:\n  web:\n    image: nginx:1.27\n  db:\n    image: postgres:16\n", 3, true, "web")
	if !strings.Contains(script, "pull 'web'") {
		t.Errorf("narrowed pull missing:\n%s", script)
	}
	if strings.Contains(script, "--remove-orphans") {
		t.Error("a narrowed deploy must not remove orphans — it would delete the " +
			"services it was told not to touch")
	}
}

// A deploy that is still pulling must not read as drift.
//
// Drift means "the host is not running what it should be", which is an
// invitation to act. A deploy in flight IS that action, happening now, and
// flagging it would put every stack into the needs-attention list for the
// minutes it takes to pull eight images.
func TestADeployInFlightIsNotDrift(t *testing.T) {
	// The host is still on r11 while r12 is being pulled -- MarkStackDeploying
	// deliberately leaves the recorded revision alone, because claiming r12
	// before it is running would be a success reported minutes early.
	//
	// So the revisions DISAGREE for the whole deploy, which is drift by every
	// other measure. It is not: drift means "the host is not running what it
	// should be", which is an invitation to act, and this IS that action
	// happening now. Without this, every stack joins the needs-attention list for
	// the minutes it takes to pull.
	prev := 11
	in := store.ContainerStack{
		Enabled: true, Revision: 12, Deployed: &prev, DeployState: DeployStateDeploying,
	}
	if driftsFrom(in) {
		t.Error("a deploy in progress was reported as drift")
	}
}

func TestAFailedDeployIsStillDriftEvenAtTheRightRevision(t *testing.T) {
	// The host confirmed an ATTEMPT at that revision, not a success. Treating
	// those as the same is how a tool ends up reporting that everything is fine.
	rev := 12
	in := store.ContainerStack{
		Enabled: true, Revision: 12, Deployed: &rev, DeployState: DeployStateFailed,
	}
	if !driftsFrom(in) {
		t.Error("a failed deploy at the right revision must still count as drift")
	}
}

// A narrowed deploy must not reach into the service's dependencies.
//
// This is the failure it exists to prevent, in full. A rollout of
// quay.io/keycloak/keycloak was correctly narrowed to the `keycloak` service and
// still took the database out: `up -d keycloak` also brings up keycloak's
// depends_on, keycloak-db had drifted from the file, so compose RECREATED it,
// the new Postgres refused the existing data directory, and the deploy exited 1
// with "dependency failed to start: container keycloak-db is unhealthy".
// Keycloak was down, and nothing in the rollout had been a Postgres change.
func TestANarrowedDeployDoesNotTouchDependencies(t *testing.T) {
	compose := "services:\n" +
		"  postgres:\n    image: postgres:17.11-alpine\n" +
		"  keycloak:\n    image: quay.io/keycloak/keycloak:26.7.4\n    depends_on:\n" +
		"      postgres:\n        condition: service_healthy\n"
	got := RenderScript("/opt/stacks/keycloak", compose, 3, true, "keycloak")

	if !strings.Contains(got, "up -d --no-deps 'keycloak'") {
		t.Errorf("the bring-up is not --no-deps, so compose will recreate the "+
			"database this deploy was never asked to touch:\n%s", got)
	}
	if strings.Contains(got, "'postgres'") {
		t.Errorf("the database was named in a deploy for keycloak:\n%s", got)
	}
}

// A whole-project deploy is the opposite case: dependency order is the point,
// and --no-deps would break a cold start.
func TestAWholeProjectDeployKeepsItsDependencyOrder(t *testing.T) {
	got := RenderScript("/opt/stacks/app", "services: {}", 1, true, "")
	if strings.Contains(got, "--no-deps") {
		t.Errorf("a whole-project deploy passed --no-deps:\n%s", got)
	}
	if !strings.Contains(got, "up -d --remove-orphans") {
		t.Errorf("a whole-project deploy lost --remove-orphans:\n%s", got)
	}
}

// Network dependents still have to come along: they share the service's network
// namespace and are stranded on a namespace that no longer exists otherwise.
// --no-deps must not undo that, which is why they are named explicitly.
func TestNoDepsStillBringsNetworkDependents(t *testing.T) {
	compose := "services:\n" +
		"  gluetun:\n    image: qmcgaw/gluetun:v3\n" +
		"  qbittorrent:\n    image: lscr.io/linuxserver/qbittorrent:5\n" +
		"    network_mode: service:gluetun\n"
	got := RenderScript("/home/keith/media-stack", compose, 4, true, "gluetun")
	if !strings.Contains(got, "--no-deps") {
		t.Errorf("expected --no-deps:\n%s", got)
	}
	if !strings.Contains(got, "'qbittorrent'") {
		t.Errorf("the network dependent was left behind, stranding it on a namespace "+
			"that no longer exists:\n%s", got)
	}
}
