package stacks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// composeStub puts a fake `docker` on PATH.
//
// `docker compose up -d` fails the first time it is called and succeeds afterwards,
// which is the arrangement that matters: a new compose file that does not come up,
// followed by a previous one that does. Every invocation is logged so a test can see
// what the script actually did rather than what it printed.
func composeStub(t *testing.T, dir string, upFailures int) string {
	t.Helper()
	bin := t.TempDir()
	// The up-counter lives in the stub's OWN directory, not the stack's: a test that
	// runs several deploys against one directory shares `calls` deliberately (it is the
	// log of everything that happened) but must NOT share the counter, or the second
	// deploy starts already past its allowance and quietly succeeds.
	body := `#!/bin/sh
echo "docker $*" >> ` + dir + `/calls
case "$1 $2" in
  "compose version") exit 0 ;;
esac
case "$2" in
  "config") exit 0 ;;
  "pull") exit 0 ;;
  "up")
    n=$(cat ` + bin + `/ups 2>/dev/null || echo 0)
    n=$((n+1)); echo "$n" > ` + bin + `/ups
    if [ "$n" -le ` + itoa(upFailures) + ` ]; then
      echo "dependency failed to start: container keycloak-db is unhealthy" >&2
      exit 1
    fi
    exit 0 ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

const goodCompose = "services:\n  postgres:\n    image: postgres:17.11-alpine\n"
const badCompose = "services:\n  postgres:\n    image: postgres:18.6-alpine\n"

// A deploy whose stack does not come up must leave the host on the file that worked.
//
// This is the Keycloak outage, twice over: the stored compose pinned a postgres major
// version the data directory could not accept, `up` exited non-zero, and the broken
// file stayed in place with the service down -- while the file that had been serving
// fine sat beside it as .prev for twenty hours.
func TestFailedBringUpRestoresThePreviousCompose(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell")
	}
	dir := t.TempDir()
	// The host as it stands before the deploy: running the good file at revision 2.
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(goodCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".provenance-revision"), []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	script := RenderScript(dir, badCompose, 3, false, "")
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+composeStub(t, dir, 1)+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("the script reported success for a deploy whose stack did not come up")
	}
	got := string(out)
	if !strings.Contains(got, "::UPFAILED::") {
		t.Errorf("the failure is not reported in the output:\n%s", got)
	}
	if !strings.Contains(got, "::RESTORED::") {
		t.Errorf("the previous compose file was not restored:\n%s", got)
	}

	// The file on the host is the one that works.
	live, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(live) != goodCompose {
		t.Errorf("the host was left on the compose file that does not come up:\n%s", live)
	}
	// The rejected one is kept, or nobody can see what was wrong with it.
	rejected, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml.rejected"))
	if err != nil {
		t.Errorf("the rejected compose file was not kept: %v", err)
	} else if !strings.Contains(string(rejected), "18.6") {
		t.Errorf("the kept file is not the one that was rejected:\n%s", rejected)
	}
	// And the marker says what the host is actually running.
	rev, err := os.ReadFile(filepath.Join(dir, ".provenance-revision"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(rev)) != "2" {
		t.Errorf("the on-host revision marker says %q, but the host is running revision 2 — "+
			"a drifted host cannot be identified from a marker that describes an apply "+
			"that was rolled back", strings.TrimSpace(string(rev)))
	}
	// Two bring-ups: the one that failed and the one that restored service.
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	if n := strings.Count(string(calls), "compose up -d"); n != 2 {
		t.Errorf("expected the failed up and the restoring up, got %d:\n%s", n, calls)
	}
}

// When the previous file will not come up either, say so rather than claiming a
// recovery: the operator is looking at a stack that is down.
func TestRestoreThatAlsoFailsIsReportedAsDown(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(goodCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	script := RenderScript(dir, badCompose, 3, false, "")
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+composeStub(t, dir, 2)+":"+os.Getenv("PATH"))
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "::RESTOREFAILED::") {
		t.Errorf("a restore that did not come up is not reported as such:\n%s", out)
	}
}

// A first deploy has nothing to fall back to. That must be stated, not silently
// treated as a recovery.
func TestFirstDeployFailureSaysThereIsNoPrevious(t *testing.T) {
	dir := t.TempDir()
	script := RenderScript(dir, badCompose, 1, false, "")
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+composeStub(t, dir, 1)+":"+os.Getenv("PATH"))
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "::NOPREVIOUS::") {
		t.Errorf("a first-deploy failure does not say there is no fallback:\n%s", out)
	}
	if strings.Contains(string(out), "::RESTORED::") {
		t.Errorf("claimed a restore with no previous file:\n%s", out)
	}
}

// The state a pre-1.9.2 deploy left on the host, and the deploy that followed it.
//
// This is the sequence exactly as it happened, and the reason it cost the good file:
//
//	02:50  (old code) live=good -> .prev=good, write bad, `up` fails, NO restore.
//	       The host is left with live=bad, .prev=good, and the stack DOWN.
//	03:54  Deploy pressed again. The rotation copies the live BAD file over .prev,
//	       destroying the only good copy on the machine. The deploy fails, the restore
//	       puts back .prev -- which is now the same broken file -- and reports success.
//
// The rotation is what did the damage, so that is what this asserts: with nothing
// running on the file that is there, the previous one must survive.
func TestRotationKeepsTheGoodFileWhenNothingIsRunning(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Exactly what the earlier deploy left behind.
	write("docker-compose.yml", badCompose)
	write("docker-compose.yml.prev", goodCompose)
	write(".provenance-revision", "3\n")

	// `ps -q` reports nothing running, because the stack is down — which is the fact
	// the rotation has to notice.
	script := RenderScript(dir, badCompose, 3, false, "")
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+composeStub(t, dir, 1)+":"+os.Getenv("PATH"))
	out, _ := cmd.CombinedOutput()

	prev, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml.prev"))
	if err != nil {
		t.Fatalf("the previous compose file is gone entirely: %v", err)
	}
	if strings.TrimSpace(string(prev)) != strings.TrimSpace(goodCompose) {
		t.Fatalf("the rotation copied a file that nothing was running over the last good "+
			"copy — the host now has no working compose file anywhere:\n%s\n--- output:\n%s",
			prev, out)
	}
	// And having kept it, the restore put it back and brought the stack up on it.
	live, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(live)) != strings.TrimSpace(goodCompose) {
		t.Errorf("the host was not returned to the file that works:\n%s", live)
	}
	if !strings.Contains(string(out), "::KEEPINGPREV::") {
		t.Errorf("the output does not say the previous file was kept:\n%s", out)
	}
}

// The other half of the rule: when the stack IS running, the file serving it is what
// .prev should hold. Otherwise an ordinary edit could never be rolled back.
func TestRotationStillRunsWhenTheStackIsUp(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(goodCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml.prev"), []byte("an ancient file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := composeStubRunning(t, dir)
	script := RenderScript(dir, badCompose, 4, false, "")
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	out, _ := cmd.CombinedOutput()

	prev, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml.prev"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(prev)) != strings.TrimSpace(goodCompose) {
		t.Errorf("the running file was not rotated into .prev, so a rollback would go "+
			"back too far:\n%s\n--- output:\n%s", prev, out)
	}
}

// Rollback restores the file that worked, not merely the previous revision.
func TestRollbackPrefersTheKnownGoodFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The state two failed deploys leave behind: .prev is as broken as the live file.
	write("docker-compose.yml", badCompose)
	write("docker-compose.yml.prev", badCompose)
	write("docker-compose.yml.last-good", goodCompose)

	cmd := exec.Command("sh", "-c", rollbackScript(dir))
	cmd.Env = append(os.Environ(), "PATH="+composeStub(t, dir, 0)+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("rollback failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "::ROLLEDBACKTO::docker-compose.yml.last-good") {
		t.Errorf("rollback does not say what it restored, or chose .prev — which here is "+
			"the broken file:\n%s", out)
	}
	live, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(live) != goodCompose {
		t.Errorf("rollback restored a file that does not come up:\n%s", live)
	}
}

// A host that has never had a successful deploy under this version still rolls back to
// its previous revision — the fallback must not be lost.
func TestRollbackFallsBackToPrevWhenNoKnownGood(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(badCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml.prev"), []byte(goodCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", rollbackScript(dir))
	cmd.Env = append(os.Environ(), "PATH="+composeStub(t, dir, 0)+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("rollback failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "::ROLLEDBACKTO::docker-compose.yml.prev") {
		t.Errorf("rollback did not fall back to the previous revision:\n%s", out)
	}
}

// composeStubRunning is composeStub for a stack that IS up: `ps -q` names a container,
// and `up` succeeds the first time and fails after, so the rotation guard sees a live
// project while the new file still fails.
func composeStubRunning(t *testing.T, dir string) string {
	t.Helper()
	bin := t.TempDir()
	body := `#!/bin/sh
echo "docker $*" >> ` + dir + `/calls
case "$1 $2" in
  "compose version") exit 0 ;;
esac
case "$2" in
  "config") exit 0 ;;
  "ps") echo deadbeefcafe; exit 0 ;;
  "pull") exit 0 ;;
  "up")
    n=$(cat ` + bin + `/ups 2>/dev/null || echo 0)
    n=$((n+1)); echo "$n" > ` + bin + `/ups
    if [ "$n" -le 1 ]; then echo "container is unhealthy" >&2; exit 1; fi
    exit 0 ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}
