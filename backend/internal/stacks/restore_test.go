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
	body := `#!/bin/sh
echo "docker $*" >> ` + dir + `/calls
case "$1 $2" in
  "compose version") exit 0 ;;
esac
case "$2" in
  "config") exit 0 ;;
  "pull") exit 0 ;;
  "up")
    n=$(cat ` + dir + `/ups 2>/dev/null || echo 0)
    n=$((n+1)); echo "$n" > ` + dir + `/ups
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
