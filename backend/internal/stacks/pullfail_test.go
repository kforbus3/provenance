package stacks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pullStub puts a fake `docker` on PATH whose PULL fails.
//
// failures is how many pull attempts fail before one succeeds; alwaysFails means
// every attempt does. msg is what the failing pull prints, because the script
// decides whether to try again by reading it.
func pullStub(t *testing.T, dir string, failures int, msg string) string {
	t.Helper()
	bin := t.TempDir()
	body := `#!/bin/sh
echo "docker $*" >> ` + dir + `/calls
case "$1 $2" in
  "compose version") exit 0 ;;
esac
case "$2" in
  "config") exit 0 ;;
  "pull")
    n=$(cat ` + bin + `/pulls 2>/dev/null || echo 0)
    n=$((n+1)); echo "$n" > ` + bin + `/pulls
    if [ "$n" -le ` + itoa(failures) + ` ]; then
      echo '` + msg + `'
      exit 1
    fi
    exit 0 ;;
  "up") exit 0 ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// alwaysFails is a pull-failure count no deploy will ever reach.
const alwaysFails = 999

const whisper66 = "services:\n  wyoming-whisper:\n    image: ghcr.io/linuxserver/faster-whisper:gpu-v3.8.1-ls66\n"
const whisper67 = "services:\n  wyoming-whisper:\n    image: ghcr.io/linuxserver/faster-whisper:gpu-v3.8.1-ls67\n"

// The host as it stood in production before the rollout: running ls66, with the
// same file recorded as the last one known to have come up.
func hostOnWhisper66(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"docker-compose.yml", "docker-compose.yml.last-good", "docker-compose.yml.prev"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(whisper66), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, ".provenance-revision"), []byte("11\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runDeploy(t *testing.T, dir, compose string, rev int, bin string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "-c", RenderScript(dir, compose, rev, true, ""))
	cmd.Env = append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"),
		"PROV_PULL_RETRY_SECONDS=0")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// A deploy whose PULL fails must leave the host's compose file as it found it.
//
// This is the production failure of 2026-09-20, exactly. A rollout rewrote a
// host's compose file from faster-whisper ls66 to ls67 and the pull came back
// "toomanyrequests: retry-after: 548.005µs". Because the script ran under
// `set -e` with a bare `docker compose pull`, it ended AT the pull -- after the
// new file had been moved into place and before any of the restore logic. The
// host was left with a compose file naming ls67, a container running ls66, and
// .last-good holding the correct ls66 file, untouched.
//
// The failure mode is not "the deploy failed". It is that the deploy left the
// host describing itself as something it was not, so the next unrelated `up` in
// that project would have recreated the service onto a version nobody deployed.
func TestFailedPullLeavesTheComposeFileAsItFoundIt(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell")
	}
	dir := hostOnWhisper66(t)
	// A permanent failure, so this test does not wait through the retries; the
	// transient case has its own test below.
	out, err := runDeploy(t, dir, whisper67, 12,
		pullStub(t, dir, alwaysFails, "unauthorized: authentication required"))
	if err == nil {
		t.Fatal("the script reported success for a deploy whose pull failed")
	}
	if !strings.Contains(out, "::PULLFAILED::") {
		t.Errorf("a failed pull is not reported as one:\n%s", out)
	}
	if !strings.Contains(out, "::REVERTEDTO::docker-compose.yml.last-good") {
		t.Errorf("the compose file was not put back:\n%s", out)
	}

	live, rerr := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(live) != whisper66 {
		t.Errorf("the host is left naming a version it is not running.\n got: %q\nwant: %q",
			string(live), whisper66)
	}

	// The revision marker too: a host that reports revision 12 when revision 12
	// was never applied cannot be told apart from one where it was.
	rev, _ := os.ReadFile(filepath.Join(dir, ".provenance-revision"))
	if strings.TrimSpace(string(rev)) != "11" {
		t.Errorf("revision marker is %q, want 11 -- the number the host is actually on",
			strings.TrimSpace(string(rev)))
	}

	// The rejected file is kept: a failure nobody can inspect is one nobody can fix.
	if rejected, rerr := os.ReadFile(filepath.Join(dir, "docker-compose.yml.rejected")); rerr != nil {
		t.Errorf("the rejected file was not kept for inspection: %v", rerr)
	} else if string(rejected) != whisper67+"\n" {
		t.Errorf(".rejected holds %q, want the file that was refused", string(rejected))
	}

	// And .last-good is still there for the NEXT failure. The old validation path
	// used `mv` from .prev, which spent the only copy.
	if _, rerr := os.Stat(filepath.Join(dir, "docker-compose.yml.last-good")); rerr != nil {
		t.Errorf("last-good was consumed by the revert: %v", rerr)
	}

	// Containers are not touched. A pull failure changed nothing that was
	// running, and bringing the project up here would START a project somebody
	// had deliberately stopped -- a new decision, taken by an error handler.
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	for _, line := range strings.Split(string(calls), "\n") {
		if strings.HasPrefix(line, "docker compose up") {
			t.Errorf("the pull-failure path ran a bring-up: %q", line)
		}
	}
}

// A registry rate limit must not end a deploy.
//
// 548 microseconds was the retry-after. Two failures then a success is the
// ordinary shape of a busy registry, and the deploy should land.
func TestTransientPullIsRetriedAndTheDeployLands(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell")
	}
	dir := hostOnWhisper66(t)
	out, err := runDeploy(t, dir, whisper67, 12,
		pullStub(t, dir, 2, "toomanyrequests: retry-after: 548.005us, allowed: 44000/minute"))
	if err != nil {
		t.Fatalf("a transient rate limit ended the deploy: %v\n%s", err, out)
	}
	if n := strings.Count(out, "::PULLRETRY::"); n != 2 {
		t.Errorf("retried %d times, want 2:\n%s", n, out)
	}
	live, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if string(live) != whisper67+"\n" {
		t.Errorf("the deploy succeeded but the host is not on the new file: %q", string(live))
	}
	if !strings.Contains(string(mustRead(t, filepath.Join(dir, "docker-compose.yml.last-good"))), "ls67") {
		t.Error("a deploy that came up did not become the new known-good file")
	}
}

// A permanent failure is reported at once, not three times several minutes
// apart. The message is the useful part and repeating it buries it.
func TestPermanentPullFailsOnTheFirstAttempt(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell")
	}
	dir := hostOnWhisper66(t)
	out, _ := runDeploy(t, dir, whisper67, 12,
		pullStub(t, dir, alwaysFails, "manifest unknown: manifest unknown"))
	if strings.Contains(out, "::PULLRETRY::") {
		t.Errorf("retried a permanent failure:\n%s", out)
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	if n := strings.Count(string(calls), "compose pull"); n != 1 {
		t.Errorf("pulled %d times for a manifest that does not exist, want 1", n)
	}
}

// A transient failure that never clears still has to leave the host consistent.
func TestExhaustedRetriesStillRevert(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell")
	}
	dir := hostOnWhisper66(t)
	out, err := runDeploy(t, dir, whisper67, 12,
		pullStub(t, dir, alwaysFails, "toomanyrequests: retry-after: 548.005us"))
	if err == nil {
		t.Fatal("a pull that never succeeded reported success")
	}
	if n := strings.Count(out, "::PULLRETRY::"); n != pullAttempts-1 {
		t.Errorf("retried %d times, want %d", n, pullAttempts-1)
	}
	if live := mustRead(t, filepath.Join(dir, "docker-compose.yml")); string(live) != whisper66 {
		t.Errorf("host left on %q after every attempt failed", string(live))
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
