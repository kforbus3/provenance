package containerupdate

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/stacks"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// End-to-end against a real Docker and a real compose project.
//
// Every bug this feature has shipped lived in the space between three things
// that are only correct TOGETHER: the script sent to a host, the shell that runs
// it, and the parser that reads it back. Unit tests fed the parser hand-written
// strings, so none of them could see:
//
//   - `echo "$_i\t$_d"`, which bash does not expand, so every digest was dropped
//   - scripts assuming they ran as root when they ran as an ordinary account
//   - a compose file already naming the target tag, so the rewrite found nothing
//
// Each of those reached production and was found by an operator. This runs the
// real scripts against a real daemon, which is the only place they can be wrong
// together.
//
// Gated: needs a working Docker with compose. Skips without one.
//
//	PROVENANCE_E2E_DOCKER=1 go test ./internal/containerupdate/ -run E2E -v

const (
	e2eFrom = "alpine:3.20"
	e2eTo   = "alpine:3.21"
	e2eRepo = "alpine"
)

func e2eEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("PROVENANCE_E2E_DOCKER") == "" {
		t.Skip("set PROVENANCE_E2E_DOCKER=1 to run (needs a working docker + compose)")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skip("docker compose not usable here")
	}
}

// sh runs a generated script exactly as a host would: through /bin/sh.
func sh(t *testing.T, script string) (string, int) {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", script)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running script: %v", err)
	}
	// Same as shRun: the product appends this to every result, so a test that
	// omits it is testing something the product never produces.
	return string(out) + fmt.Sprintf("\n[exit code %d]", code), code
}

// e2eProject writes a compose project and brings it up. Returns its directory.
func e2eProject(t *testing.T, image string) string {
	t.Helper()
	dir := t.TempDir()
	compose := fmt.Sprintf(`services:
  probe:
    image: %s
    command: ["sleep", "600"]
`, image)
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	up := exec.Command("docker", "compose", "up", "-d")
	up.Dir = dir
	if out, err := up.CombinedOutput(); err != nil {
		t.Fatalf("compose up: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		down := exec.Command("docker", "compose", "down", "-v", "--remove-orphans")
		down.Dir = dir
		_ = down.Run()
	})
	return dir
}

// TestE2EAdoptReadsTheRealFile proves adoptScript's output is what parseAdopt
// expects, against a file on disk rather than a string in a test.
func TestE2EAdoptReadsTheRealFile(t *testing.T) {
	e2eEnabled(t)
	dir := e2eProject(t, e2eFrom)

	out, _ := sh(t, adoptScript(dir))
	compose, err := parseAdopt(dir, out)
	if err != nil {
		t.Fatalf("parseAdopt: %v\nraw output:\n%s", err, out)
	}
	if !strings.Contains(compose, "image: "+e2eFrom) {
		t.Errorf("adopted compose does not contain the image:\n%s", compose)
	}
	// Byte-for-byte: this is the file an operator reviews before approving an
	// edit to it.
	onDisk, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if compose != string(onDisk) {
		t.Errorf("adopted content differs from the file on disk:\n%q\nvs\n%q", compose, onDisk)
	}
}

// TestE2EAdoptReportsAMissingDirectory keeps the two failure markers honest
// against a real shell.
func TestE2EAdoptReportsAMissingDirectory(t *testing.T) {
	e2eEnabled(t)
	out, _ := sh(t, adoptScript("/nonexistent/definitely/not/here"))
	if _, err := parseAdopt("/nonexistent/definitely/not/here", out); err == nil {
		t.Fatal("a missing directory was accepted")
	} else if !strings.Contains(err.Error(), "not there") {
		t.Errorf("wrong reason: %v (raw: %q)", err, out)
	}
}

// TestE2EVerifyReadsBackRealDigests is the test that would have caught the tab.
//
// The script's output has to survive a real shell and then parse. A literal
// backslash-t looks fine in the raw output and produces nothing at all here.
func TestE2EVerifyReadsBackRealDigests(t *testing.T) {
	e2eEnabled(t)
	e2eProject(t, e2eFrom)

	out, _ := sh(t, verifyScript(e2eRepo))
	if !strings.Contains(out, "::OK::") {
		t.Fatalf("verify did not report OK:\n%s", out)
	}
	var ref, digest string
	for _, line := range strings.Split(out, "\n") {
		r, d, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if ok && strings.HasPrefix(r, e2eRepo+":") {
			ref, digest = r, d
			break
		}
	}
	if ref == "" {
		t.Fatalf("no TAB-separated image line found — this is exactly the shape of "+
			"the bug that dropped every digest for six releases:\n%s", out)
	}
	if !strings.Contains(digest, "@sha256:") {
		t.Errorf("no digest for %s (got %q); vulnerability scanning and rebuild "+
			"detection both key off this", ref, digest)
	}
}

// TestE2EInPlaceUpdatesOneServiceAndNothingElse runs the rebuild path for real.
func TestE2EInPlaceUpdatesOneServiceAndNothingElse(t *testing.T) {
	e2eEnabled(t)
	dir := e2eProject(t, e2eFrom)

	out, code := sh(t, inPlaceScript(dir, "probe"))
	if code != 0 {
		t.Fatalf("in-place failed (%d): %s", code, inPlaceFailure(dir, "probe", out))
	}
	if !running(t, dir, "probe") {
		t.Error("the service is not running after an in-place update")
	}
}

func TestE2EInPlaceRefusesAProjectItCannotSee(t *testing.T) {
	e2eEnabled(t)
	dir := t.TempDir() // no compose file here
	out, code := sh(t, inPlaceScript(dir, "probe"))
	if code == 0 {
		t.Fatal("acted on a directory holding no compose project")
	}
	if msg := inPlaceFailure(dir, "probe", out); !strings.Contains(msg, "no compose project is readable") {
		t.Errorf("unhelpful reason: %s", msg)
	}
}

// TestE2EFullVersionBump is the operator's actual journey: a running container on
// an old tag, no stack, and a rollout that has to end with the new one running.
func TestE2EFullVersionBump(t *testing.T) {
	e2eEnabled(t)
	dir := e2eProject(t, e2eFrom)

	// 1. Adopt the host's compose file.
	out, _ := sh(t, adoptScript(dir))
	compose, err := parseAdopt(dir, out)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	// 2. It must name what is running.
	if !ReferencesImage(compose, e2eRepo, "3.20") {
		t.Fatalf("adopted file does not name %s:3.20:\n%s", e2eRepo, compose)
	}
	// 3. Rewrite to the target.
	rewritten, n := RewriteImageTag(compose, e2eRepo, "3.20", "3.21")
	if n != 1 {
		t.Fatalf("rewrote %d lines, want 1", n)
	}
	// 4. Deploy it, narrowed to the one service.
	out, code := sh(t, stacks.RenderScript(dir, rewritten, 2, true, "probe"))
	if code != 0 {
		t.Fatalf("deploy failed (%d):\n%s", code, out)
	}
	// 5. Read back what is ACTUALLY running — the whole point of the feature.
	out, _ = sh(t, verifyScript(e2eRepo))
	if !strings.Contains(out, e2eRepo+":3.21") {
		t.Fatalf("after the rollout the host is not running %s:3.21:\n%s", e2eRepo, out)
	}
	if strings.Contains(out, e2eRepo+":3.20") {
		t.Error("the old image is still running")
	}
	// 6. And the file on disk is the rewritten one, so the change survives.
	onDisk, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if !strings.Contains(string(onDisk), e2eRepo+":3.21") {
		t.Errorf("the compose file was not updated on the host:\n%s", onDisk)
	}
}

func running(t *testing.T, dir, service string) bool {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		cmd := exec.Command("docker", "compose", "ps", "--format", "{{.Service}} {{.State}}")
		cmd.Dir = dir
		out, _ := cmd.CombinedOutput()
		if strings.Contains(string(out), service+" running") {
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

// TestE2EComposeAlreadyAtTarget is the case a live rollout kept failing on.
//
// The compose file had already been edited to the new tag — by hand, or by an
// earlier attempt — while the container was still RUNNING the old one, because
// nobody had run `up -d` since. So:
//
//	compose says     curlimages/curl:8.22.0
//	container runs   curlimages/curl:8.10.1
//	rollout wants    8.10.1 -> 8.22.0
//
// Adoption asked whether the file named 8.10.1. It did not, so it refused with
// "the compose file does not name curlimages/curl:8.10.1, so it is not the
// project this container came from" — which was the wrong conclusion. It IS the
// project; the file is simply already where the rollout wants to get to, and the
// work left is to deploy it.
//
// This is not an edge case. It is the state every partially-applied change is in.
func TestE2EComposeAlreadyAtTarget(t *testing.T) {
	e2eEnabled(t)
	// Running the OLD image.
	dir := e2eProject(t, e2eFrom)
	// File edited ahead to the NEW one, without a deploy.
	path := filepath.Join(dir, "docker-compose.yml")
	b, _ := os.ReadFile(path)
	ahead := strings.ReplaceAll(string(b), e2eFrom, e2eTo)
	if err := os.WriteFile(path, []byte(ahead), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _ := sh(t, adoptScript(dir))
	compose, err := parseAdopt(dir, out)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}

	// What the engine decides. It must recognise this project as the right one.
	if !composeOwnsImage(compose, e2eRepo, "3.20", "3.21") {
		t.Fatal("the engine does not recognise a compose file already at the target " +
			"as belonging to this container, so the rollout refuses and the host is " +
			"left running the old image forever")
	}

	// And the rewrite is a no-op, so deploying it is the whole remaining job.
	rewritten, n := RewriteImageTag(compose, e2eRepo, "3.20", "3.21")
	if n != 0 {
		t.Errorf("expected nothing to rewrite, changed %d", n)
	}
	if _, code := sh(t, stacks.RenderScript(dir, rewritten, 2, true, "probe")); code != 0 {
		t.Fatal("deploy failed")
	}
	out, _ = sh(t, verifyScript(e2eRepo))
	if !strings.Contains(out, e2eRepo+":3.21") {
		t.Fatalf("host is not running the target after the rollout:\n%s", out)
	}
}

// --- the engine itself, against a real daemon -------------------------------
//
// The tests above prove each script agrees with its parser. They cannot catch a
// fault in the ORDER the engine does things — adopt, rewrite, save, deploy,
// verify, record — and that is where the rest of the failures lived: a resume
// that never retried, a host marked verified on a deploy's exit code, a version
// bump refused because only one tag was considered.
//
// So: the real Engine, the real scripts, a real Docker. Only the store is a
// fake, because a Postgres is not what these mistakes are made of.

// realRunner runs the engine's scripts locally, exactly as a host would.
type realRunner struct {
	mu      sync.Mutex
	scripts []string
}

func (r *realRunner) RunScript(_ context.Context, script string, _ *models.Host) (string, int, bool) {
	r.mu.Lock()
	r.scripts = append(r.scripts, script)
	r.mu.Unlock()
	out, code := shRun(script)
	return out, code, code != 0
}

// shRun runs a script the way the PRODUCT does, not merely the way a shell does.
//
// internal/command appends "\n[exit code N]" to every result it returns. The
// harness previously returned the raw shell output, so it modelled the host
// faithfully and stubbed the runner — and the runner is what broke: adoption took
// "everything after the marker" as the compose file, swallowed that trailing
// line, and wrote it to a real host where it is not YAML.
//
// A harness that does not reproduce every party in the chain cannot catch a
// disagreement between them. This reproduces the runner.
func shRun(script string) (string, int) {
	cmd := exec.Command("/bin/sh", "-c", script)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	return string(out) + fmt.Sprintf("\n[exit code %d]", code), code
}

// realDeployer performs the actual stack deploy with the real script.
type realDeployer struct {
	dir      string
	compose  func() string
	services []string
}

func (d *realDeployer) DeployPulling(ctx context.Context, id uuid.UUID) (*store.ContainerStack, string, error) {
	return d.DeployPullingService(ctx, id, "")
}

func (d *realDeployer) DeployPullingService(_ context.Context, _ uuid.UUID, service string) (*store.ContainerStack, string, error) {
	d.services = append(d.services, service)
	out, code := shRun(stacks.RenderScript(d.dir, d.compose(), 1, true, service))
	if code != 0 {
		return nil, out, fmt.Errorf("deploy exited %d", code)
	}
	return nil, out, nil
}

// TestE2EEngineDrivesAVersionBumpToCompletion is the operator's whole journey,
// run by the engine that actually ships.
func TestE2EEngineDrivesAVersionBumpToCompletion(t *testing.T) {
	e2eEnabled(t)
	dir := e2eProject(t, e2eFrom)

	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.rollouts[0].Repository, f.rollouts[0].FromTag, f.rollouts[0].ToTag = e2eRepo, "3.20", "3.21"
	f.stacks[ids[0]] = nil // nothing adopted: the operator has not done anything
	f.containers[ids[0]] = []models.Container{{
		Name: "probe", Image: e2eFrom, Repository: e2eRepo, Tag: "3.20",
		ComposeProject: filepath.Base(dir), ComposeService: "probe", ComposeDir: dir,
	}}

	dep := &realDeployer{dir: dir, compose: func() string {
		if len(f.saved) == 0 {
			return ""
		}
		return f.saved[len(f.saved)-1]
	}}
	e := New(f, dep, &realRunner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.Tick(context.Background())

	h := f.hosts[rid][0]
	if h.State != store.UpdateHostVerified {
		t.Fatalf("host state = %q: %s", h.State, h.Error)
	}
	// Verified must mean the daemon is running the target, not that a script
	// exited zero.
	out, _ := shRun(verifyScript(e2eRepo))
	if !strings.Contains(out, e2eRepo+":3.21") {
		t.Errorf("engine reported verified, but the host runs:\n%s", out)
	}
	// The compose file on disk carries the change, so it survives a restart.
	onDisk, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if !strings.Contains(string(onDisk), e2eRepo+":3.21") {
		t.Errorf("the host's compose file was not updated:\n%s", onDisk)
	}
	// And only the service being updated was touched.
	if len(dep.services) != 1 || dep.services[0] != "probe" {
		t.Errorf("deployed services = %v, want exactly [probe]", dep.services)
	}
}

// TestE2EEngineFinishesAHalfAppliedChange is the state a failed rollout leaves
// behind, and the one a live instance was stuck in.
func TestE2EEngineFinishesAHalfAppliedChange(t *testing.T) {
	e2eEnabled(t)
	dir := e2eProject(t, e2eFrom)
	// The file is already at the target; the container is not.
	path := filepath.Join(dir, "docker-compose.yml")
	b, _ := os.ReadFile(path)
	_ = os.WriteFile(path, []byte(strings.ReplaceAll(string(b), e2eFrom, e2eTo)), 0o644)

	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.rollouts[0].Repository, f.rollouts[0].FromTag, f.rollouts[0].ToTag = e2eRepo, "3.20", "3.21"
	f.stacks[ids[0]] = nil
	f.containers[ids[0]] = []models.Container{{
		Name: "probe", Image: e2eFrom, Repository: e2eRepo, Tag: "3.20",
		ComposeProject: filepath.Base(dir), ComposeService: "probe", ComposeDir: dir,
	}}

	dep := &realDeployer{dir: dir, compose: func() string {
		if len(f.saved) == 0 {
			// Nothing was rewritten, because the file was already correct. The
			// deploy still has to happen, with the file as adopted.
			out, _ := shRun(adoptScript(dir))
			c, _ := parseAdopt(dir, out)
			return c
		}
		return f.saved[len(f.saved)-1]
	}}
	e := New(f, dep, &realRunner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.Tick(context.Background())

	if got := f.hosts[rid][0].State; got != store.UpdateHostVerified {
		t.Fatalf("a rollout could not finish a change it had itself half-applied: "+
			"state = %q, error = %q", got, f.hosts[rid][0].Error)
	}
	out, _ := shRun(verifyScript(e2eRepo))
	if !strings.Contains(out, e2eRepo+":3.21") {
		t.Errorf("host is not on the target:\n%s", out)
	}
}

// TestE2EABrokenComposeNeverReachesTheHost is the guarantee that would have
// stopped four failed rollouts from leaving a host worse than they found it.
//
// A deploy writes whatever the stack record holds, and a stack record is only as
// good as what went into it. One went in bad — an adoption swallowed the command
// runner's trailing "[exit code 0]" line — and because the deploy never looked at
// what it was writing, every attempt rewrote the same broken file onto the host:
//
//	qdrant_data:
//
//	[exit code 0]
//	  go-yaml load error: could not find expected ':'
//
// Fixing the intake stopped NEW damage and did nothing for the record already
// poisoned. The host stayed broken across three more attempts. So the deploy
// refuses to be the thing that breaks a host, whatever it is handed.
func TestE2EABrokenComposeNeverReachesTheHost(t *testing.T) {
	e2eEnabled(t)
	dir := e2eProject(t, e2eFrom)
	path := filepath.Join(dir, "docker-compose.yml")
	good, _ := os.ReadFile(path)

	// Exactly the shape that reached a live host.
	broken := string(good) + "\n[exit code 0]\n"

	out, code := sh(t, stacks.RenderScript(dir, broken, 3, false, "probe"))
	if code == 0 {
		t.Fatal("a compose file that does not parse was deployed")
	}
	if !strings.Contains(out, "::BADCOMPOSE::") {
		t.Errorf("the failure does not say the compose was rejected:\n%s", out)
	}

	// And the host is left as it was, not half-written.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the compose file is gone entirely: %v", err)
	}
	if string(after) != string(good) {
		t.Errorf("the host's compose file was left modified:\n--- got ---\n%s\n--- want ---\n%s",
			after, good)
	}
	// It still parses, which is the property that actually matters to an operator.
	cfg := exec.Command("docker", "compose", "config", "-q")
	cfg.Dir = dir
	if outB, err := cfg.CombinedOutput(); err != nil {
		t.Errorf("the host is left with an unparseable compose file: %v\n%s", err, outB)
	}
}

// And the same through the engine, since that is the path that failed.
func TestE2EEngineDoesNotBreakAHostWithABadStackRecord(t *testing.T) {
	e2eEnabled(t)
	dir := e2eProject(t, e2eFrom)
	path := filepath.Join(dir, "docker-compose.yml")
	good, _ := os.ReadFile(path)

	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.rollouts[0].Repository, f.rollouts[0].FromTag, f.rollouts[0].ToTag = e2eRepo, "3.20", "3.21"
	// A stack already adopted, holding poisoned content.
	f.stacks[ids[0]] = []store.ContainerStack{{
		ID: uuid.New(), HostID: ids[0], Enabled: true, Name: filepath.Base(dir), Path: dir,
		Compose: strings.ReplaceAll(string(good), e2eFrom, e2eTo) + "\n[exit code 0]\n",
	}}
	f.containers[ids[0]] = []models.Container{{
		Name: "probe", Image: e2eFrom, Repository: e2eRepo, Tag: "3.20",
		ComposeProject: filepath.Base(dir), ComposeService: "probe", ComposeDir: dir,
	}}

	dep := &realDeployer{dir: dir, compose: func() string { return f.stacks[ids[0]][0].Compose }}
	e := New(f, dep, &realRunner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.Tick(context.Background())

	if got := f.hosts[rid][0].State; got != store.UpdateHostFailed {
		t.Errorf("state = %q — a rollout that could not deploy must not report success", got)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(good) {
		t.Errorf("the rollout left the host's compose file broken:\n%s", after)
	}
}

// TestE2EANetworkNamespaceDependentIsBroughtAlong proves the fix against a real
// daemon, because "the container is running" and "the container has a network"
// are different things and only one of them is visible in `docker ps`.
func TestE2EANetworkNamespaceDependentIsBroughtAlong(t *testing.T) {
	e2eEnabled(t)
	dir := t.TempDir()
	compose := `services:
  net:
    image: ` + e2eFrom + `
    command: ["sleep", "600"]
  rider:
    image: ` + e2eFrom + `
    command: ["sleep", "600"]
    network_mode: "service:net"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	up := exec.Command("docker", "compose", "up", "-d")
	up.Dir = dir
	if out, err := up.CombinedOutput(); err != nil {
		t.Fatalf("compose up: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		down := exec.Command("docker", "compose", "down", "-v", "--remove-orphans")
		down.Dir = dir
		_ = down.Run()
	})

	namespaceOf := func(service string) string {
		id := exec.Command("docker", "compose", "ps", "-q", service)
		id.Dir = dir
		b, _ := id.Output()
		cid := strings.TrimSpace(string(b))
		ins := exec.Command("docker", "inspect", cid, "--format", "{{.HostConfig.NetworkMode}}")
		out, _ := ins.Output()
		return strings.TrimSpace(string(out))
	}
	before := namespaceOf("rider")

	// Recreate the namespace owner, exactly as a rollout would.
	updated := strings.Replace(compose, e2eFrom, e2eTo, 1)
	if out, code := sh(t, stacks.RenderScript(dir, updated, 2, true, "net")); code != 0 {
		t.Fatalf("deploy failed (%d):\n%s", code, out)
	}

	after := namespaceOf("rider")
	if after == before {
		t.Fatal("the dependent was not recreated, so it is still attached to the " +
			"namespace of a container that no longer exists — running, healthy, " +
			"and with no network")
	}
	// And it points at the NEW owner.
	ownerID := exec.Command("docker", "compose", "ps", "-q", "net")
	ownerID.Dir = dir
	b, _ := ownerID.Output()
	if want := "container:" + strings.TrimSpace(string(b)); after != want {
		t.Errorf("dependent namespace = %s, want %s", after, want)
	}
}
