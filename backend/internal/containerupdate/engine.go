package containerupdate

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/pacing"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// Store is the slice of the store the engine needs.
type Store interface {
	ActiveUpdateRollouts(ctx context.Context) ([]store.UpdateRollout, error)
	UpdateRolloutHosts(ctx context.Context, id uuid.UUID) ([]store.UpdateRolloutHost, error)
	ClaimUpdateRolloutHost(ctx context.Context, rollout, host uuid.UUID) (bool, error)
	SetUpdateRolloutHostState(ctx context.Context, rollout, host uuid.UUID, state, errMsg string) error
	SetUpdateRolloutState(ctx context.Context, id uuid.UUID, state, reason string) error
	StampUpdateRolloutCanaryDone(ctx context.Context, id uuid.UUID, at time.Time) error
	ListStacks(ctx context.Context, hostID *uuid.UUID) ([]store.ContainerStack, error)
	UpsertStack(ctx context.Context, in store.StackInput) (*store.ContainerStack, error)
	GetHost(ctx context.Context, id uuid.UUID) (*models.Host, error)
}

// Deployer applies a stack to its host, pulling images first.
type Deployer interface {
	DeployPulling(ctx context.Context, stackID uuid.UUID) (*store.ContainerStack, string, error)
}

// Runner executes a script on a host, for the verification read-back.
type Runner interface {
	RunScript(ctx context.Context, script string, h *models.Host) (output string, exitCode int, failed bool)
}

// MaxAttempts is how many times one host may be started before it counts as
// failed. A host that takes the work and does not finish three times is not
// going to.
const MaxAttempts = 3

type Engine struct {
	store Store
	dep   Deployer
	run   Runner
	log   *slog.Logger
	now   func() time.Time
}

func New(st Store, dep Deployer, run Runner, log *slog.Logger) *Engine {
	return &Engine{store: st, dep: dep, run: run, log: log, now: time.Now}
}

// Run drives rollouts forward on a tick.
//
// leader gates the loop the same way the monitor sweep is gated: in a
// multi-instance deployment only one instance should be reaching out, or every
// host gets N simultaneous deploys writing the same compose file.
//
// Nothing runs at all unless a rollout is live. This is not a periodic sweep of
// the fleet; it is a response to an operator having started something.
func (e *Engine) Run(ctx context.Context, leader func() bool) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if leader == nil || leader() {
				e.Tick(ctx)
			}
		}
	}
}

// Tick advances every running rollout by as much as its rules allow.
func (e *Engine) Tick(ctx context.Context) {
	rollouts, err := e.store.ActiveUpdateRollouts(ctx)
	if err != nil {
		e.log.Warn("update rollouts: listing", "err", err)
		return
	}
	for _, r := range rollouts {
		if ctx.Err() != nil {
			return
		}
		e.advance(ctx, r)
	}
}

func (e *Engine) advance(ctx context.Context, r store.UpdateRollout) {
	now := e.now()
	hosts, err := e.store.UpdateRolloutHosts(ctx, r.ID)
	if err != nil {
		e.log.Warn("update rollout: listing hosts", "rollout", r.ID, "err", err)
		return
	}

	var flying, verified, failed, pending int
	for _, h := range hosts {
		switch h.State {
		case store.UpdateHostApplying:
			flying++
		case store.UpdateHostVerified:
			verified++
		case store.UpdateHostFailed:
			// Forgiven failures are ones an operator has already looked at and
			// resumed past. Counting them again re-halts the rollout immediately.
			if !h.Forgiven {
				failed++
			}
		case store.UpdateHostPending:
			pending++
		}
	}

	// The moment the canary phase finished, stamped once. The soak runs from
	// here; see StampUpdateRolloutCanaryDone.
	if r.Canary > 0 && r.CanaryDoneAt == nil && verified >= r.Canary {
		if err := e.store.StampUpdateRolloutCanaryDone(ctx, r.ID, now); err != nil {
			e.log.Warn("update rollout: stamping canary", "rollout", r.ID, "err", err)
		}
		at := now
		r.CanaryDoneAt = &at
	}

	strategy := pacing.Strategy{
		Canary: r.Canary, BatchSize: r.BatchSize,
		SoakSeconds: r.SoakSeconds, MaxFailures: r.MaxFailures,
	}

	// The budget is checked before anything else starts. Checking after would
	// send this tick's batch to hosts under a rollout that has already failed.
	if pacing.BudgetExceeded(strategy, failed) {
		reason := fmt.Sprintf("%d host(s) failed; the rollout stopped on its own.", failed)
		if err := e.store.SetUpdateRolloutState(ctx, r.ID, store.UpdateRolloutHalted, reason); err != nil {
			e.log.Warn("update rollout: halting", "rollout", r.ID, "err", err)
		}
		e.log.Warn("update rollout halted", "rollout", r.ID,
			"repository", r.Repository, "failed", failed)
		return
	}

	if pending == 0 && flying == 0 {
		if err := e.store.SetUpdateRolloutState(ctx, r.ID, store.UpdateRolloutCompleted, ""); err != nil {
			e.log.Warn("update rollout: completing", "rollout", r.ID, "err", err)
		}
		return
	}

	var window *pacing.Window
	if r.WindowStart != nil && r.WindowEnd != nil {
		days := make([]int, 0, len(r.WindowDays))
		for _, d := range r.WindowDays {
			days = append(days, int(d))
		}
		window = &pacing.Window{Start: *r.WindowStart, End: *r.WindowEnd, Days: days}
	}
	if !pacing.InWindow(window, now) {
		return
	}

	capacity := pacing.Capacity(strategy, flying, verified, r.CanaryDoneAt, now)
	if capacity <= 0 {
		return
	}

	// Claim first, then apply concurrently. A batch size of five means five hosts
	// moving at once -- applied one after another it would be an ordinary
	// sequence with a cap, and a fleet of any size would take hours of wall clock
	// to do what the operator asked to happen in one batch.
	//
	// Claiming is still serial and still conditional, so two overlapping ticks
	// cannot both take the same host: for a compose file that means two writers
	// racing on one path.
	claimed := make([]uuid.UUID, 0, capacity)
	for _, h := range hosts {
		if capacity <= 0 || ctx.Err() != nil {
			break
		}
		if h.State != store.UpdateHostPending {
			continue
		}
		if h.Attempts >= MaxAttempts {
			e.fail(ctx, r.ID, h.HostID, fmt.Sprintf("gave up after %d attempts", h.Attempts))
			continue
		}
		got, err := e.store.ClaimUpdateRolloutHost(ctx, r.ID, h.HostID)
		if err != nil {
			e.log.Warn("update rollout: claiming host", "host", h.HostID, "err", err)
			continue
		}
		if !got {
			continue // somebody else took it
		}
		capacity--
		claimed = append(claimed, h.HostID)
	}

	var wg sync.WaitGroup
	for _, hostID := range claimed {
		wg.Add(1)
		go func(hostID uuid.UUID) {
			defer wg.Done()
			e.apply(ctx, r, hostID)
		}(hostID)
	}
	wg.Wait()
}

// apply moves one host onto the target image.
func (e *Engine) apply(ctx context.Context, r store.UpdateRollout, hostID uuid.UUID) {
	stack, compose, err := e.targetStack(ctx, r, hostID)
	if err != nil {
		e.fail(ctx, r.ID, hostID, err.Error())
		return
	}

	// Only save a new revision when the text actually changed. A digest-only
	// update -- the same tag rebuilt -- rewrites nothing, and writing an
	// identical revision would fill the history with entries that record no
	// change while claiming one.
	if compose != stack.Compose {
		_, err := e.store.UpsertStack(ctx, store.StackInput{
			HostID: stack.HostID, Name: stack.Name, Path: stack.Path, Compose: compose,
			Note: fmt.Sprintf("%s:%s → %s (rollout)", r.Repository, r.FromTag, r.ToTag),
			// No AuthorID: the rollout wrote this revision, not a person. Naming
			// the operator who started the rollout as the author of a file they
			// never saw would make the history say something untrue.
			AuthorName: "container update rollout",
		})
		if err != nil {
			e.fail(ctx, r.ID, hostID, "could not record the new compose: "+err.Error())
			return
		}
	}

	if _, out, err := e.dep.DeployPulling(ctx, stack.ID); err != nil {
		e.fail(ctx, r.ID, hostID, trimOutput(err.Error()+"\n"+out))
		return
	}

	// Verified means the host is RUNNING the target, not that the deploy command
	// exited zero. A compose file that applies perfectly and leaves the container
	// on the old image is the exact failure this rollout exists to catch, and a
	// rollout that counted the exit code would march a no-op across the fleet
	// while reporting every host as updated.
	if err := e.verify(ctx, r, hostID); err != nil {
		e.fail(ctx, r.ID, hostID, err.Error())
		return
	}
	if err := e.store.SetUpdateRolloutHostState(ctx, r.ID, hostID, store.UpdateHostVerified, ""); err != nil {
		e.log.Warn("update rollout: recording success", "host", hostID, "err", err)
	}
}

// targetStack finds the managed stack on a host that names the image, and
// returns it with the rewritten compose.
func (e *Engine) targetStack(ctx context.Context, r store.UpdateRollout, hostID uuid.UUID) (*store.ContainerStack, string, error) {
	stacks, err := e.store.ListStacks(ctx, &hostID)
	if err != nil {
		return nil, "", fmt.Errorf("could not list this host's stacks: %w", err)
	}
	for i := range stacks {
		st := &stacks[i]
		if !st.Enabled || strings.TrimSpace(st.Compose) == "" {
			continue
		}
		out, n := RewriteImageTag(st.Compose, r.Repository, r.FromTag, r.ToTag)
		if n > 0 {
			return st, out, nil
		}
		// A digest-only update changes no text, so the rewrite finds nothing to
		// do. The stack still owns the image if it names it at the current tag,
		// and pulling is the whole update.
		if r.FromTag == r.ToTag && ReferencesImage(st.Compose, r.Repository, r.FromTag) {
			return st, st.Compose, nil
		}
	}
	// Not an error in the host's behaviour, and worth saying precisely: an
	// operator reading "no managed stack" knows the fix is to adopt the compose
	// file, whereas "deploy failed" sends them to look at docker.
	return nil, "", fmt.Errorf(
		"no Provenance-managed stack on this host names %s:%s — adopt its compose file to make it updatable",
		r.Repository, r.FromTag)
}

// verifyScript reports the digest each running container is using for one
// repository. Same technique as the monitor's collection, narrowed to one image.
func verifyScript(repo string) string {
	return `
_rt=""
if command -v docker >/dev/null 2>&1; then _rt=docker
elif command -v podman >/dev/null 2>&1; then _rt=podman
fi
if [ -z "$_rt" ]; then echo "::NORUNTIME::"; exit 0; fi
echo "::OK::"
$_rt ps --no-trunc --format '{{.Image}}' 2>/dev/null | sort -u | while read -r _i; do
  case "$_i" in
    ` + shellCase(repo) + `) ;;
    *) continue ;;
  esac
  _d=$($_rt image inspect --format '{{index .RepoDigests 0}}' "$_i" 2>/dev/null)
  echo "$_i	$_d"
done
`
}

// shellCase renders a repository as a `case` pattern matching it at any tag.
//
// Glob metacharacters are stripped rather than escaped: a repository name cannot
// contain them, so anything that does is not a repository this should match, and
// a pattern built from it would match more than intended.
func shellCase(repo string) string {
	clean := strings.Map(func(r rune) rune {
		if strings.ContainsRune("*?[]\\'\"`$();|&<>\n", r) {
			return -1
		}
		return r
	}, repo)
	return "'" + clean + ":'*"
}

// verify reads back what the host is actually running.
func (e *Engine) verify(ctx context.Context, r store.UpdateRollout, hostID uuid.UUID) error {
	h, err := e.store.GetHost(ctx, hostID)
	if err != nil {
		return fmt.Errorf("could not read the host back: %w", err)
	}
	out, _, failed := e.run.RunScript(ctx, verifyScript(r.Repository), h)
	if failed || !strings.Contains(out, "::OK::") {
		return fmt.Errorf("deployed, but could not read back what the host is running: %s",
			trimOutput(out))
	}
	want := r.Repository + ":" + r.ToTag
	for _, line := range strings.Split(out, "\n") {
		ref, digest, _ := strings.Cut(strings.TrimSpace(line), "\t")
		if ref != want {
			continue
		}
		if r.TargetDigest == "" {
			return nil // nothing to compare against; running the tag is the answer
		}
		// RepoDigests is "repo@sha256:...", so compare the digest part only.
		if _, d, ok := strings.Cut(digest, "@"); ok && d == r.TargetDigest {
			return nil
		}
		return fmt.Errorf("deployed, but %s is running %s rather than the %s this rollout targets",
			want, shortDigest(digest), shortDigest(r.TargetDigest))
	}
	return fmt.Errorf("deployed, but no container on this host is running %s", want)
}

func (e *Engine) fail(ctx context.Context, rollout, host uuid.UUID, msg string) {
	if err := e.store.SetUpdateRolloutHostState(ctx, rollout, host, store.UpdateHostFailed, msg); err != nil {
		e.log.Warn("update rollout: recording failure", "host", host, "err", err)
	}
	e.log.Warn("update rollout: host failed", "rollout", rollout, "host", host, "detail", msg)
}

func trimOutput(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 600 {
		return "…" + s[len(s)-600:]
	}
	return s
}

func shortDigest(d string) string {
	if i := strings.Index(d, "sha256:"); i >= 0 {
		d = d[i:]
	}
	if len(d) > 19 {
		return d[:19] + "…"
	}
	if d == "" {
		return "(unknown)"
	}
	return d
}
