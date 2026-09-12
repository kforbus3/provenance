package containerupdate

import (
	"context"
	"encoding/json"
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
	HostContainers(ctx context.Context, hostID uuid.UUID) ([]models.Container, error)
	RolloutImages(ctx context.Context, id uuid.UUID) ([]store.RolloutImage, error)
	GetSetting(ctx context.Context, key string) (json.RawMessage, error)
}

// Deployer applies a stack to its host, pulling images first.
type Deployer interface {
	DeployPulling(ctx context.Context, stackID uuid.UUID) (*store.ContainerStack, string, error)
	DeployPullingService(ctx context.Context, stackID uuid.UUID, service string) (*store.ContainerStack, string, error)
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
	// The images this rollout covers, read once for the whole batch rather than
	// per host: they do not change while it runs, and a rollout over a hundred
	// hosts would otherwise ask a hundred times for the same answer.
	images, err := e.store.RolloutImages(ctx, r.ID)
	if err != nil {
		e.log.Warn("update rollout: listing images", "rollout", r.ID, "err", err)
		return
	}
	if len(images) == 0 {
		// A rollout created before images were recorded. Its own columns are the
		// single image it covers.
		images = []store.RolloutImage{{
			Repository: r.Repository, FromTag: r.FromTag,
			ToTag: r.ToTag, TargetDigest: r.TargetDigest,
		}}
	}

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
			e.applyAll(ctx, r, images, hostID)
		}(hostID)
	}
	wg.Wait()
}

// applyAll moves one host onto every image in the rollout that it runs.
//
// A host is the unit, not an image: it is either current or it is not, and a
// fleet half-updated per image is harder to reason about than one updated host
// at a time. An image the host does not run is not a failure — a rollout covering
// ten images rarely has all ten on every host.
//
// The first failure stops this host. Continuing would apply later updates on top
// of a host already known to be in a state nobody intended, and the failure
// budget is about hosts.
func (e *Engine) applyAll(ctx context.Context, r store.UpdateRollout, images []store.RolloutImage, hostID uuid.UUID) {
	containers, err := e.store.HostContainers(ctx, hostID)
	if err != nil {
		e.fail(ctx, r.ID, hostID, "could not read what this host is running: "+err.Error())
		return
	}
	// Never this application's own containers. Checked here as well as when a
	// rollout is created, because a rollout created before this rule existed --
	// or one whose targets changed -- must not be applied by a later tick.
	self := selfProject(ctx, e.store)
	runs := map[string]bool{}
	protected := map[string]string{}
	for _, c := range containers {
		key := c.Repository + ":" + c.Tag
		runs[key] = true
		if isSelfContainer(self, c.ComposeProject, c.Image) {
			protected[key] = c.Name
		}
	}

	applied := 0
	for _, im := range images {
		if ctx.Err() != nil {
			return
		}
		key := im.Repository + ":" + im.FromTag
		if !runs[key] {
			continue
		}
		if name, ok := protected[key]; ok {
			e.fail(ctx, r.ID, hostID, fmt.Sprintf(
				"%s runs %s as part of Provenance itself. This application is upgraded "+
					"by signed bundle — which verifies the signature, backs up the database, "+
					"applies migrations and keeps a rollback — not by replacing its "+
					"containers underneath it.", name, key))
			return
		}
		// Each image is applied as its own single-image operation, so one code
		// path serves both a one-image rollout and a fleet-wide one.
		one := r
		one.Repository, one.FromTag, one.ToTag, one.TargetDigest =
			im.Repository, im.FromTag, im.ToTag, im.TargetDigest
		if err := e.applyOne(ctx, one, hostID); err != nil {
			e.fail(ctx, r.ID, hostID,
				fmt.Sprintf("%s:%s → %s: %s", im.Repository, im.FromTag, im.ToTag, err.Error()))
			return
		}
		applied++
	}

	if applied == 0 {
		// Enrolled but running none of the images by the time its turn came --
		// somebody updated it by hand, or the container was removed. Not a
		// failure, and not a silent success either: skipped says which.
		if err := e.store.SetUpdateRolloutHostState(ctx, r.ID, hostID, store.UpdateHostSkipped,
			"this host was not running any of the images by the time its turn came"); err != nil {
			e.log.Warn("update rollout: recording skip", "host", hostID, "err", err)
		}
		return
	}
	if err := e.store.SetUpdateRolloutHostState(ctx, r.ID, hostID, store.UpdateHostVerified, ""); err != nil {
		e.log.Warn("update rollout: recording success", "host", hostID, "err", err)
	}
}

// applyOne moves one host onto one target image, and reports what went wrong.
//
// Recording the host's state is the CALLER's job: a host in a multi-image
// rollout is not verified until every image that applies to it is.
func (e *Engine) applyOne(ctx context.Context, r store.UpdateRollout, hostID uuid.UUID) error {
	stack, compose, err := e.targetStack(ctx, r, hostID)
	if err != nil {
		// No stack holds this image. For an update that does not need the compose
		// file CHANGED -- a moved tag, the same version rebuilt -- the container's
		// own compose project is enough, and asking an operator to adopt a file
		// just to pull a rebuilt image is work for nothing.
		applied, ierr := e.applyInPlace(ctx, r, hostID)
		if applied {
			if ierr != nil {
				return ierr
			}
			return e.verify(ctx, r, hostID)
		}

		// A version bump. The new version has to be written into the compose file,
		// so adopt the host's own file and carry on as a stack — the edit then has
		// an author, a note, a revision and a rollback, which an edit made to a
		// file nobody owns would not.
		adopted, aerr := e.adopt(ctx, r, hostID)
		if aerr != nil {
			return aerr
		}
		if !adopted {
			return err
		}
		stack, compose, err = e.targetStack(ctx, r, hostID)
		if err != nil {
			return err
		}
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
			return fmt.Errorf("could not record the new compose: %w", err)
		}
	}

	// Narrowed to the service that runs this image. Bringing up the whole project
	// would restart everything beside it — on a host running a model server and a
	// vector database, updating curl would have restarted both.
	service := e.composeServiceFor(ctx, r, hostID)
	if _, out, err := e.dep.DeployPullingService(ctx, stack.ID, service); err != nil {
		return fmt.Errorf("%s", trimOutput(err.Error()+"\n"+out))
	}

	// Verified means the host is RUNNING the target, not that the deploy command
	// exited zero. A compose file that applies perfectly and leaves the container
	// on the old image is the exact failure this rollout exists to catch, and a
	// rollout that counted the exit code would march a no-op across the fleet
	// while reporting every host as updated.
	return e.verify(ctx, r, hostID)
}

// composeServiceFor returns the compose service running this image on a host, or
// "" when it cannot be established.
//
// Empty means "the whole project", which is the old behaviour and the safe
// fallback: a deploy that touches more than it needed is recoverable, and one
// that touches nothing because a name was guessed wrong is an update reported as
// applied that never happened.
func (e *Engine) composeServiceFor(ctx context.Context, r store.UpdateRollout, hostID uuid.UUID) string {
	containers, err := e.store.HostContainers(ctx, hostID)
	if err != nil {
		return ""
	}
	for _, c := range containers {
		if c.Repository == r.Repository && c.Tag == r.FromTag && c.ComposeService != "" {
			return c.ComposeService
		}
	}
	return ""
}

// adopt reads the host's compose file for this image and records it as a stack.
//
// Reports whether adoption applies at all, and if so whether it worked. It
// applies only when the container names a compose project — a plain `docker run`
// container has no file to adopt, and reproducing its arguments is the guessing
// this product does not do.
func (e *Engine) adopt(ctx context.Context, r store.UpdateRollout, hostID uuid.UUID) (bool, error) {
	containers, err := e.store.HostContainers(ctx, hostID)
	if err != nil {
		return false, nil
	}
	var match *models.Container
	for i := range containers {
		c := &containers[i]
		if c.Repository == r.Repository && c.Tag == r.FromTag && c.ComposeDir != "" {
			match = c
			break
		}
	}
	if match == nil {
		return false, nil
	}
	h, err := e.store.GetHost(ctx, hostID)
	if err != nil {
		return true, fmt.Errorf("could not read the host: %w", err)
	}
	out, _, failed := e.run.RunScript(ctx, adoptScript(match.ComposeDir), h)
	if failed {
		return true, fmt.Errorf("could not read the compose file at %s: %s",
			match.ComposeDir, trimOutput(out))
	}
	compose, perr := parseAdopt(match.ComposeDir, out)
	if perr != nil {
		return true, perr
	}
	// The file has to name the image this rollout is about. If it does not, the
	// project at that path is not the one this container came from, and rewriting
	// it would edit somebody else's stack.
	if !ReferencesImage(compose, r.Repository, r.FromTag) {
		return true, fmt.Errorf(
			"the compose file at %s/%s does not name %s:%s, so it is not the project "+
				"this container came from", match.ComposeDir, composeFilename,
			r.Repository, r.FromTag)
	}

	name := match.ComposeProject
	if name == "" {
		name = match.ComposeService
	}
	if _, err := e.store.UpsertStack(ctx, store.StackInput{
		HostID: hostID, Name: name, Path: match.ComposeDir, Compose: compose,
		Note: fmt.Sprintf("adopted from the host to apply %s:%s → %s",
			r.Repository, r.FromTag, r.ToTag),
		AuthorName: "container update rollout",
	}); err != nil {
		return true, fmt.Errorf("could not adopt the compose file: %w", err)
	}
	e.log.Info("adopted a compose file from the host",
		"host", h.Hostname, "project", name, "dir", match.ComposeDir,
		"reason", fmt.Sprintf("%s:%s → %s", r.Repository, r.FromTag, r.ToTag))
	return true, nil
}

// applyInPlace updates a container through its own compose project.
//
// Returns whether this path applies at all, and if so whether it worked. It
// applies only when the compose file does not need to change: a version bump is
// written INTO that file, and editing a file Provenance does not own is a
// different decision -- on a host whose compose files are deployed from a git
// repo or an rsync target, the edit is reverted on the next deploy, silently.
func (e *Engine) applyInPlace(ctx context.Context, r store.UpdateRollout, hostID uuid.UUID) (bool, error) {
	if r.FromTag != r.ToTag {
		return false, nil // a version bump needs the file changed; not this path
	}
	containers, err := e.store.HostContainers(ctx, hostID)
	if err != nil {
		return false, nil // fall back to the stack message rather than invent one
	}
	var match *models.Container
	for i := range containers {
		c := &containers[i]
		if c.Repository == r.Repository && c.Tag == r.FromTag &&
			c.ComposeDir != "" && c.ComposeService != "" {
			match = c
			break
		}
	}
	if match == nil {
		return false, nil
	}

	h, err := e.store.GetHost(ctx, hostID)
	if err != nil {
		return true, fmt.Errorf("could not read the host: %w", err)
	}
	out, code, failed := e.run.RunScript(ctx, inPlaceScript(match.ComposeDir, match.ComposeService), h)
	if failed || code != 0 {
		return true, fmt.Errorf("%s", inPlaceFailure(match.ComposeDir, match.ComposeService, out))
	}
	e.log.Info("container updated in place",
		"host", h.Hostname, "project", match.ComposeProject,
		"service", match.ComposeService, "dir", match.ComposeDir)
	return true, nil
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
		"no Provenance-managed stack on this host names %s:%s, and this is a version "+
			"change rather than a rebuild — the new version has to be written into a "+
			"compose file, so adopt this host's compose file as a stack to make it "+
			"updatable. Rebuilds of the same tag do not need that.",
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
