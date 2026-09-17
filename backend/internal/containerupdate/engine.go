package containerupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/composefile"
	"github.com/kforbus3/provenance/backend/internal/hostexec"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/monitor"
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
	UpdateHostContainers(ctx context.Context, hostID uuid.UUID, inv models.HostInventory) error
	RolloutImages(ctx context.Context, id uuid.UUID) ([]store.RolloutImage, error)
	InvalidateImageCheck(ctx context.Context, repository, tag string) error
	GetSetting(ctx context.Context, key string) (json.RawMessage, error)
}

// Deployer applies a stack to its host, pulling images first.
type Deployer interface {
	DeployPulling(ctx context.Context, stackID uuid.UUID) (*store.ContainerStack, string, error)
	DeployPullingService(ctx context.Context, stackID uuid.UUID, services ...string) (*store.ContainerStack, string, error)
}

// Runner executes a script on a host, for the verification read-back.
type Runner interface {
	RunScript(ctx context.Context, script string, h *models.Host) (output string, exitCode int, failed bool)
}

// errSuperseded means the host is running this repository at some other tag, so
// the rollout's premise has expired for it.
//
// Distinguished from a failure because it is not one. A host that has been
// re-pinned since the rollout was created has moved past the image, and treating
// that as a failure halts the whole operation on its budget for something nobody
// did wrong.
var errSuperseded = errors.New("the host is running this repository at another tag")

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
	// What this host's compose files currently say. A rollout is created from a
	// snapshot of what the fleet was running; by the time it reaches a given host
	// that host may have been re-pinned, and an image it has moved past should be
	// skipped rather than attempted and failed.
	stacks, _ := e.store.ListStacks(ctx, &hostID)

	// Never this application's own containers. Checked here as well as when a
	// rollout is created, because a rollout created before this rule existed --
	// or one whose targets changed -- must not be applied by a later tick.
	self := selfProject(ctx, e.store)
	runs := map[string]bool{}
	protected := map[string]string{}
	runsRepo := map[string]bool{}
	// What is actually RUNNING, kept separate from what `runs` grows to mean once
	// compose files widen it. See applies.
	containerRuns := map[string]bool{}
	for _, c := range containers {
		key := c.Repository + ":" + c.Tag
		runs[key] = true
		containerRuns[key] = true
		runsRepo[c.Repository] = true
		if isSelfContainer(self, c.ComposeProject, c.Image) {
			protected[key] = c.Name
		}
	}
	// A tag this host's compose file NAMES counts as one it runs.
	//
	// Pinning a compose file to the version a container is already on recreates
	// nothing, so between the pin and the next deploy the file says
	// bazarr:v1.6.0-ls356 while the container is still on :latest. The registry
	// check follows the file -- that is the version an operator chose, and the
	// only one a newer version can be found against -- so a rollout built from it
	// arrives here naming a from-tag no container is running. Matching only the
	// running tag would skip every host and offer an update that can never be
	// applied.
	//
	// Restricted to repositories this host actually runs: a compose file may name
	// a service that is not up, and deploying one because a rollout mentioned it
	// would start something nobody asked to start.
	declared := map[string]bool{}
	for i := range stacks {
		st := &stacks[i]
		if !st.Enabled {
			continue
		}
		for _, ref := range composefile.Images(st.Compose) {
			if runsRepo[ref.Repository] {
				runs[ref.Repository+":"+ref.Tag] = true
				declared[ref.Repository+":"+ref.Tag] = true
			}
		}
	}

	// applies reports whether this rollout still has work to do on this host.
	//
	// The from-tag is the ordinary answer. The second case is a rollout whose own
	// first half already landed: it rewrote the compose file to the target and
	// then failed before deploying, so the file names the TARGET, no container
	// runs either tag, and the from-tag it is looking for exists nowhere. Seven
	// rollouts resumed into that state and reported "this host was not running
	// any of the images by the time its turn came" — about a host where every one
	// of them still had a container to recreate.
	//
	// Only while no container is running the target yet: once one is, the work is
	// genuinely done and re-deploying would restart a service for nothing.
	applies := func(im store.RolloutImage) bool {
		if runs[im.Repository+":"+im.FromTag] {
			return true
		}
		to := im.Repository + ":" + im.ToTag
		return declared[to] && !containerRuns[to]
	}

	applied, ran, past := 0, 0, 0
	for _, im := range images {
		if ctx.Err() != nil {
			return
		}
		key := im.Repository + ":" + im.FromTag
		if !applies(im) {
			continue
		}
		ran++
		if superseded(stacks, im) {
			past++
			e.log.Info("update rollout: host has moved past this image",
				"host", hostID, "repository", im.Repository, "from", im.FromTag)
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
		// Refused here as well as when the rollout is created, for the same reason
		// the rule above is: a rollout created before this existed must not be
		// applied by a later tick.
		if how, yes := isStatefulMajorBump(im.Repository, im.FromTag, im.ToTag); yes {
			e.fail(ctx, r.ID, hostID, fmt.Sprintf(
				"%s %s → %s crosses a major version. This image owns its on-disk format: "+
					"the new version refuses the existing data directory and the container "+
					"restarts forever with the service down. It needs %s first, with both "+
					"versions available — which a container rollout cannot do.",
				im.Repository, im.FromTag, im.ToTag, how))
			return
		}
		// Each image is applied as its own single-image operation, so one code
		// path serves both a one-image rollout and a fleet-wide one.
		one := r
		one.Repository, one.FromTag, one.ToTag, one.TargetDigest =
			im.Repository, im.FromTag, im.ToTag, im.TargetDigest
		if err := e.applyOne(ctx, one, hostID); err != nil {
			if errors.Is(err, errSuperseded) {
				past++
				e.log.Info("update rollout: host has moved past this image",
					"host", hostID, "repository", im.Repository, "from", im.FromTag,
					"detail", err.Error())
				continue
			}
			e.fail(ctx, r.ID, hostID,
				fmt.Sprintf("%s:%s → %s: %s", im.Repository, im.FromTag, im.ToTag, err.Error()))
			return
		}
		applied++
	}

	if applied == 0 {
		// Two different things end here, and telling an operator the wrong one
		// sends them to look in the wrong place. "Running none of them" points at
		// the host; "already past them" points at the rollout being stale. Both
		// are skips, neither is a failure.
		detail := "this host was not running any of the images by the time its turn came"
		if ran > 0 && past == ran {
			detail = fmt.Sprintf(
				"this host was already past every image in this rollout that it runs "+
					"(%d of %d) — its compose files name newer tags than this rollout's target",
				past, len(images))
		} else if past > 0 {
			detail = fmt.Sprintf(
				"nothing left to apply: of the %d image(s) this host runs, %d were already "+
					"past this rollout's target", ran, past)
		}
		if err := e.store.SetUpdateRolloutHostState(ctx, r.ID, hostID,
			store.UpdateHostSkipped, detail); err != nil {
			e.log.Warn("update rollout: recording skip", "host", hostID, "err", err)
		}
		return
	}
	if err := e.store.SetUpdateRolloutHostState(ctx, r.ID, hostID, store.UpdateHostVerified, ""); err != nil {
		e.log.Warn("update rollout: recording success", "host", hostID, "err", err)
	}
	// The cached registry answers now describe what this host was running BEFORE
	// the rollout. Dropped here, where every path that succeeds converges, rather
	// than beside one of the deploys.
	for _, im := range images {
		one := r
		one.Repository, one.FromTag, one.ToTag = im.Repository, im.FromTag, im.ToTag
		e.invalidateChecks(ctx, one)
	}
}

// reconcileStackPath corrects a stack whose recorded directory has drifted from
// where its project actually runs.
//
// A wrong path is not cosmetic. The deploy creates the directory, writes the
// compose file into it, and leaves behind every file the project needs but that
// Provenance does not manage -- in the case that produced this function, the
// .env holding WIREGUARD_PRIVATE_KEY, so the deploy failed to interpolate and
// the operator was told their compose file was bad when it was fine. The
// running container's own compose labels are the authority on where a project
// lives, and they are already collected.
//
// Scoped to a container whose compose PROJECT is this stack: a different project
// in a different directory is somebody else's stack, not this one moved.
func (e *Engine) reconcileStackPath(ctx context.Context, st *store.ContainerStack, r store.UpdateRollout) {
	containers, err := e.store.HostContainers(ctx, st.HostID)
	if err != nil {
		return
	}
	for i := range containers {
		c := &containers[i]
		if c.Repository != r.Repository || c.ComposeDir == "" {
			continue
		}
		if c.ComposeProject != st.Name || c.ComposeDir == st.Path {
			continue
		}
		if _, err := e.store.UpsertStack(ctx, store.StackInput{
			HostID: st.HostID, Name: st.Name, Path: c.ComposeDir, Compose: st.Compose,
			AuthorName: "container update rollout",
		}); err != nil {
			e.log.Warn("update rollout: correcting a stack path",
				"stack", st.Name, "err", err)
			return
		}
		e.log.Info("corrected a stack path from the host's compose labels",
			"stack", st.Name, "was", st.Path, "now", c.ComposeDir)
		st.Path = c.ComposeDir
		return
	}
}

// superseded reports that a host's own compose files name this repository at some
// other tag, so the rollout's premise has expired for it.
func superseded(stacks []store.ContainerStack, im store.RolloutImage) bool {
	for i := range stacks {
		st := &stacks[i]
		if !st.Enabled || strings.TrimSpace(st.Compose) == "" {
			continue
		}
		if composeSupersedes(st.Compose, im.Repository, im.FromTag, im.ToTag) {
			return true
		}
	}
	return false
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
			return e.verifyInPlace(ctx, r, hostID)
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

	// What this deploy is about to APPLY, not what the rollout intended to
	// change. `compose up` brings up a service's depends_on as well, so a
	// stateful image pinned in this file across a major version from the data on
	// disk goes down with it -- which is how a Keycloak rollout took its Postgres
	// out, the file having pinned 18 against a version-17 data directory.
	if running, cerr := e.store.HostContainers(ctx, hostID); cerr == nil {
		if why, bad := dangerousPin(compose, running); bad {
			return fmt.Errorf("%s", why)
		}
	}

	// The path is where a deploy WRITES, so check it against the host before
	// writing anything.
	e.reconcileStackPath(ctx, stack, r)

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
	services := e.composeServicesFor(ctx, r, hostID, stack.Path, compose)
	if _, out, err := e.dep.DeployPullingService(ctx, stack.ID, services...); err != nil {
		return fmt.Errorf("%s", trimOutput(err.Error()+"\n"+out))
	}

	// Verified means the host is RUNNING the target, not that the deploy command
	// exited zero. A compose file that applies perfectly and leaves the container
	// on the old image is the exact failure this rollout exists to catch, and a
	// rollout that counted the exit code would march a no-op across the fleet
	// while reporting every host as updated.
	return e.verify(ctx, r, hostID)
}

// composeServicesFor returns EVERY compose service running this image on a host,
// or nil when none can be established.
//
// Nil means "the whole project", which is the old behaviour and the safe
// fallback: a deploy that touches more than it needed is recoverable, and one
// that touches nothing because a name was guessed wrong is an update reported as
// applied that never happened.
//
// ALL of them, not the first. One image backing several services in a project is
// ordinary, and the tag rewrite is file-wide -- RewriteImageTag changes every
// matching image: line. Narrowing the deploy to the first match therefore left
// the compose file claiming the new tag for services still running the old one:
// state that disagrees with itself, and that the next unrelated `up -d` in that
// project resolves by silently recreating them. Found on a host running a
// llama.cpp model router and a separate embedding server from one image, where
// only the embedding server was recreated.
// Confined to the project being deployed. A host can run the same image from two
// different compose projects, and a service name from the other one is not a
// service here: passing it would fail the deploy outright with "no such
// service". Scoped by the stack's own path, with an unscoped fallback for the
// hosts where the recorded paths do not line up, which is how this behaved when
// it only ever returned one name.
func (e *Engine) composeServicesFor(ctx context.Context, r store.UpdateRollout,
	hostID uuid.UUID, stackPath, compose string) []string {
	containers, err := e.store.HostContainers(ctx, hostID)
	if err == nil {
		var here, anywhere []string
		seenHere, seenAny := map[string]bool{}, map[string]bool{}
		for _, c := range containers {
			if c.Repository != r.Repository || c.Tag != r.FromTag || c.ComposeService == "" {
				continue
			}
			if !seenAny[c.ComposeService] {
				seenAny[c.ComposeService] = true
				anywhere = append(anywhere, c.ComposeService)
			}
			if stackPath != "" && c.ComposeDir == stackPath && !seenHere[c.ComposeService] {
				seenHere[c.ComposeService] = true
				here = append(here, c.ComposeService)
			}
		}
		if len(here) > 0 {
			return here
		}
		if len(anywhere) > 0 {
			return anywhere
		}
	}

	// No container is running the from-tag. That is not an edge case: it is the
	// state every pinned-but-not-yet-recreated service is in, where the compose
	// file names v1.6.0-ls356 and the container still carries :latest. Matching
	// only on the running tag returned "" for all seven of them, and "" means the
	// WHOLE project -- which on a media stack would have recreated gluetun and
	// everything sharing its network namespace in order to update one service.
	//
	// The compose file being deployed is the better authority anyway: it is the
	// thing about to be applied, and it names the tag this rollout is moving to
	// or from.
	if svcs := composefile.ServicesFor(compose, r.Repository, r.ToTag); len(svcs) > 0 {
		return svcs
	}
	return composefile.ServicesFor(compose, r.Repository, r.FromTag)
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
	out, _, failed := e.run.RunScript(ctx, hostexec.Privileged(adoptScript(match.ComposeDir)), h)
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
	if !composeOwnsImage(compose, r.Repository, r.FromTag, r.ToTag) {
		return true, fmt.Errorf(
			"the compose file at %s/%s names neither %s:%s nor %s:%s, so it is not "+
				"the project this container came from", match.ComposeDir, composeFilename,
			r.Repository, r.FromTag, r.Repository, r.ToTag)
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
	// Every container on this image, not the first. See composeServicesFor: the
	// first-match-wins version recreated one service and left its siblings on the
	// old image.
	//
	// Scoped to the FIRST match's compose directory, because a script runs in one
	// directory. Two projects on one host both running this image are two updates,
	// and the second is picked up on the next pass rather than deployed from the
	// wrong working directory.
	var match *models.Container
	var services []string
	seen := map[string]bool{}
	for i := range containers {
		c := &containers[i]
		if c.Repository != r.Repository || c.Tag != r.FromTag ||
			c.ComposeDir == "" || c.ComposeService == "" {
			continue
		}
		if match == nil {
			match = c
		} else if c.ComposeDir != match.ComposeDir {
			continue
		}
		if !seen[c.ComposeService] {
			seen[c.ComposeService] = true
			services = append(services, c.ComposeService)
		}
	}
	if match == nil {
		return false, nil
	}

	h, err := e.store.GetHost(ctx, hostID)
	if err != nil {
		return true, fmt.Errorf("could not read the host: %w", err)
	}
	out, code, failed := e.run.RunScript(ctx, hostexec.Privileged(inPlaceScript(match.ComposeDir, services...)), h)
	if failed || code != 0 {
		msg := inPlaceFailure(match.ComposeDir, services, out)
		if unreachableProject(out) {
			// Nothing will make this work from here, so halting a fleet-wide
			// rollout on it stops every other host for no gain, every time.
			return true, fmt.Errorf("%w: %s", errSuperseded, msg)
		}
		return true, fmt.Errorf("%s", msg)
	}
	e.log.Info("container updated in place",
		"host", h.Hostname, "project", match.ComposeProject,
		"services", strings.Join(services, ","), "dir", match.ComposeDir)
	e.refreshContainers(ctx, h)
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
		// Nothing to rewrite does not mean nothing to do.
		//
		// A digest-only update (the same tag rebuilt) changes no text. So does a
		// file already edited ahead of its containers — which is the state every
		// partially-applied change is in, including one this rollout wrote itself
		// before failing at a later step. In both cases the file is right and the
		// deploy is the remaining work.
		if composeOwnsImage(st.Compose, r.Repository, r.FromTag, r.ToTag) {
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

// verifyScript reports, for one repository, every container using it: its image
// reference, its name, whether it is actually RUNNING, and the image's digest.
//
// `ps` is listed per CONTAINER rather than deduplicated per image, and carries
// the container's state, because two things a rollout must catch are invisible
// otherwise:
//
//   - `docker ps` lists a container that is crash-looping (state "restarting")
//     exactly like a healthy one. A postgres image bumped across a major version
//     never starts -- it exits on the old data directory and is restarted
//     forever -- yet it reports the new image and the new digest, so a check
//     that only reads the image passes on a container that has never once come
//     up. That is not a hypothetical: it left a Keycloak database down for
//     twenty hours while the rollout recorded the host as verified.
//
//   - a repository can be running in SEVERAL containers on one host. Reading a
//     deduplicated image list cannot tell "every container moved" from "one of
//     them moved and the others are untouched".
func verifyScript(repo string) string {
	return `
_rt=""
if command -v docker >/dev/null 2>&1; then _rt=docker
elif command -v podman >/dev/null 2>&1; then _rt=podman
fi
if [ -z "$_rt" ]; then echo "::NORUNTIME::"; exit 0; fi
echo "::OK::"
$_rt ps --no-trunc --format '{{.Image}}	{{.Names}}	{{.State}}' 2>/dev/null | while IFS="	" read -r _i _n _s; do
  case "$_i" in
    ` + shellCase(repo) + `) ;;
    *) continue ;;
  esac
  _d=$($_rt image inspect --format '{{index .RepoDigests 0}}' "$_i" 2>/dev/null)
  echo "$_i	$_n	$_s	$_d"
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

// runningContainer is one line of verifyScript's output: a container using the
// repository under test.
type runningContainer struct {
	ref    string // repository:tag
	name   string // container name
	state  string // docker/podman container state, e.g. "running", "restarting"
	digest string // "repo@sha256:..." as RepoDigests reports it
}

// isRunning reports whether the container is actually up.
//
// Anything that is not "running" is treated as not running, rather than listing
// the states that are bad. A state this does not recognise -- a newer runtime, a
// podman-only value -- must not read as success: the whole point of this check
// is that a container which is not up cannot count as a completed update.
//
// An empty state is the exception. A runtime whose `ps` does not carry the field
// leaves it blank, and refusing every host there would turn "we cannot tell"
// into "the rollout failed" on runtimes where nothing is actually wrong.
func (c runningContainer) isRunning() bool {
	return c.state == "" || c.state == "running"
}

// parseVerifyOutput reads verifyScript's tab-separated lines.
//
// Lines that do not carry the expected field count are skipped rather than
// guessed at: the marker line and any runtime chatter share this stream.
func parseVerifyOutput(out string) []runningContainer {
	var got []runningContainer
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "::") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		c := runningContainer{
			ref:   strings.TrimSpace(parts[0]),
			name:  strings.TrimSpace(parts[1]),
			state: strings.ToLower(strings.TrimSpace(parts[2])),
		}
		if len(parts) > 3 {
			c.digest = strings.TrimSpace(parts[3])
		}
		if c.ref == "" {
			continue
		}
		got = append(got, c)
	}
	return got
}

// verify reads back what the host is actually running.
func (e *Engine) verify(ctx context.Context, r store.UpdateRollout, hostID uuid.UUID) error {
	return e.verifyRunning(ctx, r, hostID, false)
}

// verifyInPlace is the same check for a deploy that honoured the HOST's compose
// file rather than one this rollout wrote.
//
// The distinction matters at exactly one point; see verifyRunning.
func (e *Engine) verifyInPlace(ctx context.Context, r store.UpdateRollout, hostID uuid.UUID) error {
	return e.verifyRunning(ctx, r, hostID, true)
}

func (e *Engine) verifyRunning(ctx context.Context, r store.UpdateRollout, hostID uuid.UUID, inPlace bool) error {
	h, err := e.store.GetHost(ctx, hostID)
	if err != nil {
		return fmt.Errorf("could not read the host back: %w", err)
	}
	out, _, failed := e.run.RunScript(ctx, hostexec.Privileged(verifyScript(r.Repository)), h)
	if failed || !strings.Contains(out, "::OK::") {
		return fmt.Errorf("deployed, but could not read back what the host is running: %s",
			trimOutput(out))
	}
	want := r.Repository + ":" + r.ToTag
	from := r.Repository + ":" + r.FromTag
	seen := parseVerifyOutput(out)

	// A container still on the tag we are moving AWAY from means this host did
	// not take the update, whatever else on it did. Checked BEFORE looking for a
	// success, because a repository can run in several containers: on one host
	// `llamacpp-embed` was already on the target tag while `llamacpp` sat on the
	// old one, and a check satisfied by the first match called that verified and
	// left the container the rollout existed to move completely untouched.
	//
	// Only when the tags actually differ. A rebuild republishes the SAME tag, so
	// from == want and every container legitimately sits on it; there the digest
	// comparison below is what separates old bytes from new.
	if r.FromTag != r.ToTag {
		for _, c := range seen {
			if c.ref == from {
				return fmt.Errorf("deployed, but %s is still running %s, the tag this rollout moves away from",
					c.name, from)
			}
		}
	}

	for _, c := range seen {
		if c.ref != want {
			continue
		}
		// Running the right image is not the same as running. A container that
		// cannot start reports its new image and its new digest from `ps` while
		// restarting forever, so without this a rollout that BREAKS a service
		// records the host as verified.
		if !c.isRunning() {
			return fmt.Errorf("deployed %s, but the container %s is %s rather than running — the update did not come up",
				want, c.name, c.state)
		}
		if r.TargetDigest == "" {
			return nil // nothing to compare against; running the tag is the answer
		}
		// RepoDigests is "repo@sha256:...", so compare the digest part only.
		if _, d, ok := strings.Cut(c.digest, "@"); ok && d == r.TargetDigest {
			return nil
		}
		return fmt.Errorf("deployed, but %s is running %s rather than the %s this rollout targets",
			want, shortDigest(c.digest), shortDigest(r.TargetDigest))
	}
	// Nothing running the tag we wanted. If the repository is running at some
	// OTHER tag, the host has moved past this image rather than failed to take it
	// — somebody re-pinned the service between the rollout being created and it
	// reaching this host, which is ordinary on a fleet anybody is working on.
	//
	// Checked HERE, from what is actually running, rather than only from an
	// adopted stack: a host with no stack has no copy for the engine to compare
	// against, and that is exactly the host this kept failing on.
	for _, c := range seen {
		ref := c.ref
		if !strings.HasPrefix(ref, r.Repository+":") || ref == want {
			continue
		}
		// Still on the tag we were moving AWAY from is a failure, not a
		// supersession: that is a deploy which reported success and changed
		// nothing, which is the exact failure this whole feature exists to catch.
		if ref == from {
			continue
		}
		// An in-place deploy applies the HOST's compose file, so landing on a tag
		// that file names is the job done, not the rollout arriving too late.
		//
		// Rolling out a rebuild of wyoming-piper:latest against a host whose
		// compose pins 2.2.2 recreated the container onto 2.2.2 -- pulled,
		// restarted, healthy, drift resolved, which is the outcome that was
		// wanted. It was then reported as "this host was already past every image
		// in this rollout that it runs", which says nothing happened. An action
		// reported as inaction is as misleading as the reverse, and it sends an
		// operator to look for the change somewhere else.
		if inPlace {
			e.log.Info("container updated in place to the tag its compose file names",
				"host", hostID, "repository", r.Repository, "ran", ref)
			return nil
		}
		return fmt.Errorf("%w: %s", errSuperseded, ref)
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

// invalidateChecks drops the cached registry answers for an image a rollout has
// just changed, so a successful update stops reading as still pending.
//
// Both tags: the one moved away from carried the "update available" row, and the
// one moved to carries a rebuild's "rebuilt" row -- for a rebuild they are the
// same tag, which is the case that could not clear itself.
//
// Best effort, like the container refresh beside it: the deploy has happened and
// been recorded, so a failure here costs freshness and nothing else.
func (e *Engine) invalidateChecks(ctx context.Context, r store.UpdateRollout) {
	for _, tag := range []string{r.FromTag, r.ToTag} {
		if tag == "" {
			continue
		}
		if err := e.store.InvalidateImageCheck(ctx, r.Repository, tag); err != nil {
			e.log.Warn("update rollout: could not invalidate the image check",
				"repository", r.Repository, "tag", tag, "err", err)
			return
		}
	}
}

// refreshContainers re-reads what a host is running, right after changing it.
//
// The same script and parser the monitor uses; see monitor.ContainersScript.
// Containers are otherwise collected on a ten-minute cadence, so for up to ten
// minutes after a rollout the updates screen still described what was there
// BEFORE it -- an update that had just been applied went on reading "update
// available", which is indistinguishable from one that failed.
//
// Best effort, and after the fact: the deploy has happened and been recorded, so
// a failure here costs freshness and nothing else.
func (e *Engine) refreshContainers(ctx context.Context, h *models.Host) {
	out, _, failed := e.run.RunScript(ctx, hostexec.Privileged(monitor.ContainersScript), h)
	if failed {
		e.log.Warn("refreshing containers after an update", "host", h.Hostname)
		return
	}
	containers, status, detail := monitor.ParseContainers(out)
	// Only a collection that actually ASKED and got an answer may replace the
	// list. A script that died, or a host whose runtime is unreachable, parses to
	// an empty list with a reason -- and writing that would blank the host's
	// containers, turning a momentary hiccup into "this host runs nothing" across
	// every screen. The monitor's own sweep records those cases deliberately; a
	// best-effort refresh after a deploy has no business doing it.
	if status != monitor.ContainersOK {
		e.log.Warn("containers unreadable straight after a deploy; leaving the "+
			"previous list for the next sweep", "host", h.Hostname, "status", status)
		return
	}
	now := e.now()
	inv := models.HostInventory{
		Containers: containers, ContainersCheckedAt: &now,
		ContainersStatus: status, ContainersDetail: detail,
	}
	if err := e.store.UpdateHostContainers(ctx, h.ID, inv); err != nil {
		e.log.Warn("recording containers after an update", "host", h.Hostname, "err", err)
	}
}
