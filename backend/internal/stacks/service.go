package stacks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/hostexec"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/monitor"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// Runner executes a script on a host. Narrow on purpose: this package decides
// WHAT to run and the caller supplies the means, so the deploy logic is testable
// without a host, a jump host or a certificate.
type Runner interface {
	RunScript(ctx context.Context, script string, h *models.Host) (output string, exitCode int, failed bool)
}

type Service struct {
	store *store.Store
	run   Runner
	log   *slog.Logger
}

func New(st *store.Store, run Runner, log *slog.Logger) *Service {
	return &Service{store: st, run: run, log: log}
}

var ErrNoCompose = errors.New("this stack has no compose file to deploy")

// Deploy writes a stack's current revision to its host and brings it up.
//
// The result is recorded either way. A deployment that failed is not the absence
// of a deployment: leaving the previous success in place would say the host is
// running a revision it is not, and that lie is worse than the failure.
// Deployment states recorded against a stack.
const (
	DeployStateDeploying = "deploying"
	DeployStateDeployed  = "deployed"
	DeployStateFailed    = "failed"
)

func (s *Service) Deploy(ctx context.Context, stackID uuid.UUID) (*store.ContainerStack, string, error) {
	return s.deploy(ctx, stackID, false, false, "")
}

// DeployAcknowledgingStatefulMajor is Deploy with the stateful-image guard waived.
//
// The guard exists because nobody means to point postgres 18 at a version 17 data
// directory. But somebody who has just run pg_upgrade by hand means exactly that, and
// a guard with no way through would make the platform useless for the one operator
// who is doing the right thing. So the refusal is the default and this is the answer
// to it -- reached from the UI only after the dialog has named the image, both
// versions and the migration involved.
func (s *Service) DeployAcknowledgingStatefulMajor(ctx context.Context, stackID uuid.UUID) (*store.ContainerStack, string, error) {
	return s.deploy(ctx, stackID, false, true, "")
}

// DeployPulling is Deploy, fetching images first.
//
// For update rollouts. See renderScript's `pull` for why an ordinary deploy does
// not do this and why an update rollout must.
func (s *Service) DeployPulling(ctx context.Context, stackID uuid.UUID) (*store.ContainerStack, string, error) {
	return s.deploy(ctx, stackID, true, false, "")
}

// DeployPullingService is DeployPulling narrowed to one compose service.
//
// For an update rollout, which is about one image. See renderScript's `service`
// for why the whole project is the wrong scope there.
func (s *Service) DeployPullingService(ctx context.Context, stackID uuid.UUID, services ...string) (*store.ContainerStack, string, error) {
	// Never acknowledged: a rollout is automation, and the whole point of the guard
	// is that this decision belongs to a person who has a migration plan.
	return s.deploy(ctx, stackID, true, false, services...)
}

// PreflightStatefulMajor answers the stateful-image question without deploying
// anything, so the refusal can be a dialog rather than a failure that arrives
// minutes later in a row on a table.
//
// It reads only the database: the stored compose and the containers the last sweep
// saw. Nothing is written and the host is not contacted, which is what makes it safe
// to run on the request itself while the deploy that follows does not.
func (s *Service) PreflightStatefulMajor(ctx context.Context, stackID uuid.UUID) (*StatefulMajorError, error) {
	st, err := s.store.GetStack(ctx, stackID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(st.Compose) == "" {
		return nil, nil
	}
	h, err := s.store.GetHost(ctx, st.HostID)
	if err != nil {
		return nil, fmt.Errorf("host: %w", err)
	}
	if h.Inventory == nil {
		// Nothing collected from this host yet, so there is no evidence either way.
		// Silence here means "cannot tell", and the deploy proceeds -- refusing on
		// an absence would block every first deploy.
		return nil, nil
	}
	return statefulPinConflict(st.Compose, nil, h.Inventory.Containers, st.Path), nil
}

func (s *Service) deploy(ctx context.Context, stackID uuid.UUID, pull, ackStatefulMajor bool, services ...string) (*store.ContainerStack, string, error) {
	st, err := s.store.GetStack(ctx, stackID)
	if err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(st.Compose) == "" {
		return nil, "", ErrNoCompose
	}
	h, err := s.store.GetHost(ctx, st.HostID)
	if err != nil {
		return nil, "", fmt.Errorf("host: %w", err)
	}

	// Refuse before touching the host, not after.
	//
	// Nothing is recorded and nothing is written: this deploy has not happened, so a
	// deployment row saying it failed would be wrong. The caller gets an error it can
	// recognise and offer a way through.
	if !ackStatefulMajor && h.Inventory != nil {
		if conflict := statefulPinConflict(st.Compose, services, h.Inventory.Containers, st.Path); conflict != nil {
			return st, "", conflict
		}
	}

	// In progress, recorded before it starts.
	//
	// A deploy that pulls eight images takes minutes, and until it finishes there
	// was nothing anywhere saying so: the screen kept showing the PREVIOUS
	// outcome, so an operator who pressed Deploy and looked had no way to tell a
	// run in flight from one that never started. See DeployStateDeploying.
	_ = s.store.MarkStackDeploying(ctx, st.ID)

	out, code, failed := s.run.RunScript(ctx, hostexec.Privileged(RenderScript(st.Path, st.Compose, st.Revision, pull, services...)), h)
	state := "deployed"
	if failed || code != 0 {
		state = "failed"
	}
	// Re-read what the host is running, now that it has just been changed.
	//
	// Containers are otherwise collected on a ten-minute cadence, so for up to
	// ten minutes after a successful deploy every screen driven by the inventory
	// -- the updates list above all -- still described the containers that were
	// there BEFORE it. An update that had just been applied went on reading
	// "update available", which is indistinguishable from one that failed.
	//
	// Only on success: a failed deploy changed nothing, and spending an SSH round
	// trip to confirm that is work for nothing.
	if state == DeployStateDeployed {
		s.refreshContainers(ctx, h)
	}

	if rerr := s.store.RecordStackDeployment(ctx, st.ID, st.Revision, state, out); rerr != nil {
		s.log.Warn("recording stack deployment", "stack", st.ID, "err", rerr)
	}
	if state == "failed" {
		// What happened to the SERVICE is the part an operator needs first, and it is
		// not in the exit code: the script puts the previous compose file back and
		// brings it up. Saying only "deploy failed" left people to find that out by
		// looking, or to assume the stack was down when it was not.
		switch {
		case strings.Contains(out, "::RESTORED::"):
			return st, out, fmt.Errorf("deploy failed on %s (exit %d) — the previous compose file "+
				"was restored and the stack is running on it. The rejected file is on the host as "+
				"docker-compose.yml.rejected", h.Hostname, code)
		case strings.Contains(out, "::RESTOREFAILED::"):
			return st, out, fmt.Errorf("deploy failed on %s (exit %d) AND the previous compose file "+
				"did not come up either — this stack is down", h.Hostname, code)
		case strings.Contains(out, "::NOPREVIOUS::"):
			return st, out, fmt.Errorf("deploy failed on %s (exit %d) and this host has no previous "+
				"compose file to fall back to — this stack is down", h.Hostname, code)
		}
		return st, out, fmt.Errorf("deploy failed on %s (exit %d)", h.Hostname, code)
	}
	return st, out, nil
}

// Rollback restores the previous compose file ON THE HOST and brings it up.
//
// From the host's own copy rather than from the database on purpose. The file
// left beside the current one is what the host was actually running, which is
// the thing being rolled back to -- a revision fetched from here would be what
// the control plane BELIEVES it was running, and those differ exactly when a
// rollback matters.
func (s *Service) Rollback(ctx context.Context, stackID uuid.UUID) (string, error) {
	st, err := s.store.GetStack(ctx, stackID)
	if err != nil {
		return "", err
	}
	h, err := s.store.GetHost(ctx, st.HostID)
	if err != nil {
		return "", fmt.Errorf("host: %w", err)
	}
	out, code, failed := s.run.RunScript(ctx, hostexec.Privileged(rollbackScript(st.Path)), h)
	if failed || code != 0 {
		_ = s.store.RecordStackDeployment(ctx, st.ID, st.Revision, "failed", out)
		return out, fmt.Errorf("rollback failed on %s (exit %d)", h.Hostname, code)
	}
	// The host is now on the revision before this one. Which that is, is a
	// question for the host: it wrote .provenance-revision when it applied it.
	prev := st.Revision - 1
	if prev < 1 {
		prev = 1
	}
	_ = s.store.RecordStackDeployment(ctx, st.ID, prev, "rolled_back", out)
	return out, nil
}

// Drift reports stacks whose host is not running the revision it should be.
//
// Two sources disagree here and that is the point: container_stacks says what
// should run, container_stack_deployments says what the host last confirmed. A
// tool that only tracked the first would report success for a deploy that never
// landed.
func (s *Service) Drift(ctx context.Context) ([]store.ContainerStack, error) {
	all, err := s.store.ListStacks(ctx, nil)
	if err != nil {
		return nil, err
	}
	var out []store.ContainerStack
	for _, st := range all {
		if driftsFrom(st) {
			out = append(out, st)
		}
	}
	return out, nil
}

// driftsFrom is the comparison itself, separated so it can be exercised without a
// database: it is the assertion the whole feature rests on.
//
// A failed deploy counts as drift even when the revision numbers agree. The host
// confirmed an ATTEMPT at that revision, not a success, and treating those as the
// same is how a tool ends up reporting that everything is fine.
func driftsFrom(st store.ContainerStack) bool {
	if !st.Enabled {
		return false
	}
	// A deploy in flight is not drift. It is the answer to drift, happening now,
	// and flagging it would put every stack into the needs-attention list for the
	// minutes it takes to pull.
	if st.DeployState == DeployStateDeploying {
		return false
	}
	return st.Deployed == nil || *st.Deployed != st.Revision || st.DeployState == DeployStateFailed
}

// refreshContainers re-collects one host's running containers, immediately.
//
// The same script and the same parser the monitor uses -- see
// monitor.ContainersScript. A second implementation would drift from that one,
// and the two would disagree about what a host is running, which is the question
// the whole update feature turns on.
//
// Best effort: the deploy has already happened and already been recorded, so a
// failure here costs freshness, not correctness. The next sweep collects anyway.
func (s *Service) refreshContainers(ctx context.Context, h *models.Host) {
	out, _, failed := s.run.RunScript(ctx, hostexec.Privileged(monitor.ContainersScript), h)
	if failed {
		s.log.Warn("refreshing containers after a deploy", "host", h.Hostname)
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
		s.log.Warn("containers unreadable straight after a deploy; leaving the "+
			"previous list for the next sweep", "host", h.Hostname, "status", status)
		return
	}
	now := time.Now()
	inv := models.HostInventory{
		Containers: containers, ContainersCheckedAt: &now,
		ContainersStatus: status, ContainersDetail: detail,
	}
	if err := s.store.UpdateHostContainers(ctx, h.ID, inv); err != nil {
		s.log.Warn("recording containers after a deploy", "host", h.Hostname, "err", err)
	}
}
