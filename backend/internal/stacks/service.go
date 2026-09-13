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
	return s.deploy(ctx, stackID, false, "")
}

// DeployPulling is Deploy, fetching images first.
//
// For update rollouts. See renderScript's `pull` for why an ordinary deploy does
// not do this and why an update rollout must.
func (s *Service) DeployPulling(ctx context.Context, stackID uuid.UUID) (*store.ContainerStack, string, error) {
	return s.deploy(ctx, stackID, true, "")
}

// DeployPullingService is DeployPulling narrowed to one compose service.
//
// For an update rollout, which is about one image. See renderScript's `service`
// for why the whole project is the wrong scope there.
func (s *Service) DeployPullingService(ctx context.Context, stackID uuid.UUID, service string) (*store.ContainerStack, string, error) {
	return s.deploy(ctx, stackID, true, service)
}

func (s *Service) deploy(ctx context.Context, stackID uuid.UUID, pull bool, service string) (*store.ContainerStack, string, error) {
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

	// In progress, recorded before it starts.
	//
	// A deploy that pulls eight images takes minutes, and until it finishes there
	// was nothing anywhere saying so: the screen kept showing the PREVIOUS
	// outcome, so an operator who pressed Deploy and looked had no way to tell a
	// run in flight from one that never started. See DeployStateDeploying.
	_ = s.store.MarkStackDeploying(ctx, st.ID)

	out, code, failed := s.run.RunScript(ctx, hostexec.Privileged(RenderScript(st.Path, st.Compose, st.Revision, pull, service)), h)
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
