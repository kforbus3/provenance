package stacks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/hostexec"
	"github.com/kforbus3/provenance/backend/internal/models"
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

	out, code, failed := s.run.RunScript(ctx, hostexec.Privileged(RenderScript(st.Path, st.Compose, st.Revision, pull, service)), h)
	state := "deployed"
	if failed || code != 0 {
		state = "failed"
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
	return st.Deployed == nil || *st.Deployed != st.Revision || st.DeployState == "failed"
}
