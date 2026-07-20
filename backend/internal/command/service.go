// Package command runs ad-hoc shell commands on managed Linux (SSH) hosts — the
// lightweight counterpart to Ansible playbooks and PowerShell scripts. Execution
// goes over SSH through the Fleet jump host, as the host's system principal, with a
// bounded worker pool and a capped output buffer. Every command is evaluated
// against the command-control policy (flag/block/approval) before it runs, so the
// same governance that applies to an interactive session applies here.
package command

import (
	"log/slog"
	"sync"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/identity"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/sshgw"
	"github.com/fleet-terminal/backend/internal/store"
)

// Service orchestrates ad-hoc command runs over SSH.
type Service struct {
	store  *store.Store
	cfg    *config.Config
	log    *slog.Logger
	gw     *sshgw.Gateway
	issuer *identity.Issuer
	nfy    *notify.Service
	live   sync.Map // runID -> *liveRun
}

func New(st *store.Store, cfg *config.Config, log *slog.Logger, gw *sshgw.Gateway, issuer *identity.Issuer, nfy *notify.Service) *Service {
	return &Service{store: st, cfg: cfg, log: log, gw: gw, issuer: issuer, nfy: nfy}
}

// LiveOutput returns the current output for a run in flight, if any.
func (s *Service) LiveOutput(id uuid.UUID) (string, bool) {
	v, ok := s.live.Load(id)
	if !ok {
		return "", false
	}
	return v.(*liveRun).snapshot(), true
}
