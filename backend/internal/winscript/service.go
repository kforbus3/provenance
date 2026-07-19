// Package winscript runs operator-authored PowerShell scripts on Windows (RDP)
// hosts — the Windows counterpart to the Ansible playbook runner. Execution goes
// over WinRM through the Fleet jump host (the same transport the monitor uses for
// facts), authenticated with each host's vaulted credential (honoring its check-out
// policy). Multi-host runs use a bounded worker pool and a capped output buffer so a
// large fan-out or a chatty/hostile host can't exhaust jump-host connections or memory.
package winscript

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

// Service orchestrates PowerShell script runs over WinRM.
type Service struct {
	store  *store.Store
	cfg    *config.Config
	log    *slog.Logger
	gw     *sshgw.Gateway
	issuer *identity.Issuer
	nfy    *notify.Service
	live   sync.Map // runID -> *liveRun
}

// New constructs the winscript service.
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
