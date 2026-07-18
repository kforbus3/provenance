// Package scheduler fires recurring scans and playbook runs. It reuses the
// normal scan/playbook run paths so scheduled work shows up in the usual
// history; the engine itself only resolves targets, launches the run, and
// advances each schedule's next fire time.
package scheduler

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/playbook"
	"github.com/fleet-terminal/backend/internal/scan"
	"github.com/fleet-terminal/backend/internal/store"
)

// scanFanoutLimit bounds how many host scans a scheduled fire runs at once. A
// schedule targeting a large group would otherwise launch one SSH scan per host
// simultaneously through the single jump host, a resource storm on both ends.
const scanFanoutLimit = 16

// Engine ticks on an interval and fires due schedules.
type Engine struct {
	store    *store.Store
	scans    *scan.Service
	playbook *playbook.Service
	log      *slog.Logger
	scanSem  chan struct{}
}

func New(st *store.Store, scans *scan.Service, pb *playbook.Service, log *slog.Logger) *Engine {
	return &Engine{store: st, scans: scans, playbook: pb, log: log, scanSem: make(chan struct{}, scanFanoutLimit)}
}

// Run drives the scheduler loop until ctx is cancelled, checking once a minute.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTimer(20 * time.Second) // first check shortly after startup
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.tick(ctx)
			t.Reset(time.Minute)
		}
	}
}

func (e *Engine) tick(ctx context.Context) {
	now := time.Now()
	due, err := e.store.ClaimDueSchedules(ctx, now)
	if err != nil {
		e.log.Warn("scheduler: claim due", "err", err)
		return
	}
	for _, sc := range due {
		status, ids := e.Fire(ctx, sc)
		next := e.store.ScheduleNextRun(ctx, sc.Recurrence)
		if err := e.store.MarkScheduleFired(ctx, sc.ID, now, status, next, ids); err != nil {
			e.log.Warn("scheduler: mark fired", "schedule", sc.ID, "err", err)
		}
	}
}

// Fire launches a schedule's work immediately (also used by "run now"). It
// returns a short status string recorded as last_status, plus the IDs of the
// scan/playbook-run records it created so callers can track in-progress state;
// the produced scan/run carries the real outcome.
func (e *Engine) Fire(ctx context.Context, sc *models.Schedule) (string, []uuid.UUID) {
	hosts, err := e.resolveHosts(ctx, sc)
	if err != nil {
		e.log.Warn("scheduler: resolve hosts", "schedule", sc.ID, "err", err)
		return "error: " + err.Error(), nil
	}
	if len(hosts) == 0 {
		return "skipped: no hosts", nil
	}
	switch sc.Kind {
	case "scan":
		return e.fireScan(ctx, sc, hosts)
	case "playbook":
		return e.firePlaybook(ctx, sc, hosts)
	default:
		return "error: unknown kind", nil
	}
}

func (e *Engine) resolveHosts(ctx context.Context, sc *models.Schedule) ([]*models.Host, error) {
	if sc.TargetID == nil {
		return nil, nil
	}
	if sc.TargetKind == "group" {
		members, err := e.store.HostsInGroup(ctx, *sc.TargetID)
		if err != nil {
			return nil, err
		}
		out := make([]*models.Host, 0, len(members))
		for i := range members {
			out = append(out, &members[i])
		}
		return out, nil
	}
	h, err := e.store.GetHost(ctx, *sc.TargetID)
	if err != nil {
		return nil, err
	}
	return []*models.Host{h}, nil
}

func (e *Engine) fireScan(ctx context.Context, sc *models.Schedule, hosts []*models.Host) (string, []uuid.UUID) {
	var p models.ScanSchedulePayload
	_ = json.Unmarshal(sc.Payload, &p)
	skip := p.SkipRules
	if p.SkipExpensiveFsRules {
		skip = append(append([]string{}, scan.ExpensiveFSRules...), skip...)
	}
	var ids []uuid.UUID
	for _, h := range hosts {
		rec, err := e.store.CreateHostScan(ctx, h.ID, nil, sc.Requester, p.Profile, true)
		if err != nil {
			e.log.Warn("scheduler: create scan", "host", h.Hostname, "err", err)
			continue
		}
		ids = append(ids, rec.ID)
		// Launch immediately but gate concurrency on scanSem: extra hosts queue
		// rather than all dialing the jump host at once. Fire still returns promptly.
		go func(scanID uuid.UUID, host *models.Host) {
			e.scanSem <- struct{}{}
			defer func() { <-e.scanSem }()
			e.scans.Run(scanID, host, p.Profile, skip)
		}(rec.ID, h)
	}
	if len(ids) == 0 {
		return "error: no scans created", nil
	}
	return "started", ids
}

func (e *Engine) firePlaybook(ctx context.Context, sc *models.Schedule, hosts []*models.Host) (string, []uuid.UUID) {
	var p models.PlaybookSchedulePayload
	if err := json.Unmarshal(sc.Payload, &p); err != nil {
		return "error: bad payload", nil
	}
	pb, err := e.store.GetPlaybook(ctx, p.PlaybookID)
	if err != nil {
		return "error: playbook not found", nil
	}
	targetName := sc.TargetName
	var targetID *uuid.UUID
	if sc.TargetKind == "group" {
		targetID = sc.TargetID
	} else if len(hosts) == 1 {
		targetID = &hosts[0].ID
	}
	rec, err := e.store.CreatePlaybookRun(ctx, models.PlaybookRun{
		PlaybookID:      pb.ID,
		PlaybookVersion: pb.Version,
		Requester:       sc.Requester,
		TargetKind:      sc.TargetKind,
		TargetID:        targetID,
		TargetName:      targetName,
		HostCount:       len(hosts),
		CheckMode:       p.CheckMode,
		Scheduled:       true,
	}, nil)
	if err != nil {
		return "error: create run", nil
	}
	go e.playbook.Run(rec.ID, pb.Content, hosts, p.CheckMode)
	return "started", []uuid.UUID{rec.ID}
}
