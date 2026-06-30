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

// Engine ticks on an interval and fires due schedules.
type Engine struct {
	store    *store.Store
	scans    *scan.Service
	playbook *playbook.Service
	log      *slog.Logger
}

func New(st *store.Store, scans *scan.Service, pb *playbook.Service, log *slog.Logger) *Engine {
	return &Engine{store: st, scans: scans, playbook: pb, log: log}
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
	due, err := e.store.DueSchedules(ctx, now)
	if err != nil {
		e.log.Warn("scheduler: list due", "err", err)
		return
	}
	for _, sc := range due {
		status := e.Fire(ctx, sc)
		next := e.store.ScheduleNextRun(ctx, sc.Recurrence)
		if err := e.store.MarkScheduleFired(ctx, sc.ID, now, status, next); err != nil {
			e.log.Warn("scheduler: mark fired", "schedule", sc.ID, "err", err)
		}
	}
}

// Fire launches a schedule's work immediately (also used by "run now"). It
// returns a short status string recorded as last_status; the produced scan/run
// carries the real outcome.
func (e *Engine) Fire(ctx context.Context, sc *models.Schedule) string {
	hosts, err := e.resolveHosts(ctx, sc)
	if err != nil {
		e.log.Warn("scheduler: resolve hosts", "schedule", sc.ID, "err", err)
		return "error: " + err.Error()
	}
	if len(hosts) == 0 {
		return "skipped: no hosts"
	}
	switch sc.Kind {
	case "scan":
		return e.fireScan(ctx, sc, hosts)
	case "playbook":
		return e.firePlaybook(ctx, sc, hosts)
	default:
		return "error: unknown kind"
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

func (e *Engine) fireScan(ctx context.Context, sc *models.Schedule, hosts []*models.Host) string {
	var p models.ScanSchedulePayload
	_ = json.Unmarshal(sc.Payload, &p)
	skip := p.SkipRules
	if p.SkipExpensiveFsRules {
		skip = append(append([]string{}, scan.ExpensiveFSRules...), skip...)
	}
	for _, h := range hosts {
		rec, err := e.store.CreateHostScan(ctx, h.ID, nil, sc.Requester, p.Profile)
		if err != nil {
			e.log.Warn("scheduler: create scan", "host", h.Hostname, "err", err)
			continue
		}
		go e.scans.Run(rec.ID, h, p.Profile, skip)
	}
	return "started"
}

func (e *Engine) firePlaybook(ctx context.Context, sc *models.Schedule, hosts []*models.Host) string {
	var p models.PlaybookSchedulePayload
	if err := json.Unmarshal(sc.Payload, &p); err != nil {
		return "error: bad payload"
	}
	pb, err := e.store.GetPlaybook(ctx, p.PlaybookID)
	if err != nil {
		return "error: playbook not found"
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
	}, nil)
	if err != nil {
		return "error: create run"
	}
	go e.playbook.Run(rec.ID, pb.Content, hosts, p.CheckMode)
	return "started"
}
