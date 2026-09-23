// Package scheduler fires recurring scans and playbook runs. It reuses the
// normal scan/playbook run paths so scheduled work shows up in the usual
// history; the engine itself only resolves targets, launches the run, and
// advances each schedule's next fire time.
package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/msrc"
	"github.com/kforbus3/provenance/backend/internal/playbook"
	"github.com/kforbus3/provenance/backend/internal/scan"
	"github.com/kforbus3/provenance/backend/internal/store"
	"github.com/kforbus3/provenance/backend/internal/topology"
	"github.com/kforbus3/provenance/backend/internal/vulnscan"
	"github.com/kforbus3/provenance/backend/internal/winscript"
)

// scanFanoutLimit bounds how many host scans a scheduled fire runs at once. A
// schedule targeting a large group would otherwise launch one SSH scan per host
// simultaneously through the single jump host, a resource storm on both ends.
//
// It must stay BELOW the jump host's sshd MaxStartups start value (OpenSSH default
// 10:30:100): from the 10th connection still mid-handshake, sshd drops a share of
// new ones. At 16, a daily scan of a 14-host group had six connections dropped at
// 01:00 on 2026-09-23 and lost one host's scan outright. The rest of Provenance keeps
// dialling the jump host while a scan runs, so this leaves it headroom rather than
// sitting at the edge; 8 matches the cap on manually started scans. The jump dial
// also retries a dropped connection (sshgw.dialJump) -- that covers a burst from
// elsewhere, this keeps the scheduler from being the burst.
const scanFanoutLimit = 8

// Engine ticks on an interval and fires due schedules.
type Engine struct {
	store     *store.Store
	scans     *scan.Service
	vuln      *vulnscan.Service
	msrc      *msrc.Service
	playbook  *playbook.Service
	winscript *winscript.Service
	log       *slog.Logger
	scanSem   chan struct{}
}

func New(st *store.Store, scans *scan.Service, vuln *vulnscan.Service, ms *msrc.Service, pb *playbook.Service, ws *winscript.Service, log *slog.Logger) *Engine {
	return &Engine{store: st, scans: scans, vuln: vuln, msrc: ms, playbook: pb, winscript: ws, log: log, scanSem: make(chan struct{}, scanFanoutLimit)}
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
	// vulndb refreshes the CVE databases (grype + MSRC); it has no host target.
	if sc.Kind == "vulndb" {
		return e.fireVulnDB(), nil
	}
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
	case "vulnscan":
		return e.fireVulnScan(ctx, sc, hosts)
	case "playbook":
		return e.firePlaybook(ctx, sc, hosts)
	case "script":
		return e.fireScript(ctx, sc, hosts)
	default:
		return "error: unknown kind", nil
	}
}

// fireVulnDB refreshes the CVE databases online: the grype vulnerability DB and the
// MSRC (Windows) mapping. Runs in the background (a DB download can take minutes) so
// it doesn't block the scheduler tick; the outcome is logged.
func (e *Engine) fireVulnDB() string {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		if _, err := e.vuln.DBUpdate(ctx); err != nil {
			e.log.Warn("scheduled vulndb: grype update", "err", err)
		} else {
			e.log.Info("scheduled vulndb: grype DB updated")
		}
		if e.msrc != nil {
			if n, err := e.msrc.UpdateOnline(ctx); err != nil {
				e.log.Warn("scheduled vulndb: msrc update", "err", err)
			} else {
				e.log.Info("scheduled vulndb: msrc updated", "entries", n)
			}
		}
	}()
	return "started"
}

// fireVulnScan launches a vulnerability scan per target host, bounded by the same
// fan-out cap as compliance scans.
func (e *Engine) fireVulnScan(ctx context.Context, sc *models.Schedule, hosts []*models.Host) (string, []uuid.UUID) {
	var ids []uuid.UUID
	for _, h := range hosts {
		id, err := e.store.CreateVulnScan(ctx, h.ID, nil, sc.Requester, true)
		if err != nil {
			e.log.Warn("scheduler: create vuln scan", "host", h.Hostname, "err", err)
			continue
		}
		ids = append(ids, id)
		go func(scanID uuid.UUID, host *models.Host) {
			e.scanSem <- struct{}{}
			defer func() { <-e.scanSem }()
			e.vuln.Run(context.WithoutCancel(ctx), scanID, host)
		}(id, h)
	}
	if len(ids) == 0 {
		return "error: no scans created", nil
	}
	return "started", ids
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
			e.scans.Run(context.WithoutCancel(ctx), scanID, host, p.Profile, skip)
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
	if p.OrderByTopology {
		return e.firePlaybookInWaves(ctx, sc, pb, hosts, p, targetID, targetName)
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
	go e.playbook.Run(context.WithoutCancel(ctx), rec.ID, pb.Content, hosts, p.CheckMode)
	return "started", []uuid.UUID{rec.ID}
}

// firePlaybookInWaves runs the schedule's hosts in dependency order: dependents
// first, whatever carries them last.
//
// This is the ordering an operator otherwise writes as clock times -- guests at
// 03:00, storage at 03:45, the hypervisor at 04:30 -- with a gap chosen by
// guessing how long the earlier run takes. That is a race, not an order: a guest
// run bounded by a ninety-minute timeout can still be going when the storage
// window opens, and when it is, storage reboots out from under it.
//
// Each wave is its own run, so the history shows what actually happened at each
// stage rather than one row that hides the sequence.
//
// A failed wave STOPS the rest. That is the whole point: if patching the guests
// went wrong, rebooting the NAS underneath them is the last thing that should
// happen next. Cautious rather than fast, like the rollout pacing defaults.
func (e *Engine) firePlaybookInWaves(
	ctx context.Context, sc *models.Schedule, pb *models.Playbook,
	hosts []*models.Host, p models.PlaybookSchedulePayload,
	targetID *uuid.UUID, targetName string,
) (string, []uuid.UUID) {
	ids := make([]uuid.UUID, 0, len(hosts))
	byID := make(map[uuid.UUID]*models.Host, len(hosts))
	for _, h := range hosts {
		ids = append(ids, h.ID)
		byID[h.ID] = h
	}
	edges, err := e.store.DependentsOf(ctx, ids)
	if err != nil {
		// Ordering is the reason this schedule exists, so guessing an order is
		// worse than not starting: running unordered is the failure it was set up
		// to prevent.
		e.log.Error("scheduled playbook: could not read topology; not starting",
			"schedule", sc.ID, "err", err)
		return "error: topology unavailable", nil
	}
	waves := topology.Waves(ids, edges)
	if len(waves) <= 1 {
		// Nothing to order. Fall through to the ordinary single run rather than
		// creating a one-wave sequence that reads differently for no reason.
		p.OrderByTopology = false
		one := *sc
		payload, merr := json.Marshal(p)
		if merr == nil {
			one.Payload = payload
			return e.firePlaybook(ctx, &one, hosts)
		}
	}

	runIDs := make([]uuid.UUID, 0, len(waves))
	stages := make([]stage, 0, len(waves))
	for i, wave := range waves {
		wh := make([]*models.Host, 0, len(wave))
		for _, id := range wave {
			if h := byID[id]; h != nil {
				wh = append(wh, h)
			}
		}
		if len(wh) == 0 {
			continue
		}
		name := fmt.Sprintf("%s (wave %d of %d)", targetName, i+1, len(waves))
		rec, cerr := e.store.CreatePlaybookRun(ctx, models.PlaybookRun{
			PlaybookID:      pb.ID,
			PlaybookVersion: pb.Version,
			Requester:       sc.Requester,
			TargetKind:      sc.TargetKind,
			TargetID:        targetID,
			TargetName:      name,
			HostCount:       len(wh),
			CheckMode:       p.CheckMode,
			Scheduled:       true,
		}, nil)
		if cerr != nil {
			e.log.Error("scheduled playbook: create wave run", "schedule", sc.ID, "err", cerr)
			return "error: create run", runIDs
		}
		stages = append(stages, stage{id: rec.ID, hosts: wh})
		runIDs = append(runIDs, rec.ID)
	}

	go func() {
		bg := context.WithoutCancel(ctx)
		runWave := func(st stage) { e.playbook.Run(bg, st.id, pb.Content, st.hosts, p.CheckMode) }
		waveStatus := func(id uuid.UUID) (string, error) {
			run, err := e.store.GetPlaybookRun(bg, id)
			if err != nil {
				return "", err
			}
			return run.Status, nil
		}
		runStages(stages, runWave, waveStatus, func(msg string, args ...any) {
			e.log.Warn(msg, append([]any{"schedule", sc.ID}, args...)...)
		}, func(st stage, reason string) {
			// Recorded as interrupted rather than failed: nothing was attempted on
			// these hosts, and calling that a failure would put them in every report
			// of things that went wrong on machines that were never touched.
			if err := e.store.CompletePlaybookRun(bg, st.id,
				models.PlaybookRunInterrupted, reason, nil, reason); err != nil {
				e.log.Warn("scheduled playbook: could not mark a skipped wave",
					"schedule", sc.ID, "run", st.id, "err", err)
			}
		})
	}()
	return "started", runIDs
}

// fireScript runs a PowerShell script on the schedule's Windows hosts. Non-Windows
// hosts in the target are skipped (PowerShell doesn't apply). Scheduled runs are
// unattended, so winscript.Run uses only open-policy credentials (nil userID).
func (e *Engine) fireScript(ctx context.Context, sc *models.Schedule, hosts []*models.Host) (string, []uuid.UUID) {
	var p models.ScriptSchedulePayload
	if err := json.Unmarshal(sc.Payload, &p); err != nil {
		return "error: bad payload", nil
	}
	script, err := e.store.GetWinScript(ctx, p.ScriptID)
	if err != nil {
		return "error: script not found", nil
	}
	winHosts := make([]*models.Host, 0, len(hosts))
	for _, h := range hosts {
		if h.Protocol == "rdp" {
			winHosts = append(winHosts, h)
		}
	}
	if len(winHosts) == 0 {
		return "skipped: no Windows hosts", nil
	}
	var targetID *uuid.UUID
	if sc.TargetKind == "group" {
		targetID = sc.TargetID
	} else if len(winHosts) == 1 {
		targetID = &winHosts[0].ID
	}
	rec, err := e.store.CreateWinScriptRun(ctx, models.WinScriptRun{
		ScriptID:      script.ID,
		ScriptVersion: script.Version,
		Requester:     sc.Requester,
		TargetKind:    sc.TargetKind,
		TargetID:      targetID,
		TargetName:    sc.TargetName,
		HostCount:     len(winHosts),
		Scheduled:     true,
	}, nil)
	if err != nil {
		return "error: create run", nil
	}
	go e.winscript.Run(context.WithoutCancel(ctx), rec.ID, script.Content, winHosts, nil)
	return "started", []uuid.UUID{rec.ID}
}

// stage is one wave: its own playbook run, over the hosts in that wave.
type stage struct {
	id    uuid.UUID
	hosts []*models.Host
}

// runStages runs dependency-ordered waves in sequence and STOPS at the first one
// that does not complete.
//
// Extracted from the goroutine so the halting rule can be tested, because it is
// the part that is dangerous in both directions: too eager and a fleet upgrade
// reboots the storage its remaining hosts stand on; too strict and every
// sequence silently ends after its first wave. It shipped as the latter once --
// gated on the status "success", which this system never writes -- and that was
// caught by querying the database rather than by any test.
func runStages(
	stages []stage,
	run func(stage),
	status func(uuid.UUID) (string, error),
	warn func(msg string, args ...any),
	skip func(st stage, reason string),
) {
	// Every wave's run row is created up front, so the ones that never execute have to
	// be closed out — or they sit at "pending" for ever, which on the history screen is
	// indistinguishable from "about to start". An operator looking at a stopped
	// sequence would see one failed wave and one apparently still coming.
	stop := func(from int, reason string) {
		for _, rest := range stages[from:] {
			skip(rest, reason)
		}
	}
	for i, st := range stages {
		run(st)
		got, err := status(st.id)
		if err != nil {
			// Not knowing whether a wave succeeded is not permission to continue:
			// the next wave is the thing the previous one stands on.
			warn("scheduled playbook: could not read a wave result; later waves skipped",
				"wave", i+1, "of", len(stages), "err", err)
			stop(i+1, fmt.Sprintf("not run: the result of wave %d of %d could not be read, "+
				"and this wave is what that one stands on", i+1, len(stages)))
			return
		}
		if got != models.PlaybookRunCompleted {
			warn("scheduled playbook: wave did not succeed; later waves skipped",
				"wave", i+1, "of", len(stages), "status", got)
			stop(i+1, fmt.Sprintf("not run: wave %d of %d %s, and this wave is what that "+
				"one stands on", i+1, len(stages), got))
			return
		}
	}
}
