package imaging

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/blackfriars/backend/internal/auth"
	"github.com/kforbus3/blackfriars/backend/internal/models"
	"github.com/kforbus3/blackfriars/backend/internal/notify"
)

// The operations behind the API: reading the fleet, running rollouts, and the
// one call that turns a machine's check-in into a decision.

// FleetView is every machine, with the host it is paired to and whether this
// server can reach that host — which is the thing an operator wants at a glance
// before starting a rollout, because it is the difference between an update
// that lands in minutes and one that lands whenever the machine next asks.
func (s *Service) FleetView(ctx context.Context, p *auth.Principal) ([]models.ImagingMachine, error) {
	machines, err := s.store.ListMachines(ctx)
	if err != nil {
		return nil, err
	}
	hosts, err := s.store.ListHosts(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}
	byID := map[uuid.UUID]*models.Host{}
	for i := range hosts {
		byID[hosts[i].ID] = &hosts[i]
	}

	interval := s.AgentInterval()
	now := time.Now()
	out := make([]models.ImagingMachine, 0, len(machines))
	for i := range machines {
		m := machines[i]
		m.Presence = Presence(m.LastSeen, interval, now)
		if m.HostID != nil {
			h, ok := byID[*m.HostID]
			if !ok {
				// Paired with a host that no longer exists. Shown unpaired
				// rather than hidden: a pairing that has stopped resolving is
				// worth noticing.
				m.HostID = nil
			} else {
				// Host access is this product's rule and applies to every view
				// of a host, including this one.
				if p != nil && !p.IsSuperAdmin {
					allowed, aerr := s.store.UserCanAccessHost(ctx, p.UserID, h.ID)
					if aerr != nil || !allowed {
						continue
					}
				}
				m.HostName = h.Hostname
				m.Environment = h.Environment
				m.Tags = h.Tags
				m.Reachable = h.Enrolled && h.Protocol != "rdp" && !h.InMaintenance()
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// EvaluateFor folds a machine's report into whatever rollout owns it and returns
// what the machine should do next.
//
// Called from the heartbeat, so it runs on every check-in from every machine.
// It never returns an error: a machine that cannot be told what to do should be
// told nothing and try again, not receive a failure it has no way to act on.
func (s *Service) EvaluateFor(ctx context.Context, machineID string, rep Report) *Action {
	rollouts, err := s.store.ListRollouts(ctx)
	if err != nil {
		s.log.Warn("imaging: listing rollouts for a heartbeat", "err", err)
		return nil
	}
	machine, err := s.store.GetMachine(ctx, machineID)
	if err != nil {
		return nil
	}

	// Newest first: the most recent intent wins for a machine that is not
	// already committed to an earlier one.
	for i := range rollouts {
		rec := &rollouts[i]
		if rec.State != RolloutRunning && rec.State != RolloutPaused {
			continue
		}
		members, err := s.store.MachinesForTarget(ctx, rec.TargetGroups, rec.TargetHosts, rec.TargetAll)
		if err != nil {
			continue
		}
		if !contains(members, machineID) {
			continue
		}
		progress, err := s.store.RolloutProgress(ctx, rec.ID)
		if err != nil {
			continue
		}
		if p, ok := progress[machineID]; ok && terminal(p.State) {
			continue
		}

		eng := engineFrom(rec, progress)
		action, changed := eng.Evaluate(machineID, rep, members, machine.Held, time.Now())
		if changed {
			applyEngine(rec, eng)
			if err := s.store.SaveRolloutProgress(ctx, rec, progressFrom(eng)); err != nil {
				s.log.Warn("imaging: saving rollout progress", "rollout", rec.ID, "err", err)
			}
			// Counts computed here, from the engine that has just run. This
			// path never calls fill(), which is the only thing that populates
			// rec.Done -- so the alert used to read "0 of 37 machines were
			// done" on every halt, throwing away the one number that says how
			// far the rollout got before it stopped.
			counts := eng.Counts(members)
			done := counts[StateVerified] + counts[StateFailed] + counts[StateSkipped]
			s.announceHalt(ctx, rec, done, len(members))
		}
		return action
	}
	return nil
}

func contains(all []string, want string) bool {
	for _, v := range all {
		if v == want {
			return true
		}
	}
	return false
}

// engineFrom builds the pure engine's view of a stored rollout.
func engineFrom(rec *models.ImagingRollout, progress map[string]models.RolloutProgress) *Rollout {
	r := &Rollout{
		ID: rec.ID.String(), Bundle: rec.Bundle, Version: rec.Version,
		BundleURL: rec.BundleURL, State: rec.State, HaltReason: rec.HaltReason,
		Strategy: Strategy{
			Canary: rec.Canary, BatchSize: rec.BatchSize,
			SoakSeconds: rec.SoakSeconds, MaxFailures: rec.MaxFailures,
		},
		CanaryDoneAt:    rec.CanaryDoneAt,
		FailureBaseline: rec.FailureBaseline,
		Machines:        map[string]*MachineProgress{},
	}
	if rec.WindowStart != nil && rec.WindowEnd != nil {
		days := make([]int, 0, len(rec.WindowDays))
		for _, d := range rec.WindowDays {
			days = append(days, int(d))
		}
		r.Window = &Window{Start: *rec.WindowStart, End: *rec.WindowEnd, Days: days}
	}
	for id, p := range progress {
		r.Machines[id] = &MachineProgress{
			State: p.State, Error: p.Error, Attempts: p.Attempts, ChangedAt: p.ChangedAt,
		}
	}
	return r
}

func applyEngine(rec *models.ImagingRollout, r *Rollout) {
	rec.State = r.State
	rec.HaltReason = r.HaltReason
	rec.CanaryDoneAt = r.CanaryDoneAt
	rec.FailureBaseline = r.FailureBaseline
}

func progressFrom(r *Rollout) map[string]models.RolloutProgress {
	out := make(map[string]models.RolloutProgress, len(r.Machines))
	for id, m := range r.Machines {
		out[id] = models.RolloutProgress{
			State: m.State, Error: m.Error, Attempts: m.Attempts, ChangedAt: m.ChangedAt,
		}
	}
	return out
}

// Rollouts lists them with the counts an operator looks at.
func (s *Service) Rollouts(ctx context.Context) ([]models.ImagingRollout, error) {
	recs, err := s.store.ListRollouts(ctx)
	if err != nil {
		return nil, err
	}
	for i := range recs {
		if err := s.fill(ctx, &recs[i], false); err != nil {
			return nil, err
		}
	}
	return recs, nil
}

// RolloutDetail is one rollout including every machine's place in it.
func (s *Service) RolloutDetail(ctx context.Context, id uuid.UUID) (*models.ImagingRollout, error) {
	rec, err := s.store.GetRollout(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.fill(ctx, rec, true); err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *Service) fill(ctx context.Context, rec *models.ImagingRollout, detail bool) error {
	members, err := s.store.MachinesForTarget(ctx, rec.TargetGroups, rec.TargetHosts, rec.TargetAll)
	if err != nil {
		return err
	}
	progress, err := s.store.RolloutProgress(ctx, rec.ID)
	if err != nil {
		return err
	}
	eng := engineFrom(rec, progress)
	rec.Total = len(members)
	rec.Counts = eng.Counts(members)
	rec.Done = rec.Counts[StateVerified] + rec.Counts[StateFailed] + rec.Counts[StateSkipped]
	if detail {
		rec.Machines = map[string]models.RolloutProgress{}
		for _, id := range members {
			if p, ok := progress[id]; ok {
				rec.Machines[id] = p
			} else {
				rec.Machines[id] = models.RolloutProgress{State: StatePending}
			}
		}
	}
	return nil
}

// NewRollout is what an operator asked for.
//
// Carries its own JSON tags and is decoded into directly. There was a separate
// request struct beside the handler with exactly these fields, which is one
// definition of a rollout's inputs too many: the failure mode of two is that
// somebody adds a field to one of them.
//
// The pointers are the point of the struct. A rollout has real defaults --
// canary 1, batches of 10, a fifteen-minute soak, stop after 2 -- and zero is a
// meaningful value for every one of them. `"canary": 0` is "skip the canary",
// which is a different instruction from omitting the field, and only a pointer
// can tell those apart.
type NewRollout struct {
	Bundle      string      `json:"bundle"`
	BundleURL   string      `json:"bundleUrl"`
	Description string      `json:"description"`
	Groups      []uuid.UUID `json:"groups"`
	Hosts       []uuid.UUID `json:"hosts"`
	All         bool        `json:"all"`
	Canary      *int        `json:"canary"`
	BatchSize   *int        `json:"batchSize"`
	SoakSeconds *int        `json:"soakSeconds"`
	MaxFailures *int        `json:"maxFailures"`
	WindowStart string      `json:"windowStart"`
	WindowEnd   string      `json:"windowEnd"`
	WindowDays  []int32     `json:"windowDays"`
}

// CreateRollout records the intent. Nothing is sent anywhere by it: machines
// pick it up on their next check-in, and the reconcile loop asks the ones this
// server can reach to check in now.
func (s *Service) CreateRollout(ctx context.Context, req NewRollout, p *auth.Principal) (*models.ImagingRollout, error) {
	bundle := strings.TrimSpace(req.Bundle)
	if bundle == "" {
		return nil, errors.New("a bundle is required")
	}
	// The name is interpolated into a URL and a container path, so it must be a
	// plain filename from the library rather than anything with a path in it.
	if strings.ContainsAny(bundle, "/\\") || strings.Contains(bundle, "..") {
		return nil, errors.New("the bundle must be a filename in the bundle library")
	}
	if len(req.Groups) == 0 && len(req.Hosts) == 0 && !req.All {
		return nil, errors.New("a rollout needs a target: groups, hosts, or all")
	}

	info, err := s.BundleInfo(bundle)
	if err != nil {
		return nil, err
	}
	if info.Version == "" {
		// Without a version there is no way to tell a machine that installed the
		// bundle from one that did not, so the rollout could never finish.
		// Better to refuse at creation than to leave one running for ever.
		return nil, fmt.Errorf("%s has no version recorded beside it; rebuild it so "+
			"machines can be checked against it", bundle)
	}

	url := strings.TrimSpace(req.BundleURL)
	if url == "" {
		base := strings.TrimRight(s.cfg.ControlURL, "/")
		if base == "" {
			// Deliberately refused rather than guessed. The address that reaches
			// this UI is routinely not one a machine in the field can reach, and
			// a bundle URL a machine cannot fetch fails on the machine and
			// nowhere else.
			return nil, errors.New("set CONTROL_URL so machines are given a bundle " +
				"URL they can actually reach; the address you are using to read " +
				"this is usually not one they are on")
		}
		url = base + "/bundles/" + bundle
	}

	rec := &models.ImagingRollout{
		Bundle: bundle, Version: info.Version, BundleURL: url,
		Description:  strings.TrimSpace(req.Description),
		TargetGroups: req.Groups, TargetHosts: req.Hosts, TargetAll: req.All,
		Canary:      pick(req.Canary, 1),
		BatchSize:   maxInt(pick(req.BatchSize, 10), 1),
		SoakSeconds: pick(req.SoakSeconds, 900),
		MaxFailures: pick(req.MaxFailures, 2),
	}
	if req.WindowStart != "" && req.WindowEnd != "" {
		start, end := req.WindowStart, req.WindowEnd
		if _, err := parseHM(start); err != nil {
			return nil, errors.New("the window start must look like 22:00")
		}
		if _, err := parseHM(end); err != nil {
			return nil, errors.New("the window end must look like 04:00")
		}
		rec.WindowStart, rec.WindowEnd, rec.WindowDays = &start, &end, req.WindowDays
	}

	members, err := s.store.MachinesForTarget(ctx, rec.TargetGroups, rec.TargetHosts, rec.TargetAll)
	if err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return nil, errors.New("that target matches no machines")
	}

	var by *uuid.UUID
	if p != nil {
		by = &p.UserID
		rec.CreatedByName = p.Username
	}
	out, err := s.store.CreateRollout(ctx, rec, by)
	if err != nil {
		return nil, err
	}
	if err := s.fill(ctx, out, false); err != nil {
		return nil, err
	}
	return out, nil
}

func pick(v *int, def int) int {
	if v == nil || *v < 0 {
		return def
	}
	return *v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// notifyHalted is the alert. Kept separate from the bookkeeping in announceHalt
// so that "have we already said this" and "what do we say" are not tangled.
func (s *Service) notifyHalted(ctx context.Context, rec *models.ImagingRollout, done, total int) {
	s.nfy.Notify(ctx, notify.Event{
		Type:     notify.EventRolloutHalted,
		Severity: notify.SeverityError,
		Title:    "Rollout halted: " + rec.Version,
		Body: fmt.Sprintf("Rolling out %s stopped on its failure budget. %s "+
			"%d of %d machines were done.", rec.Bundle, rec.HaltReason, done, total),
		DedupeKey: "imaging-rollout-" + rec.ID.String(),
	})
}

// SteerRollout pauses, resumes or cancels one.
//
// Pausing stops further machines being offered the bundle; it does not recall it
// from a machine already installing, because there is no way to reach into an
// install and interrupting one is how a machine ends up on neither version.
func (s *Service) SteerRollout(ctx context.Context, id uuid.UUID, verb string) error {
	rec, err := s.store.GetRollout(ctx, id)
	if err != nil {
		return errors.New("no such rollout")
	}
	switch verb {
	case "pause":
		return s.store.SetRolloutState(ctx, id, RolloutPaused, "", rec.FailureBaseline)
	case "cancel":
		return s.store.SetRolloutState(ctx, id, RolloutCancelled, "", rec.FailureBaseline)
	case "resume":
		if rec.State != RolloutPaused && rec.State != RolloutHalted {
			return fmt.Errorf("rollout is %s, not paused", rec.State)
		}
		progress, err := s.store.RolloutProgress(ctx, id)
		if err != nil {
			return err
		}
		eng := engineFrom(rec, progress)
		// Forgives the failures that stopped it: the machines that failed stay
		// failed, and the budget counts from here. Without this a resumed
		// rollout re-halts on the very next heartbeat.
		eng.Resume()
		return s.store.SetRolloutState(ctx, id, RolloutRunning, "", eng.FailureBaseline)
	}
	return errors.New("verb must be pause, resume or cancel")
}

// announceHalt notifies once when a rollout stops itself on its failure budget.
//
// The event an operator most needs pushed at them rather than found: a halted
// rollout means machines failed an update and the rest of the fleet is
// deliberately not getting it, and nothing else will say so.
func (s *Service) announceHalt(ctx context.Context, rec *models.ImagingRollout, done, total int) {
	if s.nfy == nil {
		return
	}
	key := rec.ID.String()
	s.mu.Lock()
	already := s.halted[key]
	if rec.State == RolloutHalted {
		s.halted[key] = true
	} else {
		delete(s.halted, key)
	}
	s.mu.Unlock()
	if rec.State != RolloutHalted || already {
		return
	}
	s.notifyHalted(ctx, rec, done, total)
}
