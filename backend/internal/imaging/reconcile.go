package imaging

import (
	"context"
	"time"

	"github.com/kforbus3/blackfriars/backend/internal/models"
)

// Run drives rollouts forward by reaching the machines they are waiting on.
//
// This is the whole of the "push" that having one product rather than two makes
// possible. The rollout's rules are unchanged -- canary, soak, batch, window,
// budget all still apply, and every decision is still made when a machine asks.
// What this removes is the waiting: instead of a machine finding out on its own
// timer that there is an update for it, this asks it to check in now.
//
// leader gates the loop the same way the monitor sweep is gated: in a
// multi-instance deployment only one instance should be reaching out, or every
// host gets N simultaneous connections saying the same thing.
//
// Nothing runs at all unless a rollout is live. This is not a periodic sweep of
// the fleet; it is a response to an operator having started something.
func (s *Service) Run(ctx context.Context, leader func() bool) {
	if !s.cfg.ImagingNudge {
		return
	}
	t := time.NewTicker(reconcileEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if leader != nil && !leader() {
				continue
			}
			s.reconcile(ctx)
		}
	}
}

func (s *Service) reconcile(ctx context.Context) {
	rollouts, err := s.store.ListRollouts(ctx)
	if err != nil {
		// Debug, not warn: a transient database blip is not an event, and a
		// warning every thirty seconds would be its own problem.
		s.log.Debug("imaging: listing rollouts", "err", err)
		return
	}

	waiting := map[string]bool{}
	// Machines a rollout believes are mid-update. If one of them cannot reach
	// this server, nobody will ever say how it went and the rollout sits on it
	// until the offer times out -- recording a successful update as a failure.
	inFlight := map[string]bool{}
	live := false
	for i := range rollouts {
		rec := &rollouts[i]
		if rec.State != RolloutRunning {
			continue
		}
		live = true
		progress, err := s.store.RolloutProgress(ctx, rec.ID)
		if err != nil {
			continue
		}
		members, err := s.store.MachinesForTarget(ctx, rec.TargetGroups, rec.TargetHosts, rec.TargetAll)
		if err != nil {
			continue
		}
		for _, id := range members {
			p, ok := progress[id]
			if !ok || p.State == StatePending {
				waiting[id] = true
				continue
			}
			if inFlightState(p.State) {
				inFlight[id] = true
			}
		}
	}
	if !live || (len(waiting) == 0 && len(inFlight) == 0) {
		return
	}

	// The real fleet view, because both decisions below need what is in it: a
	// machine's host, so there is something to connect to, and its presence, so
	// this does not speak over a machine that reports perfectly well for itself.
	fleet, err := s.FleetView(ctx, nil)
	if err != nil {
		s.log.Warn("imaging: reading the fleet", "err", err)
		return
	}

	acted := 0
	for i := range fleet {
		m := fleet[i]
		if acted >= maxActionsPerPass {
			break
		}
		if !waiting[m.ID] && !inFlight[m.ID] {
			continue
		}
		if m.HostID == nil || !m.Reachable || m.Held {
			continue
		}
		// One action per machine per few minutes. Without this a machine that
		// takes twenty minutes to install would be reached on every pass for the
		// whole of it.
		s.mu.Lock()
		last, seen := s.touched[m.ID]
		fresh := seen && time.Since(last) < 5*time.Minute
		if !fresh {
			s.touched[m.ID] = time.Now()
		}
		s.mu.Unlock()
		if fresh {
			continue
		}

		host, err := s.store.GetHost(ctx, *m.HostID)
		if err != nil {
			continue
		}
		if inFlight[m.ID] {
			// Only when this server is not hearing from the machine itself. A
			// machine whose presence is online is checking in, and its own word
			// arrives on its own timer -- nothing here has business speaking
			// over it.
			if m.Presence == "online" {
				continue
			}
			acted++
			go s.settle(ctx, host, m.ID)
			continue
		}
		acted++
		go func(h *models.Host) {
			if _, err := s.Nudge(ctx, h); err != nil {
				// Not an alert. A nudge that fails costs latency and nothing
				// else -- the agent still polls -- and a fleet with a few
				// sleeping laptops would otherwise produce a steady drip of
				// warnings about a system that is working correctly.
				s.log.Debug("imaging: nudge", "host", h.Hostname, "err", err)
			}
		}(host)
	}
	if acted > 0 {
		s.log.Info("imaging: reached machines a rollout is waiting on", "count", acted)
	}
}

func inFlightState(state string) bool { return inFlight(state) }

// settle looks at a machine a rollout believes is mid-update and records what is
// actually there.
//
// Only for machines this server is not hearing from -- the caller checks
// presence. This is what lets a rollout finish across a site with no route back:
// the machine cannot report, so something that can reach it reports instead,
// about what it read off the host rather than about what it was told.
func (s *Service) settle(ctx context.Context, h *models.Host, machineID string) {
	obs, err := s.Observe(ctx, h)
	if err != nil {
		s.log.Debug("imaging: settling", "host", h.Hostname, "err", err)
		return
	}
	obs.ObservedBy = "system"
	// Deliberately no update_state: the version and health are what a rollout
	// decides from, and asserting a state as well would be guessing at a
	// machine's internal progress rather than reporting what was seen.
	s.recordObservation(ctx, machineID, obs)
}
