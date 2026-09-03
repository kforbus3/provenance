package imaging

import (
	"sort"
	"sync"
	"time"
)

// Live state of machines being imaged right now.
//
// The imager posts a line every time it changes phase. This keeps the most
// recent one per machine and forgets it again once the machine has finished or
// gone quiet, so the page shows what is happening at this moment rather than a
// growing list of everything that ever booted.
//
// Deliberately in memory, and deliberately not in the database next to
// ImagingMachine. The two answer different questions. A machine record is the
// durable fact that this fleet contains a machine; this is a progress bar for a
// twenty-minute run. Persisting it would mean carrying stale rows across
// restarts and having to expire them there too, and a restart loses nothing
// that is not re-reported within seconds by any machine still running.
//
// What *is* persisted is the pair of moments that bracket the run: ImagedAt when
// a machine reports `done`, and BootedAt when it checks in from the installed
// system. Those are what answer "did it come back", which is the question the
// progress bar cannot.

const (
	// How long a machine may go without reporting before it is treated as gone.
	// The imager reports on phase changes rather than on a timer, and writing a
	// large image to a slow disk is a long silence, so this is generous: holding
	// a dead machine a little longer costs a stale row, while expiring a live one
	// mid-write makes the page lie about a machine that is working fine.
	staleAfter = 10 * time.Minute
	// How long a finished machine stays visible. Long enough to see that it
	// succeeded, short enough that the page returns to showing only active work.
	keepFinished = 90 * time.Second
	// When a machine that has not finished is called stalled rather than active.
	stalledAfter = 2 * time.Minute
)

// phaseFloor is the share of a run each phase represents. The imager reports a
// percentage for the long phases; the rest are derived so that a machine which
// has only said "detected" does not sit at 0 and look stuck.
var phaseFloor = map[string]int{
	"booted": 0, "detected": 5, "downloading": 10, "writing": 15,
	"verified": 90, "expanding": 95, "done": 100, "failed": 0,
}

func terminalPhase(p string) bool { return p == "done" || p == "failed" }

// PhaseChange is one step of a run, kept so an operator looking at a stuck
// machine can see how far it got rather than only where it stopped.
type PhaseChange struct {
	Phase string    `json:"phase"`
	At    time.Time `json:"at"`
}

// Imaging is one machine's progress through a run.
type Imaging struct {
	ID         string        `json:"id"`
	Phase      string        `json:"phase"`
	Percent    int           `json:"percent"`
	Detail     string        `json:"detail,omitempty"`
	Disk       string        `json:"disk,omitempty"`
	Image      string        `json:"image,omitempty"`
	Address    string        `json:"address,omitempty"`
	FirstSeen  time.Time     `json:"firstSeen"`
	LastSeen   time.Time     `json:"lastSeen"`
	FinishedAt *time.Time    `json:"finishedAt,omitempty"`
	History    []PhaseChange `json:"history"`

	// Derived on read.
	State     string  `json:"state"` // active | stalled | done | failed
	AgeSecs   float64 `json:"ageSeconds"`
	StaleSecs float64 `json:"staleSeconds"`
}

type progressRegistry struct {
	mu   sync.Mutex
	rows map[string]*Imaging
}

func newProgressRegistry() *progressRegistry {
	return &progressRegistry{rows: map[string]*Imaging{}}
}

// Report records one progress report from a machine being imaged.
func (r *progressRegistry) Report(id, phase string, percent *int, detail, disk, image, address string) Imaging {
	now := time.Now()
	floor := phaseFloor[phase]
	pct := floor
	if percent != nil && *percent > floor {
		pct = *percent
	}
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[id]
	if !ok {
		row = &Imaging{ID: id, FirstSeen: now}
		r.rows[id] = row
	}
	if n := len(row.History); n == 0 || row.History[n-1].Phase != phase {
		row.History = append(row.History, PhaseChange{Phase: phase, At: now})
	}
	row.Phase = phase
	row.Percent = pct
	// Each of these keeps its previous value when the new report omits it. A
	// machine reports the disk once, when it picks one, and every later report
	// leaves the field empty -- blanking it on each one would make the page
	// forget which disk is being written half a second after saying so.
	if detail != "" {
		row.Detail = detail
	}
	if disk != "" {
		row.Disk = disk
	}
	if image != "" {
		row.Image = image
	}
	if address != "" {
		row.Address = address
	}
	row.LastSeen = now
	if terminalPhase(phase) {
		at := now
		row.FinishedAt = &at
	} else {
		row.FinishedAt = nil
	}
	out := *row
	out.History = append([]PhaseChange(nil), row.History...)
	return out
}

// Active is the machines worth showing, newest activity first, with the dead
// removed. Expiry happens here rather than on a timer for the same reason the
// rollout engine sweeps on demand: the only moment the answer matters is when
// somebody is asking.
func (r *progressRegistry) Active() []Imaging {
	now := time.Now()
	r.mu.Lock()
	for id, row := range r.rows {
		if terminalPhase(row.Phase) {
			done := row.LastSeen
			if row.FinishedAt != nil {
				done = *row.FinishedAt
			}
			if now.Sub(done) > keepFinished {
				delete(r.rows, id)
			}
			continue
		}
		// Stopped reporting without finishing: powered off, rebooted into the
		// new image, or fell off the network. Either way it is not imaging now,
		// which is what this list is about.
		if now.Sub(row.LastSeen) > staleAfter {
			delete(r.rows, id)
		}
	}
	out := make([]Imaging, 0, len(r.rows))
	for _, row := range r.rows {
		v := *row
		v.History = append([]PhaseChange(nil), row.History...)
		v.AgeSecs = now.Sub(v.FirstSeen).Seconds()
		v.StaleSecs = now.Sub(v.LastSeen).Seconds()
		switch {
		case v.Phase == "failed":
			v.State = "failed"
		case v.Phase == "done":
			v.State = "done"
		case now.Sub(v.LastSeen) > stalledAfter:
			v.State = "stalled"
		default:
			v.State = "active"
		}
		out = append(out, v)
	}
	r.mu.Unlock()

	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// Forget drops a row by hand, for a machine that will never report again.
func (r *progressRegistry) Forget(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.rows[id]
	delete(r.rows, id)
	return ok
}
