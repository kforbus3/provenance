package containerupdate

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/notify"
	"github.com/kforbus3/provenance/backend/internal/store"
)

type fakeNotifier struct {
	mu     sync.Mutex
	events []notify.Event
}

func (f *fakeNotifier) Notify(_ context.Context, ev notify.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
}

// A halted container rollout must tell somebody.
//
// It did not, for the whole life of the feature -- while the OS-image rollout
// beside it has raised rollout.halted since imaging shipped. A three-image rollout
// halted in this fleet at 16:01 with its second host left pending, and was found
// by somebody opening the page later and noticing a red chip. A fleet-wide update
// stopped partway, with hosts on two different versions, is not a thing to
// discover by eye.
func TestAHaltedRolloutRaisesANotification(t *testing.T) {
	f, _, _ := fixture(3, store.UpdateRollout{Canary: 0, BatchSize: 1, MaxFailures: 1})
	n := &fakeNotifier{}
	e := newEngine(f, &fakeDeployer{err: errors.New("nginx:1.24 → 1.27: manifest unknown")},
		&fakeRunner{out: runningNew})
	e.SetNotifier(n)
	e.Tick(context.Background()) // one host fails
	e.Tick(context.Background()) // budget spent: halt

	n.mu.Lock()
	defer n.mu.Unlock()
	var halt *notify.Event
	for i := range n.events {
		if n.events[i].Type == notify.EventContainerRolloutHalted {
			halt = &n.events[i]
		}
	}
	if halt == nil {
		t.Fatalf("a halted rollout raised no notification; events=%v", n.events)
	}
	if halt.Severity != notify.SeverityError {
		t.Errorf("severity %q, want error — a stopped fleet-wide update is not informational",
			halt.Severity)
	}
	// The title has to name the image: a rollout covering several images is listed
	// under the first one, and a notification that says only "a rollout halted"
	// sends the reader back to the page to find out which.
	if !strings.Contains(halt.Title, "nginx") {
		t.Errorf("the notification does not name the image: %q", halt.Title)
	}
	// And the body carries the reason, which is the thing that decides what to do.
	if !strings.Contains(halt.Body, "failed") {
		t.Errorf("the notification does not carry the halt reason: %q", halt.Body)
	}
}

// One notification per halt, not one per tick. The engine keeps ticking while a
// rollout is halted, and a notification channel that repeats every tick is one
// people filter.
func TestTheHaltNotificationIsNotRepeatedOnEveryTick(t *testing.T) {
	f, _, _ := fixture(3, store.UpdateRollout{Canary: 0, BatchSize: 1, MaxFailures: 1})
	n := &fakeNotifier{}
	e := newEngine(f, &fakeDeployer{err: errors.New("nope")}, &fakeRunner{out: runningNew})
	e.SetNotifier(n)
	for i := 0; i < 5; i++ {
		e.Tick(context.Background())
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	count := 0
	for _, ev := range n.events {
		if ev.Type == notify.EventContainerRolloutHalted {
			count++
		}
	}
	if count != 1 {
		t.Errorf("%d halt notifications for one halted rollout, want 1", count)
	}
}

// An engine with no notifier must still run rollouts.
func TestNoNotifierIsNotAFailure(t *testing.T) {
	f, rid, _ := fixture(1, store.UpdateRollout{Canary: 0, BatchSize: 1, MaxFailures: 1})
	e := newEngine(f, &fakeDeployer{err: errors.New("nope")}, &fakeRunner{out: runningNew})
	e.Tick(context.Background())
	e.Tick(context.Background())
	if len(f.hosts[rid]) == 0 {
		t.Fatal("fixture lost its host")
	}
}
