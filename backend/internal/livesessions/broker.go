package livesessions

import (
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
)

// Frame is one piece of live terminal activity fanned out to read-only watchers.
type Frame struct {
	Kind string // "o" = output bytes, "r" = resize
	Data []byte // output bytes when Kind == "o"
	Cols int    // when Kind == "r"
	Rows int
}

// Broker fans out a live terminal session's output (and resize events) to any
// number of read-only watchers, keyed by the SSH-session id. Watchers never feed
// input back — this is one-way oversight. A slow watcher drops frames rather than
// stalling the session that produced them.
type Broker struct {
	mu    sync.Mutex
	subs  map[uuid.UUID]map[uint64]chan Frame
	size  map[uuid.UUID][2]int // last known cols,rows per session (sent to a joiner)
	next  uint64
	total int64 // atomic: total live watchers, for a lock-free "anyone watching?" check
}

// NewBroker constructs an empty Broker.
func NewBroker() *Broker {
	return &Broker{subs: map[uuid.UUID]map[uint64]chan Frame{}, size: map[uuid.UUID][2]int{}}
}

// Active reports whether any watcher exists at all (lock-free). Publishers use it
// to skip copying output on the hot path when nobody is watching anything.
func (b *Broker) Active() bool { return atomic.LoadInt64(&b.total) > 0 }

// Publish delivers a frame to every watcher of sessionID. Non-blocking: a full
// watcher channel drops the frame. Resize frames also update the remembered size.
func (b *Broker) Publish(sessionID uuid.UUID, f Frame) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if f.Kind == "r" {
		b.size[sessionID] = [2]int{f.Cols, f.Rows}
	}
	for _, ch := range b.subs[sessionID] {
		select {
		case ch <- f:
		default: // slow watcher: drop rather than block the live session
		}
	}
}

// Watchers returns how many watchers a session currently has.
func (b *Broker) Watchers(sessionID uuid.UUID) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs[sessionID])
}

// Subscribe registers a watcher of sessionID, returning a frame channel, the last
// known terminal size (zero if unknown), and an unsubscribe func the caller must
// invoke when done.
func (b *Broker) Subscribe(sessionID uuid.UUID) (<-chan Frame, [2]int, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	id := b.next
	if b.subs[sessionID] == nil {
		b.subs[sessionID] = map[uint64]chan Frame{}
	}
	ch := make(chan Frame, 512)
	b.subs[sessionID][id] = ch
	atomic.AddInt64(&b.total, 1)
	size := b.size[sessionID]
	return ch, size, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if m := b.subs[sessionID]; m != nil {
			if _, ok := m[id]; ok {
				delete(m, id)
				close(ch)
				atomic.AddInt64(&b.total, -1)
			}
			if len(m) == 0 {
				delete(b.subs, sessionID)
			}
		}
	}
}

// Clear drops a finished session's remembered size (its watchers, if any, are
// closed out when their own connections end). Called when the session ends.
func (b *Broker) Clear(sessionID uuid.UUID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.size, sessionID)
}
