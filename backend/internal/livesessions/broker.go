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

	// Cluster bridge (HA): lets a watcher on one instance shadow a session whose PTY
	// lives on another. All fields nil/empty and inert in a single-instance deployment.
	local     map[uuid.UUID]struct{}            // sessions whose PTY is on THIS instance
	remoteOut map[uuid.UUID]map[string]struct{} // owner side: peer instances watching a local session
	remoteIn  map[uuid.UUID]int                 // watcher side: local watchers of a remote session
	peerPub   func(sid uuid.UUID, f Frame)      // mirror a local session's frame to peers
	peerWant  func(sid uuid.UUID, want bool)    // tell peers this instance (stops) wanting a session
}

// NewBroker constructs an empty Broker.
func NewBroker() *Broker {
	return &Broker{
		subs: map[uuid.UUID]map[uint64]chan Frame{}, size: map[uuid.UUID][2]int{},
		local: map[uuid.UUID]struct{}{}, remoteOut: map[uuid.UUID]map[string]struct{}{},
		remoteIn: map[uuid.UUID]int{},
	}
}

// SetPeer wires the cluster bridge: peerPub mirrors a locally-produced frame to
// other instances, peerWant announces this instance's interest in a remote session.
// Called once at startup; leaving it unset keeps the broker single-instance.
func (b *Broker) SetPeer(peerPub func(sid uuid.UUID, f Frame), peerWant func(sid uuid.UUID, want bool)) {
	b.mu.Lock()
	b.peerPub, b.peerWant = peerPub, peerWant
	b.mu.Unlock()
}

// RegisterLocal marks a session's PTY as living on this instance, so this instance
// answers peers' shadow requests for it. UnregisterLocal (or Clear) reverses it.
func (b *Broker) RegisterLocal(sessionID uuid.UUID) {
	b.mu.Lock()
	b.local[sessionID] = struct{}{}
	b.mu.Unlock()
}

// IsLocal reports whether the session's PTY is on this instance.
func (b *Broker) IsLocal(sessionID uuid.UUID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.local[sessionID]
	return ok
}

// RemoteWatchStart records that peer `origin` wants to shadow a session this
// instance owns; subsequent frames are mirrored to peers. Ignored if the session
// isn't local here (only the owner mirrors). Sends the current size immediately so
// a joiner sizes its terminal without waiting for the next resize.
func (b *Broker) RemoteWatchStart(sessionID uuid.UUID, origin string) {
	b.mu.Lock()
	if _, ok := b.local[sessionID]; !ok {
		b.mu.Unlock()
		return
	}
	if b.remoteOut[sessionID] == nil {
		b.remoteOut[sessionID] = map[string]struct{}{}
	}
	_, existed := b.remoteOut[sessionID][origin]
	b.remoteOut[sessionID][origin] = struct{}{}
	size := b.size[sessionID]
	pub := b.peerPub
	b.mu.Unlock()
	if !existed {
		// Count remote demand in the same atomic the PTY's lock-free Active() gate
		// reads, so the owner keeps publishing even with no LOCAL watcher.
		atomic.AddInt64(&b.total, 1)
	}
	if pub != nil && size[0] > 0 && size[1] > 0 {
		pub(sessionID, Frame{Kind: "r", Cols: size[0], Rows: size[1]})
	}
}

// RemoteWatchStop drops peer `origin`'s interest in a local session.
func (b *Broker) RemoteWatchStop(sessionID uuid.UUID, origin string) {
	b.mu.Lock()
	removed := false
	if m := b.remoteOut[sessionID]; m != nil {
		if _, ok := m[origin]; ok {
			delete(m, origin)
			removed = true
		}
		if len(m) == 0 {
			delete(b.remoteOut, sessionID)
		}
	}
	b.mu.Unlock()
	if removed {
		atomic.AddInt64(&b.total, -1)
	}
}

// WantRemote is called when a local watcher subscribes to a session owned by
// another instance: on the first such watcher it announces interest to peers so the
// owner starts mirroring. Balanced by ReleaseRemote.
func (b *Broker) WantRemote(sessionID uuid.UUID) {
	b.mu.Lock()
	b.remoteIn[sessionID]++
	first := b.remoteIn[sessionID] == 1
	want := b.peerWant
	b.mu.Unlock()
	if first && want != nil {
		want(sessionID, true)
	}
}

// ReleaseRemote balances WantRemote; on the last watcher it tells the owner to stop.
func (b *Broker) ReleaseRemote(sessionID uuid.UUID) {
	b.mu.Lock()
	if b.remoteIn[sessionID] > 0 {
		b.remoteIn[sessionID]--
	}
	last := b.remoteIn[sessionID] == 0
	if last {
		delete(b.remoteIn, sessionID)
	}
	want := b.peerWant
	b.mu.Unlock()
	if last && want != nil {
		want(sessionID, false)
	}
}

// Active reports whether any watcher exists at all (lock-free). Publishers use it
// to skip copying output on the hot path when nobody is watching anything.
func (b *Broker) Active() bool { return atomic.LoadInt64(&b.total) > 0 }

// Publish delivers a frame to every watcher of sessionID. Non-blocking: a full
// watcher channel drops the frame. Resize frames also update the remembered size.
func (b *Broker) Publish(sessionID uuid.UUID, f Frame) {
	b.mu.Lock()
	if f.Kind == "r" {
		b.size[sessionID] = [2]int{f.Cols, f.Rows}
	}
	for _, ch := range b.subs[sessionID] {
		select {
		case ch <- f:
		default: // slow watcher: drop rather than block the live session
		}
	}
	// Mirror to peers only when some other instance is shadowing this session, so a
	// session with no remote watcher costs nothing on the wire.
	mirror := b.peerPub != nil && len(b.remoteOut[sessionID]) > 0
	pub := b.peerPub
	b.mu.Unlock()
	if mirror {
		pub(sessionID, f) // async + chunked in the adapter; never blocks the PTY
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

// Clear drops a finished session's remembered size and marks it no longer local.
// remoteOut is intentionally left for each remote watcher's own unsubscribe to
// balance (it decrements the shared watcher counter), so it is NOT cleared here —
// the final "end" frame published just before Clear has already told those watchers
// to disconnect. Called when the session ends.
func (b *Broker) Clear(sessionID uuid.UUID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.size, sessionID)
	delete(b.local, sessionID)
}
