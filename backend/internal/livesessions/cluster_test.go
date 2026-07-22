package livesessions

import (
	"sync"
	"testing"

	"github.com/google/uuid"
)

// TestBrokerClusterMirror verifies the cross-instance bridge: an owner mirrors a
// local session's frames to peers ONLY while a peer is watching, and the watcher
// side announces/withdraws interest exactly once.
func TestBrokerClusterMirror(t *testing.T) {
	b := NewBroker()
	sid := uuid.New()

	var mu sync.Mutex
	var mirrored []Frame
	var wants []bool
	b.SetPeer(
		func(_ uuid.UUID, f Frame) { mu.Lock(); mirrored = append(mirrored, f); mu.Unlock() },
		func(_ uuid.UUID, want bool) { mu.Lock(); wants = append(wants, want); mu.Unlock() },
	)

	// Owner side: mark the session local and seed a size.
	b.RegisterLocal(sid)
	if !b.IsLocal(sid) {
		t.Fatal("session should be local after RegisterLocal")
	}
	b.Publish(sid, Frame{Kind: "r", Cols: 80, Rows: 24})

	// No remote watcher yet → output is NOT mirrored to peers.
	b.Publish(sid, Frame{Kind: "o", Data: []byte("before")})
	mu.Lock()
	if len(mirrored) != 0 {
		t.Fatalf("expected no mirroring before a remote watcher, got %d frames", len(mirrored))
	}
	mu.Unlock()

	// A peer subscribes → owner should start mirroring, and re-send the current size.
	b.RemoteWatchStart(sid, "peer-B")
	if !b.Active() {
		t.Error("Active() must be true while a remote watcher exists (drives the PTY publish gate)")
	}
	b.Publish(sid, Frame{Kind: "o", Data: []byte("after")})

	mu.Lock()
	var sawResize, sawAfter bool
	for _, f := range mirrored {
		if f.Kind == "r" && f.Cols == 80 {
			sawResize = true
		}
		if f.Kind == "o" && string(f.Data) == "after" {
			sawAfter = true
		}
	}
	mu.Unlock()
	if !sawResize {
		t.Error("owner should mirror the current size to a joining remote watcher")
	}
	if !sawAfter {
		t.Error("owner should mirror output produced while a remote watcher is attached")
	}

	// Peer leaves → mirroring stops and the demand counter clears.
	b.RemoteWatchStop(sid, "peer-B")
	if b.Active() {
		t.Error("Active() must be false once the last remote watcher leaves")
	}
	mu.Lock()
	n := len(mirrored)
	mu.Unlock()
	b.Publish(sid, Frame{Kind: "o", Data: []byte("gone")})
	mu.Lock()
	if len(mirrored) != n {
		t.Error("owner must not mirror after the remote watcher left")
	}
	mu.Unlock()

	// Watcher side: WantRemote announces once, ReleaseRemote withdraws once, even with
	// two overlapping local watchers of the same remote session.
	other := uuid.New()
	b.WantRemote(other)
	b.WantRemote(other)
	b.ReleaseRemote(other)
	b.ReleaseRemote(other)
	mu.Lock()
	defer mu.Unlock()
	if len(wants) != 2 || wants[0] != true || wants[1] != false {
		t.Fatalf("expected exactly [true,false] peer-want signals, got %v", wants)
	}
}
