package ws

import (
	"testing"

	"github.com/google/uuid"
)

func received(c *client) bool {
	select {
	case <-c.send:
		return true
	default:
		return false
	}
}

// BroadcastSession must reach the session's own user and any Session.Replay
// holder (allSessions), but never an unrelated user — so one user's activity does
// not leak to every connected dashboard.
func TestBroadcastSessionFiltering(t *testing.T) {
	h := NewHub()
	owner, other := uuid.New(), uuid.New()
	add := func(uid uuid.UUID, all bool) *client {
		c := &client{send: make(chan []byte, 1), userID: uid, allSessions: all}
		h.clients[c] = struct{}{}
		return c
	}
	ownerC := add(owner, false)
	otherC := add(other, false)
	replayC := add(other, true) // holds Session.Replay → sees all sessions

	h.BroadcastSession("session.start", owner, map[string]any{"hostId": "h"})

	if !received(ownerC) {
		t.Error("session owner should receive their own session event")
	}
	if received(otherC) {
		t.Error("an unrelated user must NOT receive another user's session event")
	}
	if !received(replayC) {
		t.Error("a Session.Replay holder should receive all session events")
	}
}

// Broadcast (global, e.g. host.status) reaches every client regardless of user.
func TestBroadcastGlobalReachesAll(t *testing.T) {
	h := NewHub()
	a := &client{send: make(chan []byte, 1), userID: uuid.New()}
	b := &client{send: make(chan []byte, 1), userID: uuid.New()}
	h.clients[a] = struct{}{}
	h.clients[b] = struct{}{}

	h.Broadcast("host.status", map[string]any{"status": "online"})

	if !received(a) || !received(b) {
		t.Error("global broadcast should reach every client")
	}
}
