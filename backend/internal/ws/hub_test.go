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

// A Session.Replay holder's cross-user visibility is scoped to its own tenant: an
// event tagged with another tenant must not reach it, so session activity (usernames,
// hostnames) never leaks across tenants over the events WS.
func TestBroadcastSessionTenantScoping(t *testing.T) {
	h := NewHub()
	owner := uuid.New()
	tenantA, tenantB := uuid.New(), uuid.New()

	add := func(uid, tid uuid.UUID, all bool) *client {
		c := &client{send: make(chan []byte, 1), userID: uid, tenantID: tid, allSessions: all}
		h.clients[c] = struct{}{}
		return c
	}
	sameTenantReplay := add(uuid.New(), tenantA, true)  // Replay holder in the owner's tenant
	otherTenantReplay := add(uuid.New(), tenantB, true) // Replay holder in a DIFFERENT tenant

	// Session owned by a user in tenantA.
	h.BroadcastSession("session.start", owner, map[string]any{"hostId": "h", "tenantId": tenantA.String()})

	if !received(sameTenantReplay) {
		t.Error("a Replay holder in the session's tenant should receive the event")
	}
	if received(otherTenantReplay) {
		t.Error("a Replay holder in another tenant must NOT receive the event")
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
