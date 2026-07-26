package sshgw

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/store"
)

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestHostKeyTOFU(t *testing.T) {
	v := newHostKeyVerifier(nil, nil)
	k1 := testKey(t)
	k2 := testKey(t)

	// First sight of a host pins its key and is accepted.
	if err := v.check("jumphost:22", nil, k1); err != nil {
		t.Fatalf("first connect should pin+accept: %v", err)
	}
	// Same key again → accepted.
	if err := v.check("jumphost:22", nil, k1); err != nil {
		t.Fatalf("same key should be accepted: %v", err)
	}
	// Different key for the same host → refused (possible MITM).
	if err := v.check("jumphost:22", nil, k2); err == nil {
		t.Fatal("changed host key should be refused")
	}
	// A different host is independent — its first key is pinned+accepted.
	if err := v.check("10.100.0.22:22", nil, k2); err != nil {
		t.Fatalf("different host should pin independently: %v", err)
	}
}

// fakePinStore is an in-memory hostKeyPinStore for testing persistence behavior.
type fakePinStore struct {
	pins   map[string]store.HostKeyPin
	getErr error
}

func (f *fakePinStore) GetHostKey(_ context.Context, host string) (store.HostKeyPin, bool, error) {
	if f.getErr != nil {
		return store.HostKeyPin{}, false, f.getErr
	}
	p, ok := f.pins[host]
	return p, ok, nil
}
func (f *fakePinStore) PinHostKey(_ context.Context, host, line, typ string) error {
	if f.pins == nil {
		f.pins = map[string]store.HostKeyPin{}
	}
	if _, ok := f.pins[host]; !ok { // ON CONFLICT DO NOTHING
		f.pins[host] = store.HostKeyPin{Host: host, KeyLine: line, KeyType: typ, Source: "tofu"}
	}
	return nil
}

// TestHostKeyPersistedPinSurvivesRestart proves a pin written by one verifier instance is
// enforced by a fresh instance sharing the store (i.e. across a simulated restart), and
// that a mismatching key is then refused — the whole point of persisting pins.
func TestHostKeyPersistedPinSurvivesRestart(t *testing.T) {
	st := &fakePinStore{pins: map[string]store.HostKeyPin{}}
	k1, k2 := testKey(t), testKey(t)

	// First process pins k1 for the host.
	v1 := newHostKeyVerifier(st, nil)
	if err := v1.check("host-a:2222", nil, k1); err != nil {
		t.Fatalf("first pin should accept: %v", err)
	}
	// knownhosts normalizes a non-default port to "[host]:port".
	if _, ok := st.pins["[host-a]:2222"]; !ok {
		t.Fatalf("pin was not persisted to the store; keys=%v", st.pins)
	}

	// A fresh verifier (empty memory cache) must load the pin and enforce it.
	v2 := newHostKeyVerifier(st, nil)
	if err := v2.check("host-a:2222", nil, k1); err != nil {
		t.Fatalf("persisted pin should be accepted after restart: %v", err)
	}
	if err := v2.check("host-a:2222", nil, k2); err == nil {
		t.Fatal("a different key must be refused against the persisted pin (MITM/rebuild)")
	}
}

// TestHostKeyLookupErrorFailsClosed proves a store lookup error refuses the connection
// rather than blindly re-pinning (which could trust a MITM key).
func TestHostKeyLookupErrorFailsClosed(t *testing.T) {
	st := &fakePinStore{getErr: errors.New("db down")}
	v := newHostKeyVerifier(st, nil)
	if err := v.check("host-b:22", nil, testKey(t)); err == nil {
		t.Fatal("a pin-lookup error must refuse the connection, not accept it")
	}
}
