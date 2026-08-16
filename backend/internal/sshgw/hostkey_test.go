package sshgw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/kforbus3/Moorgate/backend/internal/store"
)

// memPins is an in-memory hostKeyPinStore standing in for the database.
type memPins struct {
	pins map[string]store.HostKeyPin
}

func newMemPins() *memPins { return &memPins{pins: map[string]store.HostKeyPin{}} }

func (m *memPins) GetHostKey(_ context.Context, host string) (store.HostKeyPin, bool, error) {
	p, ok := m.pins[host]
	return p, ok, nil
}

func (m *memPins) PinHostKey(_ context.Context, host, keyLine, keyType string) error {
	if _, exists := m.pins[host]; exists {
		return nil // mirrors ON CONFLICT DO NOTHING
	}
	m.pins[host] = store.HostKeyPin{Host: host, KeyLine: keyLine, KeyType: keyType, Source: "tofu"}
	return nil
}

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}
	return sk
}

// Clearing a pin has to clear the in-process cache as well as the stored row.
// The verifier caches every pin it enforces, so deleting only the database row
// leaves a running backend refusing the host's new key — which is what made
// "remove its pin to re-trust" look like it did nothing.
func TestForgetHostKeysDropsTheCachedPin(t *testing.T) {
	pins := newMemPins()
	v := newHostKeyVerifier(pins, nil)
	old, rebuilt := testKey(t), testKey(t)

	if err := v.check("host.example:22", nil, old); err != nil {
		t.Fatalf("first contact should pin, got %v", err)
	}
	if err := v.check("host.example:22", nil, rebuilt); err == nil {
		t.Fatal("a changed host key must be refused while the pin stands")
	}

	// Operator clears the pin: the stored row goes, and so must the cache.
	delete(pins.pins, "host.example")
	if err := v.check("host.example:22", nil, rebuilt); err == nil {
		t.Error("cached pin still enforced after the row was deleted — ForgetHostKeys is required")
	}
	v.ForgetHostKeys("host.example")
	if err := v.check("host.example:22", nil, rebuilt); err != nil {
		t.Errorf("after clearing the pin the new key must be accepted, got %v", err)
	}
	if got := pins.pins["host.example"].KeyLine; got != string(ssh.MarshalAuthorizedKey(rebuilt)) {
		t.Error("the re-trusted key should have been re-pinned")
	}
}

// The identity a pin is stored under is the dialed address normalized the way
// the verifier normalizes it — including dropping the default port. A host
// reachable at several addresses holds several pins, and HostKeyID is what the
// clear-pin endpoint uses to find all of them.
func TestHostKeyIDMatchesWhatTheVerifierPins(t *testing.T) {
	pins := newMemPins()
	v := newHostKeyVerifier(pins, nil)
	for _, tc := range []struct {
		addr string
		port int
	}{
		{"10.100.0.26", 22},
		{"debian-ab-test", 22},
		{"10.100.0.26", 2222},
	} {
		target := tc.addr + ":" + strconv.Itoa(tc.port)
		if err := v.check(target, nil, testKey(t)); err != nil {
			t.Fatalf("pin %s: %v", target, err)
		}
		id := HostKeyID(tc.addr, tc.port)
		if _, ok := pins.pins[id]; !ok {
			var have []string
			for k := range pins.pins {
				have = append(have, k)
			}
			t.Errorf("HostKeyID(%q,%d)=%q does not match any stored pin %v", tc.addr, tc.port, id, have)
		}
	}
}

// Clearing a host's trust means clearing every address it is dialed as. The set
// is built from the host record (overlay address, management address, hostname),
// where blanks and duplicates are both normal — an unset management address, or a
// hostname that is also the dialed address. Each identity produced must be one the
// verifier would actually pin, or a clear silently leaves a live pin behind.
func TestHostKeyIDsCoverEveryDialedAddress(t *testing.T) {
	// The arrangement that stranded debian-ab-test: overlay address set, management
	// address empty, hostname distinct — two pins, one of them easy to overlook.
	ids := HostKeyIDs(22, "10.100.0.26", "", "debian-ab-test")
	if len(ids) != 2 {
		t.Fatalf("expected both dialed identities, got %v", ids)
	}

	pins := newMemPins()
	v := newHostKeyVerifier(pins, nil)
	for _, target := range []string{"10.100.0.26:22", "debian-ab-test:22"} {
		if err := v.check(target, nil, testKey(t)); err != nil {
			t.Fatalf("pin %s: %v", target, err)
		}
	}
	for _, id := range ids {
		if _, ok := pins.pins[id]; !ok {
			t.Errorf("identity %q matches no pin the verifier recorded", id)
		}
	}
	if len(pins.pins) != len(ids) {
		t.Errorf("clearing %v would leave pins behind: verifier holds %d", ids, len(pins.pins))
	}

	// Duplicates collapse, and a non-default port is part of the identity.
	if got := HostKeyIDs(22, "web-01", "web-01"); len(got) != 1 {
		t.Errorf("duplicate addresses should collapse, got %v", got)
	}
	if got := HostKeyIDs(2222, "web-01"); got[0] == HostKeyIDs(22, "web-01")[0] {
		t.Error("a non-default port must produce a distinct identity")
	}
	if got := HostKeyIDs(0, "web-01"); got[0] != HostKeyIDs(22, "web-01")[0] {
		t.Error("an unset port should be treated as 22, matching the dial")
	}
}

func TestPinFingerprintRendersSSHFormat(t *testing.T) {
	key := testKey(t)
	got := PinFingerprint(string(ssh.MarshalAuthorizedKey(key)))
	if want := ssh.FingerprintSHA256(key); got != want {
		t.Errorf("fingerprint = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, "SHA256:") {
		t.Errorf("fingerprint %q should be the SHA256 form ssh prints", got)
	}
	if PinFingerprint("not a key") != "" {
		t.Error("an unparseable pin should render empty, not panic")
	}
}
