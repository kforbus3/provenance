package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
)

// newCred builds a minimal live credential for vault tests. The private key is
// real so zeroization can be asserted.
func newCred(session, host, user uuid.UUID, serial uint64) *Credential {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &Credential{
		SessionID: session, HostID: host, UserID: user, Serial: serial,
		ExpiresAt: time.Now().Add(time.Hour), privateKey: priv,
	}
}

func TestVaultSessionAndHostScoping(t *testing.T) {
	v := NewVault()
	session := uuid.New()
	hostA := uuid.New()
	hostB := uuid.New()
	user := uuid.New()

	v.put(newCred(session, sessionScope, user, 1)) // session-level
	v.put(newCred(session, hostA, user, 2))
	v.put(newCred(session, hostB, user, 3))

	// Session-level lookup returns the session credential, not a host one.
	if c, ok := v.Get(session); !ok || c.Serial != 1 {
		t.Fatalf("Get(session) = %v ok=%v; want serial 1", c, ok)
	}
	// Each host has its own distinct credential/serial.
	if c, ok := v.GetHost(session, hostA); !ok || c.Serial != 2 {
		t.Fatalf("GetHost(A) = %v ok=%v; want serial 2", c, ok)
	}
	if c, ok := v.GetHost(session, hostB); !ok || c.Serial != 3 {
		t.Fatalf("GetHost(B) = %v ok=%v; want serial 3", c, ok)
	}
	// An unknown host has no credential.
	if _, ok := v.GetHost(session, uuid.New()); ok {
		t.Fatal("GetHost(unknown) unexpectedly returned a credential")
	}
}

func TestVaultDestroyZeroizesAllSessionCredentials(t *testing.T) {
	v := NewVault()
	session := uuid.New()
	host := uuid.New()
	user := uuid.New()

	sessCred := newCred(session, sessionScope, user, 1)
	hostCred := newCred(session, host, user, 2)
	v.put(sessCred)
	v.put(hostCred)

	// Capture the underlying key byte slices before Destroy so we can confirm they
	// were scrubbed in place (Destroy also drops the reference).
	sessKey := sessCred.privateKey.(ed25519.PrivateKey)
	hostKey := hostCred.privateKey.(ed25519.PrivateKey)

	if !v.Destroy(session) {
		t.Fatal("Destroy returned false for a live session")
	}
	// Both the session-level and per-host credentials are gone.
	if _, ok := v.Get(session); ok {
		t.Fatal("session credential survived Destroy")
	}
	if _, ok := v.GetHost(session, host); ok {
		t.Fatal("per-host credential survived Destroy")
	}
	// Private key bytes were zeroized for both.
	for _, b := range sessKey {
		if b != 0 {
			t.Fatal("session private key not zeroized")
		}
	}
	for _, b := range hostKey {
		if b != 0 {
			t.Fatal("host private key not zeroized")
		}
	}
}

func TestVaultPutReplacesAndZeroizesPrevious(t *testing.T) {
	v := NewVault()
	session := uuid.New()
	host := uuid.New()
	user := uuid.New()

	first := newCred(session, host, user, 10)
	firstKey := first.privateKey.(ed25519.PrivateKey)
	v.put(first)
	second := newCred(session, host, user, 11)
	v.put(second)

	if c, ok := v.GetHost(session, host); !ok || c.Serial != 11 {
		t.Fatalf("GetHost after replace = %v ok=%v; want serial 11", c, ok)
	}
	for _, b := range firstKey {
		if b != 0 {
			t.Fatal("replaced credential's private key not zeroized")
		}
	}
}

func TestVaultDestroyIsolatesSessions(t *testing.T) {
	v := NewVault()
	user := uuid.New()
	s1, s2 := uuid.New(), uuid.New()
	host := uuid.New()
	v.put(newCred(s1, host, user, 1))
	v.put(newCred(s2, host, user, 2))

	v.Destroy(s1)
	if _, ok := v.GetHost(s1, host); ok {
		t.Fatal("s1 host credential survived its Destroy")
	}
	if _, ok := v.GetHost(s2, host); !ok {
		t.Fatal("s2 host credential wrongly removed by s1 Destroy")
	}
}
