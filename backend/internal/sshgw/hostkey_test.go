package sshgw

import (
	"crypto/ed25519"
	"testing"

	"golang.org/x/crypto/ssh"
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
	v := newHostKeyVerifier(nil)
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
