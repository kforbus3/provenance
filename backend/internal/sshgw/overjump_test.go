package sshgw

import (
	"bytes"
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	princ "github.com/kforbus3/provenance/backend/internal/principals"
)

// Sessions opened over a shared jump connection must not own it: closing one
// leaves the jump connection working for the next, and the whole sequence costs
// the jump host a single handshake.
func TestSessionsOverOneJumpShareItAndDoNotOwnIt(t *testing.T) {
	ca := newTestCA(t)
	managed := startSSHD(t, ca, map[string][]string{"prov": {princ.Global}}, false)
	jumpd := startSSHD(t, ca, map[string][]string{"prov": {princ.Global}}, true)
	front := startThrottledJump(t, jumpd.addr, 0, true)

	g := testGateway(t, front.addr)
	g.cfg.JumpUser = "prov"
	cert := ca.sign(t, "system/monitor/1", []string{princ.Global})
	jump, err := g.DialJumpWithSigner(context.Background(), cert)
	if err != nil {
		t.Fatalf("dial jump: %v", err)
	}
	defer jump.Close()
	host, port := splitHostPort(t, managed.addr)

	for i := 0; i < 3; i++ {
		c, err := g.DialOverJump(context.Background(), jump, host, port, "prov", ssh.PublicKeys(cert))
		if err != nil {
			t.Fatalf("session %d over the shared jump: %v", i+1, err)
		}
		c.Close()
	}
	if n := front.accepted.Load(); n != 1 {
		t.Fatalf("expected 1 jump-host connection for 3 sessions, saw %d", n)
	}

	// A raw tunnel over the same connection reads the managed host's banner.
	tun, _, err := TunnelOverJump(context.Background(), jump, host, port)
	if err != nil {
		t.Fatalf("tunnel over the shared jump: %v", err)
	}
	defer tun.Close()
	_ = tun.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	n, _ := tun.Read(buf)
	if !bytes.HasPrefix(buf[:n], []byte("SSH-")) {
		t.Fatalf("expected an SSH banner through the tunnel, got %q", buf[:n])
	}

	// An address the jump host cannot resolve fails as a refused channel, and
	// costs no new connection.
	if _, _, err := TunnelOverJump(context.Background(), jump, "no-such-host.invalid", 22); err == nil {
		t.Fatal("expected a refusal for an unresolvable address")
	}
	if n := front.accepted.Load(); n != 1 {
		t.Fatalf("a failed tunnel opened a new jump connection: %d total", n)
	}
}
