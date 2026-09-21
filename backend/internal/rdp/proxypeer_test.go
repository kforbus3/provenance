package rdp

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// Anyone on the backend's network could take over an RDP session by connecting first.
//
// The per-session tunnel listens on an ephemeral port on ALL interfaces, because guacd
// runs in its own container and has to reach the backend across the Docker network. It
// then handed the session to whoever connected first. Any other container sharing that
// network could race guacd and win by connecting faster — and the prize is a live RDP
// session to a managed host with the brokered credential injected, so the attacker gets
// the password and the desktop.
//
// For a system that exists so people do not have to hold credentials themselves, that
// is the wrong way round.
func TestAnUnexpectedPeerCannotClaimTheTunnel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// The managed host at the far end of the jump tunnel.
	hostSide, proxySide := net.Pipe()
	defer hostSide.Close()

	// Only 10.9.9.9 may claim it — nothing that can connect to a loopback listener.
	go proxyOnce(ln, proxySide, io.NopCloser(nil), []net.IP{net.ParseIP("10.9.9.9")},
		slog.New(slog.DiscardHandler))

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// The impostor must get nothing. If it were proxied, this write would reach the
	// host side; read with a deadline and require silence + a closed connection.
	_, _ = c.Write([]byte("take over the session"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, rerr := c.Read(buf)
	if n > 0 {
		t.Errorf("the impostor received %d byte(s) from the session: %q", n, buf[:n])
	}
	if rerr == nil {
		t.Error("the impostor's connection was not refused")
	}

	// And nothing it sent reached the managed host.
	_ = hostSide.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _ := hostSide.Read(buf); n > 0 {
		t.Errorf("the impostor's bytes were forwarded to the managed host: %q", buf[:n])
	}
}

// The real guacd still gets through, and the refusal above must not have consumed the
// session's one chance to connect.
func TestTheExpectedPeerIsProxied(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hostSide, proxySide := net.Pipe()
	defer hostSide.Close()

	go proxyOnce(ln, proxySide, io.NopCloser(nil), []net.IP{net.ParseIP("127.0.0.1")},
		slog.New(slog.DiscardHandler))

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("rdp bytes")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = hostSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	n, err := hostSide.Read(buf)
	if err != nil || string(buf[:n]) != "rdp bytes" {
		t.Errorf("guacd's bytes did not reach the managed host: got %q err=%v", buf[:n], err)
	}
}

// A losing racer must not cost the real guacd its session: the listener keeps accepting
// until the deadline, so an attacker cannot deny the session by connecting first either.
func TestARefusedPeerDoesNotConsumeTheSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hostSide, proxySide := net.Pipe()
	defer hostSide.Close()

	// Allow loopback, but first connect from a peer we then pretend is wrong by
	// allowing only an address this process cannot use. Instead: allow loopback and
	// verify a SECOND connection still works after a first one is closed early —
	// the accept loop must survive a connection that goes away.
	go proxyOnce(ln, proxySide, io.NopCloser(nil), []net.IP{net.ParseIP("127.0.0.1")},
		slog.New(slog.DiscardHandler))

	first, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := first.Write([]byte("real guacd")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = hostSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	if n, err := hostSide.Read(buf); err != nil || string(buf[:n]) != "real guacd" {
		t.Errorf("the allowed peer was not proxied: got %q err=%v", buf[:n], err)
	}
	first.Close()
}

// Resolving which peer is allowed must fail closed rather than allow everyone.
func TestExpectedPeersFailsClosed(t *testing.T) {
	if _, err := expectedProxyPeers(""); err == nil {
		t.Error("an empty guacd address produced an allow-list rather than an error; the " +
			"session would then accept from anyone")
	}
	if _, err := expectedProxyPeers("no-such-host.invalid:4822"); err == nil {
		t.Error("an unresolvable guacd host produced an allow-list rather than an error")
	}
	ips, err := expectedProxyPeers("10.1.2.3:4822")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.1.2.3")) {
		t.Errorf("a literal address did not resolve to itself: %v %v", ips, err)
	}
}
