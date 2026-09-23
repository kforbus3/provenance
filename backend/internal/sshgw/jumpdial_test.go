package sshgw

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	princ "github.com/kforbus3/provenance/backend/internal/principals"
)

// throttledJump stands in front of a real (stub) jump sshd and drops the first
// `drop` connections the way sshd does past MaxStartups: it accepts the TCP
// connection and closes it without reading or answering. With reset, the close is
// abortive (SO_LINGER 0), which the client sees as "connection reset by peer" --
// the exact error production logged on 2026-09-23. Without it, the close is clean
// and the client sees an end of stream. Every later connection is spliced through
// to the real server, so a retry that gets in authenticates for real.
type throttledJump struct {
	addr     string
	accepted atomic.Int32
}

func startThrottledJump(t *testing.T, backend string, drop int32, reset bool) *throttledJump {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tj := &throttledJump{addr: ln.Addr().String()}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			if tj.accepted.Add(1) <= drop {
				if reset {
					_ = nc.(*net.TCPConn).SetLinger(0)
				}
				_ = nc.Close()
				continue
			}
			go splice(nc, backend)
		}
	}()
	return tj
}

func splice(front net.Conn, backend string) {
	back, err := net.Dial("tcp", backend)
	if err != nil {
		_ = front.Close()
		return
	}
	var once sync.Once
	done := func() { once.Do(func() { _ = front.Close(); _ = back.Close() }) }
	go func() { _, _ = io.Copy(back, front); done() }()
	go func() { _, _ = io.Copy(front, back); done() }()
}

// fastBackoff keeps the retry schedule's SHAPE (three retries) but not its waits,
// and restores the real one afterwards.
func fastBackoff(t *testing.T, retries int) {
	t.Helper()
	saved := jumpDialBackoff
	jumpDialBackoff = make([]time.Duration, retries)
	for i := range jumpDialBackoff {
		jumpDialBackoff[i] = 5 * time.Millisecond
	}
	t.Cleanup(func() { jumpDialBackoff = saved })
}

func jumpFixture(t *testing.T) (*testCA, *sshdStub) {
	t.Helper()
	ca := newTestCA(t)
	return ca, startSSHD(t, ca, map[string][]string{"fleet": {princ.Global}}, true)
}

// The failure itself, reproduced: without retries, a connection the jump host drops
// fails the dial with the error production logged. If this stops failing, the front
// listener no longer reproduces the throttle and the tests below prove nothing.
func TestJumpDialDroppedConnectionFailsWithoutRetry(t *testing.T) {
	ca, jump := jumpFixture(t)
	front := startThrottledJump(t, jump.addr, 1, true)
	fastBackoff(t, 0)

	g := testGateway(t, front.addr)
	_, err := g.DialJumpWithSigner(context.Background(), ca.sign(t, "system", []string{princ.Global}))
	if err == nil {
		t.Fatal("expected the dropped connection to fail the dial when retries are off")
	}
	if !strings.Contains(err.Error(), "dial jump host") || !retryableJumpDialErr(err) {
		t.Fatalf("expected a dropped-connection error at the jump hop, got %v", err)
	}
}

// What the scheduled scan of gitlab needed: the jump host drops the first attempts,
// a moment later it has room, and the dial gets through and authenticates.
func TestJumpDialRetriesPastMaxStartupsDrops(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reset bool
	}{{"reset", true}, {"clean close", false}} {
		t.Run(tc.name, func(t *testing.T) {
			ca, jump := jumpFixture(t)
			front := startThrottledJump(t, jump.addr, 2, tc.reset)
			fastBackoff(t, 3)

			g := testGateway(t, front.addr)
			client, err := g.DialJumpWithSigner(context.Background(), ca.sign(t, "system", []string{princ.Global}))
			if err != nil {
				t.Fatalf("expected the dial to get through after two drops, got %v", err)
			}
			_ = client.Close()
			if n := front.accepted.Load(); n != 3 {
				t.Fatalf("expected 3 connection attempts (2 dropped + 1 accepted), saw %d", n)
			}
		})
	}
}

// Retries are finite: a jump host that keeps dropping still produces an error.
func TestJumpDialGivesUpAfterTheLastRetry(t *testing.T) {
	ca, jump := jumpFixture(t)
	front := startThrottledJump(t, jump.addr, 100, true)
	fastBackoff(t, 3)

	g := testGateway(t, front.addr)
	if _, err := g.DialJumpWithSigner(context.Background(), ca.sign(t, "system", []string{princ.Global})); err == nil {
		t.Fatal("expected an error from a jump host that never accepts")
	}
	if n := front.accepted.Load(); n != 4 {
		t.Fatalf("expected 4 attempts (1 + 3 retries), saw %d", n)
	}
}

// A refused certificate is an answer, not a throttle: one attempt, and the refusal
// comes back unchanged. The rejection is asserted too, so a connection error that
// never reached authentication cannot pass for it.
func TestJumpDialDoesNotRetryAnAuthenticationFailure(t *testing.T) {
	ca, jump := jumpFixture(t)
	front := startThrottledJump(t, jump.addr, 0, true)
	fastBackoff(t, 3)

	g := testGateway(t, front.addr)
	_, err := g.DialJumpWithSigner(context.Background(), ca.sign(t, "login-only", []string{princ.GlobalLogin}))
	if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("expected an authentication failure, got %v", err)
	}
	if retryableJumpDialErr(err) {
		t.Fatalf("an authentication failure must not be classed retryable: %v", err)
	}
	if n := front.accepted.Load(); n != 1 {
		t.Fatalf("expected exactly 1 attempt for a refused certificate, saw %d", n)
	}
	select {
	case <-jump.rejected:
	case <-time.After(2 * time.Second):
		t.Fatal("the jump host never evaluated the certificate")
	}
}

// Cancelling the caller stops the retries and returns the dial's own error rather
// than hiding it behind "context canceled".
func TestJumpDialStopsRetryingWhenCancelled(t *testing.T) {
	ca, jump := jumpFixture(t)
	front := startThrottledJump(t, jump.addr, 100, true)
	saved := jumpDialBackoff
	jumpDialBackoff = []time.Duration{time.Hour}
	t.Cleanup(func() { jumpDialBackoff = saved })

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	g := testGateway(t, front.addr)
	start := time.Now()
	_, err := g.DialJumpWithSigner(ctx, ca.sign(t, "system", []string{princ.Global}))
	if err == nil || errors.Is(err, context.Canceled) || !retryableJumpDialErr(err) {
		t.Fatalf("expected the dropped-connection error, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("cancellation did not interrupt the retry wait")
	}
	if n := front.accepted.Load(); n != 1 {
		t.Fatalf("expected no attempt after cancellation, saw %d", n)
	}
}

func TestRetryableJumpDialErrIgnoresOtherFailures(t *testing.T) {
	for _, err := range []error{
		syscall.ECONNREFUSED,
		errors.New("ssh: handshake failed: knownhosts: key mismatch"),
		context.DeadlineExceeded,
	} {
		if retryableJumpDialErr(err) {
			t.Errorf("%v must not be retried", err)
		}
	}
}
