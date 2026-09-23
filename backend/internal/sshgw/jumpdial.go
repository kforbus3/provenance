package sshgw

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// jumpDialBackoff is how long dialJump waits before each retry. Its length is the
// number of retries, so a dial is attempted len+1 times in all.
//
// Why retry at all: every connection Provenance makes to a managed host goes
// through the one jump host, and OpenSSH's sshd refuses new connections once too
// many are mid-handshake (MaxStartups, default 10:30:100 -- from the 10th
// unauthenticated connection it drops a growing share of new ones). A burst is
// normal here: a scheduled vulnerability scan of a host group starts many scans in
// the same second. On 2026-09-23 the jump host logged "drop connection #10 ... past
// MaxStartups" six times at 01:00, and the gitlab scan failed with "handshake
// failed: ... connection reset by peer" -- a refusal that a moment later would have
// been an acceptance.
//
// The waits are short because a throttle clears as soon as the handshakes ahead of
// it finish, and jittered so the connections that were dropped together do not
// all come back together and get dropped again.
var jumpDialBackoff = []time.Duration{250 * time.Millisecond, 750 * time.Millisecond, 2 * time.Second}

// dialJump opens the SSH connection to the jump host, retrying a connection the
// jump host dropped before the SSH handshake could happen.
//
// Only that case is retried. A refused certificate, a host-key mismatch or an
// unreachable address is an answer, not a throttle: retrying it would only delay the
// error, and for a host key it would mean asking a possibly impersonated server
// again. See retryableJumpDialErr.
func (g *Gateway) dialJump(ctx context.Context, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	for attempt := 0; ; attempt++ {
		client, err := ssh.Dial("tcp", g.cfg.JumpHost, cfg)
		if err == nil {
			return client, nil
		}
		if attempt >= len(jumpDialBackoff) || !retryableJumpDialErr(err) {
			return nil, err
		}
		wait := jumpDialBackoff[attempt]
		wait += time.Duration(rand.Int64N(int64(wait)/2 + 1))
		if g.log != nil {
			g.log.Debug("jump host dropped the connection before the handshake; retrying",
				"attempt", attempt+1, "wait", wait, "err", err)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			// The dial's own error says what happened; the cancellation only says
			// why there was no further attempt.
			return nil, err
		case <-t.C:
		}
	}
}

// retryableJumpDialErr reports whether a failed jump dial is the connection being
// dropped before SSH got going -- what sshd does to a connection past MaxStartups --
// rather than an answer from it.
//
// sshd closes such a socket without reading from it. The client has usually sent
// its version string by then, so the close arrives as a reset (or, on a write that
// follows it, a broken pipe); when it has not, it arrives as a clean end of stream. Both surface wrapped inside "ssh: handshake
// failed", which x/crypto builds with %w, so errors.Is reaches them.
func retryableJumpDialErr(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF)
}
