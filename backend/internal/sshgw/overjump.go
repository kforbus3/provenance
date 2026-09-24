package sshgw

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// DialOverJump opens an SSH session to host:port through a jump-host connection
// the caller already holds, authenticating to the host with auth.
//
// It exists so a caller that tries several addresses for one host can pay for
// ONE jump-host handshake instead of one per address. Every other Dial*ViaJump
// opens its own jump connection, and the monitor used to race a host's
// addresses that way: two or three pre-auth handshakes per host, six hosts at a
// time, against a jump host whose sshd starts refusing at ten (MaxStartups).
// Over an existing connection, each extra address costs a channel, not a
// handshake, and an address the jump host cannot resolve costs nothing at all.
//
// The returned Conn does NOT own jump. Closing it closes only the host session;
// the caller closes jump when it is done with every tunnel it opened over it.
func (g *Gateway) DialOverJump(ctx context.Context, jump *ssh.Client, host string, port int, user string, auth ssh.AuthMethod) (*Conn, error) {
	if jump == nil {
		return nil, fmt.Errorf("no jump connection")
	}
	tunnel, target, err := TunnelOverJump(ctx, jump, host, port)
	if err != nil {
		return nil, err
	}
	ncc, chans, reqs, err := ssh.NewClientConn(tunnel, target, g.pin(&ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: g.hostKeyCallback(),
		Timeout:         15 * time.Second,
	}))
	if err != nil {
		_ = tunnel.Close()
		return nil, fmt.Errorf("ssh handshake with %s: %w", target, err)
	}
	return &Conn{Client: ssh.NewClient(ncc, chans, reqs)}, nil
}

// TunnelOverJump opens a raw TCP tunnel to host:port through an existing jump
// connection and returns it with the target it dialled. Nothing is sent: the
// caller decides what to do with the bytes (the monitor reads an SSH banner).
// Like DialOverJump, it does not own jump.
func TunnelOverJump(ctx context.Context, jump *ssh.Client, host string, port int) (net.Conn, string, error) {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	tunnel, err := jump.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, target, fmt.Errorf("tunnel to %s via jump: %w", target, err)
	}
	return tunnel, target, nil
}
