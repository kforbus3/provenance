// Package sshgw is the SSH gateway: the ONLY SSH client in the system. It dials
// managed hosts through the jump host (native ProxyJump), authenticating with the
// session's ephemeral certificate. The browser never speaks SSH directly.
package sshgw

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/cryptoprofile"
	"github.com/fleet-terminal/backend/internal/identity"
	princ "github.com/fleet-terminal/backend/internal/principals"
)

// Gateway establishes SSH connections through the jump host.
type Gateway struct {
	cfg      *config.Config
	log      *slog.Logger
	vault    *identity.Vault
	issuer   *identity.Issuer
	hostKeys *hostKeyVerifier
	profile  cryptoprofile.Profile
}

// New constructs a Gateway. st backs the persistent SSH host-key pin store (survives
// restarts); pass nil for a memory-only verifier (tests).
func New(cfg *config.Config, log *slog.Logger, vault *identity.Vault, issuer *identity.Issuer, st hostKeyPinStore) *Gateway {
	return &Gateway{
		cfg: cfg, log: log, vault: vault, issuer: issuer,
		hostKeys: newHostKeyVerifier(st, log),
		profile:  cryptoprofile.For(cfg.FIPSMode),
	}
}

// pin applies the crypto profile's SSH algorithm pins to a client config and
// returns it, so every dial routes through the FIPS-approved suite in FIPS mode
// and is unchanged (default negotiation) otherwise. Every ssh.ClientConfig in this
// file is wrapped with this.
func (g *Gateway) pin(c *ssh.ClientConfig) *ssh.ClientConfig {
	g.profile.ApplySSHClientConfig(c)
	return c
}

// Conn bundles a live SSH client and its underlying network connections so the
// caller can close everything cleanly.
type Conn struct {
	Client *ssh.Client
	jump   *ssh.Client
}

// Close tears down the host client and the jump tunnel.
func (c *Conn) Close() {
	if c.Client != nil {
		_ = c.Client.Close()
	}
	if c.jump != nil {
		_ = c.jump.Close()
	}
}

// Dial connects to host:port through the jump host using the ephemeral
// credentials bound to sessionID. host should be the managed host's WireGuard
// address, which is routable from the jump host.
func (g *Gateway) Dial(ctx context.Context, sessionID, host string, port int, user string) (*Conn, error) {
	cred, ok := g.vaultLookup(sessionID)
	if !ok {
		return nil, fmt.Errorf("no live credential for session")
	}
	return g.dialWithCred(ctx, cred, host, port, user)
}

// dialWithCred opens jump → tunnel → host using one credential for both hops.
func (g *Gateway) dialWithCred(ctx context.Context, cred *identity.Credential, host string, port int, user string) (*Conn, error) {
	signer := cred.CertSigner()
	if signer == nil {
		return nil, fmt.Errorf("session credential unavailable")
	}
	return g.dialWithSigners(ctx, signer, signer, host, port, user)
}

// dialWithSigners opens jump → tunnel → host, authenticating each hop with its own
// certificate. The two hops trust different principals, so they need different
// credentials whenever the host hop is login-only:
//
//   - The jump host always trusts only the fleet-wide "fleet" principal and is
//     never locked down (see docs/security-guide.md §13), so jumpSigner must carry
//     "fleet". The session-level certificate is the one that does.
//   - A managed host maps a certificate to an account via AuthorizedPrincipalsFile.
//     A login-only certificate deliberately carries "fleet-login"/"fleet-login-h-<id>"
//     and NOT "fleet", which is what keeps sshd — not just the backend — enforcing
//     the no-sudo tier. Reusing that certificate for the jump hop would be rejected
//     there; adding "fleet" to it would surrender the account split on any host not
//     yet under FLEET_HOST_SCOPED_ONLY.
//
// Hence: jumpSigner authenticates the jump hop, hostSigner the managed host.
func (g *Gateway) dialWithSigners(ctx context.Context, jumpSigner, hostSigner ssh.Signer, host string, port int, user string) (*Conn, error) {
	if jumpSigner == nil || hostSigner == nil {
		return nil, fmt.Errorf("session credential unavailable")
	}

	// Host keys are verified trust-on-first-use (see hostKeyCallback); the local
	// test fabric sets FLEET_SSH_INSECURE_HOST_KEYS to accept ephemeral keys.
	hostKeyCB := g.hostKeyCallback()

	jumpCfg := g.pin(&ssh.ClientConfig{
		User:            g.cfg.JumpUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(jumpSigner)},
		HostKeyCallback: hostKeyCB,
		Timeout:         10 * time.Second,
	})
	jumpClient, err := ssh.Dial("tcp", g.cfg.JumpHost, jumpCfg)
	if err != nil {
		return nil, fmt.Errorf("dial jump host: %w", err)
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	tunnel, err := jumpClient.DialContext(ctx, "tcp", target)
	if err != nil {
		_ = jumpClient.Close()
		return nil, fmt.Errorf("tunnel to %s via jump: %w", target, err)
	}

	hostCfg := g.pin(&ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(hostSigner)},
		HostKeyCallback: hostKeyCB,
		Timeout:         10 * time.Second,
	})
	ncc, chans, reqs, err := ssh.NewClientConn(tunnel, target, hostCfg)
	if err != nil {
		_ = tunnel.Close()
		_ = jumpClient.Close()
		return nil, fmt.Errorf("ssh handshake with %s: %w", target, err)
	}
	return &Conn{Client: ssh.NewClient(ncc, chans, reqs), jump: jumpClient}, nil
}

// DialForHost connects to a managed host using a certificate UNIQUE to this
// (session, host) pair, minting it if necessary. Unlike Dial (which uses the
// session-level identity for the jump host / enrollment), every managed-host
// connection authenticates with its own distinct key and certificate serial.
//
// user is the host account to log into and principals are the certificate
// principals (which the host maps to that account); pass both from LoginTier so
// the privileged vs login-only tier is consistent. nil principals fall back to
// the issuer's default privileged principals.
func (g *Gateway) DialForHost(ctx context.Context, sessionID, userID, hostID uuid.UUID, username, hostname, host string, port int, user string, principals []string) (*Conn, error) {
	if g.issuer == nil {
		return nil, fmt.Errorf("gateway issuer unavailable")
	}
	if _, err := g.issuer.EnsureHostCredential(ctx, sessionID, userID, hostID, username, hostname, principals); err != nil {
		return nil, fmt.Errorf("issue per-host credential: %w", err)
	}
	cred, ok := g.vault.GetHost(sessionID, hostID)
	if !ok {
		return nil, fmt.Errorf("no per-host credential for session")
	}
	// The jump hop authenticates with the SESSION certificate, which always carries
	// the fleet-wide "fleet" principal the jump host trusts. The per-host credential
	// authenticates only the managed host. This matters for the login-only tier,
	// whose per-host certificate deliberately omits "fleet" — using it for the jump
	// hop would be rejected there, so a user without Host.Sudo could not connect at
	// all. See dialWithSigners.
	sessCred, ok := g.vault.Get(sessionID)
	if !ok {
		return nil, fmt.Errorf("no live credential for session")
	}
	return g.dialWithSigners(ctx, sessCred.CertSigner(), cred.CertSigner(), host, port, user)
}

// LoginTier maps a connection's privilege to the host account it lands in and
// the certificate principals that authorize it. Enrollment provisions two
// accounts per host: the privileged shared account (sshUser, NOPASSWD sudo,
// principal "fleet") and a login-only account (sshUser+"-login", no sudo,
// principal "fleet-login"). sudo callers get the former; everyone else the
// latter. The username is added as a namespaced, informational principal
// (principals.User → "user:<name>"); it matches no AuthorizedPrincipalsFile entry
// and cannot collide with a "fleet"/"fleet-h-<id>" principal, so it grants no
// access on its own even if the username were chosen adversarially.
//
// The returned principals are for the MANAGED-HOST hop only. The login-only set
// omits the fleet-wide "fleet" on purpose: that is what makes sshd, rather than
// only the backend, refuse to open the sudo account for a login-only user on a
// host that still trusts "fleet" (i.e. not yet under FLEET_HOST_SCOPED_ONLY).
// The jump hop is authenticated separately by the session certificate.
func LoginTier(sudo bool, sshUser, username string) (loginUser string, principals []string) {
	if sudo {
		return sshUser, nil // nil -> issuer default principals {"fleet", "user:<name>"}
	}
	return sshUser + "-login", []string{princ.GlobalLogin, princ.User(username)}
}

// DialSystemForHost dials a host with a short-lived system credential carrying
// that host's principal set (the same one background workers use, host-scoped when
// locked down). Enrollment uses it to verify the certificate-login path end to end
// against the host's actual accepted principals, rather than the session-level
// credential, which does not carry the host-scoped principal a locked host requires.
func (g *Gateway) DialSystemForHost(ctx context.Context, hostID uuid.UUID, host string, port int, user string) (*Conn, error) {
	if g.issuer == nil {
		return nil, fmt.Errorf("gateway issuer unavailable")
	}
	signer, err := g.issuer.SystemSigner(ctx, g.issuer.SystemHostPrincipals(hostID), 10*time.Minute)
	if err != nil {
		return nil, err
	}
	return g.DialWithSigner(ctx, signer, host, port, user)
}

// DialDirectSystemForHost opens a DIRECT (no jump) SSH connection to a host with a
// short-lived system credential carrying that host's principal set. Enrollment's
// "host already trusts the CA" path uses it to re-provision a host that is directly
// reachable but locked down — the session-level credential carries only "fleet",
// which a locked host no longer accepts.
func (g *Gateway) DialDirectSystemForHost(ctx context.Context, hostID uuid.UUID, addr string, port int, user string) (*ssh.Client, error) {
	if g.issuer == nil {
		return nil, fmt.Errorf("gateway issuer unavailable")
	}
	signer, err := g.issuer.SystemSigner(ctx, g.issuer.SystemHostPrincipals(hostID), 10*time.Minute)
	if err != nil {
		return nil, err
	}
	return g.DialDirectKey(ctx, addr, port, user, signer)
}

// HostCredentialSerial returns the serial of the per-host certificate bound to a
// session+host, for audit/verification.
func (g *Gateway) HostCredentialSerial(sessionID, hostID uuid.UUID) (uint64, bool) {
	cred, ok := g.vault.GetHost(sessionID, hostID)
	if !ok {
		return 0, false
	}
	return cred.Serial, true
}

// DialHost implements app.Dialer.
func (g *Gateway) DialHost(handle, host string, port int, user string) (any, error) {
	return g.Dial(context.Background(), handle, host, port, user)
}

// DialDirectPassword opens a direct SSH connection authenticating with a
// password. Enrollment uses this to bootstrap a brand-new host that does not yet
// trust the Fleet CA (chicken-and-egg: we install the trust over this session).
func (g *Gateway) DialDirectPassword(ctx context.Context, addr string, port int, user, password string) (*ssh.Client, error) {
	cfg := g.pin(&ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: g.hostKeyCallback(),
		Timeout:         15 * time.Second,
	})
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, fmt.Errorf("dial %s:%d: %w", addr, port, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh password auth to %s: %w", addr, err)
	}
	return ssh.NewClient(ncc, chans, reqs), nil
}

// DialPasswordViaJump bootstraps a host *through the jump host*: it connects to
// the jump host with the session certificate, opens a tunnel to host:port, then
// authenticates to the host with a password. Use this when the backend cannot
// reach the host directly but the jump host can (the host is on the jump's LAN).
func (g *Gateway) DialPasswordViaJump(ctx context.Context, sessionID, host string, port int, user, password string) (*Conn, error) {
	cred, ok := g.vaultLookup(sessionID)
	if !ok {
		return nil, fmt.Errorf("no live credential for session")
	}
	signer := cred.CertSigner()
	if signer == nil {
		return nil, fmt.Errorf("session credential unavailable")
	}
	jumpClient, err := ssh.Dial("tcp", g.cfg.JumpHost, g.pin(&ssh.ClientConfig{
		User:            g.cfg.JumpUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: g.hostKeyCallback(),
		Timeout:         15 * time.Second,
	}))
	if err != nil {
		return nil, fmt.Errorf("dial jump host: %w", err)
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	tunnel, err := jumpClient.DialContext(ctx, "tcp", target)
	if err != nil {
		_ = jumpClient.Close()
		return nil, fmt.Errorf("tunnel to %s via jump: %w", target, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(tunnel, target, g.pin(&ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: g.hostKeyCallback(),
		Timeout:         15 * time.Second,
	}))
	if err != nil {
		_ = tunnel.Close()
		_ = jumpClient.Close()
		return nil, fmt.Errorf("ssh password auth to %s via jump: %w", target, err)
	}
	return &Conn{Client: ssh.NewClient(ncc, chans, reqs), jump: jumpClient}, nil
}

// DialSystemPasswordViaJump reaches a host through the jump hop using a short-lived
// SYSTEM certificate (no user session required) and then authenticates to the target
// with a password. It is the unattended counterpart of DialPasswordViaJump, used by
// the scheduled credential-rotation loop to change a vaulted password on its host.
func (g *Gateway) DialSystemPasswordViaJump(ctx context.Context, hostID uuid.UUID, host string, port int, user, password string) (*Conn, error) {
	return g.DialSystemAuthViaJump(ctx, hostID, host, port, user, ssh.Password(password))
}

// DialSystemAuthViaJump opens a system-context connection to a host through the
// jump host using an arbitrary auth method for the host (typically an injected
// vault credential), while a short-lived system certificate authenticates to the
// jump. No user session is involved — the background monitor and credential rotator
// use this to reach directly-managed hosts that don't trust the Fleet CA.
func (g *Gateway) DialSystemAuthViaJump(ctx context.Context, hostID uuid.UUID, host string, port int, user string, auth ssh.AuthMethod) (*Conn, error) {
	if g.issuer == nil {
		return nil, fmt.Errorf("gateway issuer unavailable")
	}
	signer, err := g.issuer.SystemSigner(ctx, g.issuer.SystemHostPrincipals(hostID), 10*time.Minute)
	if err != nil {
		return nil, err
	}
	jumpClient, err := g.DialJumpWithSigner(ctx, signer)
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	tunnel, err := jumpClient.DialContext(ctx, "tcp", target)
	if err != nil {
		_ = jumpClient.Close()
		return nil, fmt.Errorf("tunnel to %s via jump: %w", target, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(tunnel, target, g.pin(&ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: g.hostKeyCallback(),
		Timeout:         15 * time.Second,
	}))
	if err != nil {
		_ = tunnel.Close()
		_ = jumpClient.Close()
		return nil, fmt.Errorf("ssh auth to %s via jump: %w", target, err)
	}
	return &Conn{Client: ssh.NewClient(ncc, chans, reqs), jump: jumpClient}, nil
}

// DialDirectKey opens a direct SSH connection authenticating with a raw key
// signer (a plain public key, not a certificate). Enrollment uses this to
// bootstrap a host that has no password auth but already trusts an operator's
// key in authorized_keys, and does not yet trust the Fleet CA.
func (g *Gateway) DialDirectKey(ctx context.Context, addr string, port int, user string, signer ssh.Signer) (*ssh.Client, error) {
	return g.DialDirectAuth(ctx, addr, port, user, ssh.PublicKeys(signer))
}

// DialDirectAuth opens a direct SSH connection using an arbitrary auth method.
// Enrollment uses this for SSH-agent bootstrap, where the auth method delegates
// signing to the operator's forwarded agent (the private key never reaches us).
func (g *Gateway) DialDirectAuth(ctx context.Context, addr string, port int, user string, auth ssh.AuthMethod) (*ssh.Client, error) {
	cfg := g.pin(&ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: g.hostKeyCallback(),
		Timeout:         20 * time.Second,
	})
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, fmt.Errorf("dial %s:%d: %w", addr, port, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh auth to %s: %w", addr, err)
	}
	return ssh.NewClient(ncc, chans, reqs), nil
}

// DialAuthViaJump bootstraps a host *through the jump host* using an arbitrary
// auth method for the host, while the session certificate authenticates to the
// jump host. Used by SSH-agent enrollment when the host is only reachable via
// the jump.
func (g *Gateway) DialAuthViaJump(ctx context.Context, sessionID, host string, port int, user string, auth ssh.AuthMethod) (*Conn, error) {
	cred, ok := g.vaultLookup(sessionID)
	if !ok {
		return nil, fmt.Errorf("no live credential for session")
	}
	jumpSigner := cred.CertSigner()
	if jumpSigner == nil {
		return nil, fmt.Errorf("session credential unavailable")
	}
	jumpClient, err := ssh.Dial("tcp", g.cfg.JumpHost, g.pin(&ssh.ClientConfig{
		User:            g.cfg.JumpUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(jumpSigner)},
		HostKeyCallback: g.hostKeyCallback(),
		Timeout:         15 * time.Second,
	}))
	if err != nil {
		return nil, fmt.Errorf("dial jump host: %w", err)
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	tunnel, err := jumpClient.DialContext(ctx, "tcp", target)
	if err != nil {
		_ = jumpClient.Close()
		return nil, fmt.Errorf("tunnel to %s via jump: %w", target, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(tunnel, target, g.pin(&ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: g.hostKeyCallback(),
		Timeout:         20 * time.Second,
	}))
	if err != nil {
		_ = tunnel.Close()
		_ = jumpClient.Close()
		return nil, fmt.Errorf("ssh auth to %s via jump: %w", target, err)
	}
	return &Conn{Client: ssh.NewClient(ncc, chans, reqs), jump: jumpClient}, nil
}

// DialRawViaJump opens a raw TCP tunnel to host:port THROUGH the jump host,
// authenticating the jump hop with the session's certificate. It returns the
// target connection and the jump client; the caller must close BOTH when done
// (close the returned net.Conn, then the *ssh.Client). Used to reach non-SSH
// services on managed hosts (e.g. RDP on 3389) over the same overlay path.
func (g *Gateway) DialRawViaJump(ctx context.Context, sessionID, host string, port int) (net.Conn, *ssh.Client, error) {
	cred, ok := g.vaultLookup(sessionID)
	if !ok {
		return nil, nil, fmt.Errorf("no live credential for session")
	}
	jumpSigner := cred.CertSigner()
	if jumpSigner == nil {
		return nil, nil, fmt.Errorf("session credential unavailable")
	}
	jumpClient, err := ssh.Dial("tcp", g.cfg.JumpHost, g.pin(&ssh.ClientConfig{
		User:            g.cfg.JumpUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(jumpSigner)},
		HostKeyCallback: g.hostKeyCallback(),
		Timeout:         15 * time.Second,
	}))
	if err != nil {
		return nil, nil, fmt.Errorf("dial jump host: %w", err)
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	tunnel, err := jumpClient.DialContext(ctx, "tcp", target)
	if err != nil {
		_ = jumpClient.Close()
		return nil, nil, fmt.Errorf("tunnel to %s via jump: %w", target, err)
	}
	return tunnel, jumpClient, nil
}

// DialKeyViaJump bootstraps a host *through the jump host* using a raw key signer
// for the host, while the session certificate authenticates to the jump host.
// Use when the backend cannot reach the host directly but the jump host can.
func (g *Gateway) DialKeyViaJump(ctx context.Context, sessionID, host string, port int, user string, signer ssh.Signer) (*Conn, error) {
	cred, ok := g.vaultLookup(sessionID)
	if !ok {
		return nil, fmt.Errorf("no live credential for session")
	}
	jumpSigner := cred.CertSigner()
	if jumpSigner == nil {
		return nil, fmt.Errorf("session credential unavailable")
	}
	jumpClient, err := ssh.Dial("tcp", g.cfg.JumpHost, g.pin(&ssh.ClientConfig{
		User:            g.cfg.JumpUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(jumpSigner)},
		HostKeyCallback: g.hostKeyCallback(),
		Timeout:         15 * time.Second,
	}))
	if err != nil {
		return nil, fmt.Errorf("dial jump host: %w", err)
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	tunnel, err := jumpClient.DialContext(ctx, "tcp", target)
	if err != nil {
		_ = jumpClient.Close()
		return nil, fmt.Errorf("tunnel to %s via jump: %w", target, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(tunnel, target, g.pin(&ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: g.hostKeyCallback(),
		Timeout:         15 * time.Second,
	}))
	if err != nil {
		_ = tunnel.Close()
		_ = jumpClient.Close()
		return nil, fmt.Errorf("ssh key auth to %s via jump: %w", target, err)
	}
	return &Conn{Client: ssh.NewClient(ncc, chans, reqs), jump: jumpClient}, nil
}

// DialWithSigner connects to host:port through the jump host using an explicit
// certificate signer (e.g. the monitor's system identity) rather than a session
// credential from the vault. Both hops present the same certificate, which is
// correct for the privileged system principals (they carry "fleet", which the jump
// host trusts). Use DialWithSigners when the host hop must be login-only.
func (g *Gateway) DialWithSigner(ctx context.Context, signer ssh.Signer, host string, port int, user string) (*Conn, error) {
	return g.DialWithSigners(ctx, signer, signer, host, port, user)
}

// DialWithSigners connects to host:port through the jump host presenting a
// different certificate to each hop. The login-only principal sets omit the
// fleet-wide "fleet" the jump host requires (that omission is what keeps sshd
// enforcing the no-sudo account), so a login-only host hop must be paired with a
// privileged jump hop — see identity.SystemHostLoginPrincipals.
func (g *Gateway) DialWithSigners(ctx context.Context, jumpSigner, hostSigner ssh.Signer, host string, port int, user string) (*Conn, error) {
	if jumpSigner == nil || hostSigner == nil {
		return nil, fmt.Errorf("nil signer")
	}
	return g.dialWithSigners(ctx, jumpSigner, hostSigner, host, port, user)
}

// DialJumpSystem opens an SSH connection to the jump host with a short-lived SYSTEM
// certificate. Background work that touches the jump host but belongs to no user
// session — retiring a deleted host's overlay membership — needs this: there is no
// session credential to borrow, and passing a freshly generated session id to
// DialDirect does not conjure one, it just fails the vault lookup.
//
// The certificate carries only the fleet-wide principal, which is the one the jump
// host trusts and the only one it ever needs (it is never locked down; see
// docs/security-guide.md §13).
func (g *Gateway) DialJumpSystem(ctx context.Context) (*ssh.Client, error) {
	if g.issuer == nil {
		return nil, fmt.Errorf("gateway issuer unavailable")
	}
	signer, err := g.issuer.SystemSigner(ctx, []string{princ.Global}, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	return g.DialJumpWithSigner(ctx, signer)
}

// DialJumpWithSigner opens an SSH connection to the jump host authenticated with the
// given (system) signer and returns the client. The caller uses client.DialContext to
// tunnel arbitrary TCP through the jump host (e.g. WinRM to a Windows host) and must
// Close the client when done.
func (g *Gateway) DialJumpWithSigner(ctx context.Context, signer ssh.Signer) (*ssh.Client, error) {
	if signer == nil {
		return nil, fmt.Errorf("nil signer")
	}
	client, err := ssh.Dial("tcp", g.cfg.JumpHost, g.pin(&ssh.ClientConfig{
		User:            g.cfg.JumpUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: g.hostKeyCallback(),
		Timeout:         10 * time.Second,
	}))
	if err != nil {
		return nil, fmt.Errorf("dial jump host: %w", err)
	}
	return client, nil
}

// DialDirect opens an SSH connection straight to addr:port using the session's
// ephemeral certificate, bypassing the jump host. Enrollment uses this to reach
// the jump host itself and a host that is not yet on the WireGuard overlay.
func (g *Gateway) DialDirect(ctx context.Context, sessionID, addr string, port int, user string) (*ssh.Client, error) {
	cred, ok := g.vaultLookup(sessionID)
	if !ok {
		return nil, fmt.Errorf("no live credential for session")
	}
	signer := cred.CertSigner()
	if signer == nil {
		return nil, fmt.Errorf("session credential unavailable")
	}
	cfg := g.pin(&ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: g.hostKeyCallback(),
		Timeout:         10 * time.Second,
	})
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, fmt.Errorf("dial %s:%d: %w", addr, port, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake with %s: %w", addr, err)
	}
	return ssh.NewClient(ncc, chans, reqs), nil
}

// CredentialSerial returns the serial of the certificate bound to a session, for
// audit/verification (recorded on each SSH session).
func (g *Gateway) CredentialSerial(sessionID string) (uint64, bool) {
	cred, ok := g.vaultLookup(sessionID)
	if !ok {
		return 0, false
	}
	return cred.Serial, true
}

func (g *Gateway) vaultLookup(sessionID string) (*identity.Credential, bool) {
	id, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, false
	}
	return g.vault.Get(id)
}
