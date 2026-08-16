package sshgw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/kforbus3/Moorgate/backend/internal/config"
	princ "github.com/kforbus3/Moorgate/backend/internal/principals"
)

// These tests stand up the real two-hop arrangement in process: a jump host that
// trusts ONLY the fleet-wide "fleet" principal (what deploy/testfabric/jumphost
// writes into /etc/ssh/auth_principals/fleet, and what
// deploy/compose/docker-compose.jumphost.yml builds for single-server production),
// and a managed host that maps principals to two accounts the way caTrustScript
// provisions them.
//
// What they pin down: a login-only certificate deliberately omits "fleet" so sshd
// refuses to open the sudo account with it. That same omission means it cannot
// authenticate the jump hop either — so the two hops must present DIFFERENT
// certificates. Using one credential for both (what dialWithCred does) leaves a
// user without Host.Sudo unable to connect at all.

// testCA signs user certificates the way the Fleet CA does.
type testCA struct{ signer ssh.Signer }

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	return &testCA{signer: s}
}

// sign mints a user certificate carrying principals, returning a signer for it.
func (c *testCA) sign(t *testing.T, keyID string, principals []string) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}
	userSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("user signer: %v", err)
	}
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Permissions:     ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	cs, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatalf("cert signer: %v", err)
	}
	return cs
}

// sshdStub is an in-process sshd enforcing an AuthorizedPrincipalsFile-equivalent:
// accounts maps a login account to the set of certificate principals that may open
// it, exactly as /etc/ssh/auth_principals/<account> does on a real host.
type sshdStub struct {
	addr     string
	accounts map[string][]string
	// forwards, when true, serves direct-tcpip channels (the jump host's role).
	forwards bool
	rejected chan string
}

func startSSHD(t *testing.T, ca *testCA, accounts map[string][]string, forwards bool) *sshdStub {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	s := &sshdStub{accounts: accounts, forwards: forwards, rejected: make(chan string, 16)}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			return string(k.Marshal()) == string(ca.signer.PublicKey().Marshal())
		},
		UserKeyFallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("only certificates are accepted")
		},
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			perms, err := s.authenticate(checker, meta, key)
			if err != nil {
				// Record every refusal, whatever stage produced it, so a test can
				// assert the server actually evaluated a certificate rather than
				// pass on a connection error that never reached it.
				select {
				case s.rejected <- fmt.Sprintf("account %q rejected %s: %v", meta.User(), describe(key), err):
				default:
				}
			}
			return perms, err
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.addr = ln.Addr().String()
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(nc, cfg)
		}
	}()
	return s
}

// authenticate mirrors sshd: CertChecker validates the CA signature, certificate
// type, validity window, and that a principal matches the login user; the accounts
// map is the AuthorizedPrincipalsFile layer on top of it.
func (s *sshdStub) authenticate(checker *ssh.CertChecker, meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("not a certificate")
	}
	allowed := s.accounts[meta.User()]
	matched := ""
	for _, want := range allowed {
		for _, have := range cert.ValidPrincipals {
			if have == want {
				matched = want
			}
		}
	}
	if matched == "" {
		return nil, fmt.Errorf("no principal in %v is trusted by account %q (trusts %v)", cert.ValidPrincipals, meta.User(), allowed)
	}
	// CertChecker matches a principal against the login user, which Fleet's model
	// does not do — the account is named by the sshd config, not by the principal.
	// Validate the certificate itself against a login name it will accept.
	if _, err := checker.Authenticate(certMeta{meta, matched}, key); err != nil {
		return nil, err
	}
	return &ssh.Permissions{}, nil
}

// certMeta overrides the login user CertChecker validates principals against.
type certMeta struct {
	ssh.ConnMetadata
	user string
}

func (c certMeta) User() string { return c.user }

func describe(key ssh.PublicKey) string {
	if cert, ok := key.(*ssh.Certificate); ok {
		return fmt.Sprintf("cert %q principals %v", cert.KeyId, cert.ValidPrincipals)
	}
	return "non-certificate key"
}

func (s *sshdStub) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		_ = nc.Close()
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		switch {
		case newCh.ChannelType() == "direct-tcpip" && s.forwards:
			go s.forward(newCh)
		case newCh.ChannelType() == "session":
			ch, chReqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(chReqs)
			_ = ch.Close()
		default:
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

// forward implements the jump host's direct-tcpip: dial the requested target and
// splice the streams, which is what makes the second hop reachable.
func (s *sshdStub) forward(newCh ssh.NewChannel) {
	var payload struct {
		DestAddr string
		DestPort uint32
		SrcAddr  string
		SrcPort  uint32
	}
	if err := ssh.Unmarshal(newCh.ExtraData(), &payload); err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, "bad payload")
		return
	}
	target := net.JoinHostPort(payload.DestAddr, strconv.Itoa(int(payload.DestPort)))
	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		_ = upstream.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() { _, _ = io.Copy(upstream, ch); _ = upstream.Close() }()
	go func() { _, _ = io.Copy(ch, upstream); _ = ch.Close() }()
}

// testGateway builds a Gateway pointed at the stub jump host, with host-key
// pinning relaxed (the stubs mint ephemeral host keys per run).
func testGateway(t *testing.T, jumpAddr string) *Gateway {
	t.Helper()
	cfg := &config.Config{
		JumpHost:            jumpAddr,
		JumpUser:            "fleet",
		SSHInsecureHostKeys: true,
	}
	return New(cfg, nil, nil, nil, nil)
}

// The login-only tier must be able to reach a managed host. Its certificate omits
// "fleet" by design, so it cannot authenticate the jump hop — the jump host trusts
// only "fleet" and is never locked down. Presenting that one certificate for both
// hops (dialWithCred's behavior) fails at the jump host, which is why a user with
// Host.Connect but no Host.Sudo could not open a terminal at all.
func TestLoginOnlyTierReachesHostThroughJump(t *testing.T) {
	ca := newTestCA(t)
	hostID := uuid.New()

	// Managed host, provisioned the way caTrustScript does: the privileged account
	// trusts fleet/fleet-h-<id>, the login-only account fleet-login/fleet-login-h-<id>.
	managed := startSSHD(t, ca, map[string][]string{
		"fleet":       {princ.Global, princ.Host(hostID)},
		"fleet-login": {princ.GlobalLogin, princ.HostLogin(hostID)},
	}, false)

	// Jump host: one account, trusting only the fleet-wide principal.
	jump := startSSHD(t, ca, map[string][]string{
		"fleet": {princ.Global},
	}, true)

	g := testGateway(t, jump.addr)
	managedHost, managedPort := splitHostPort(t, managed.addr)

	// The certificates DialForHost works with: a session-level cert (carries
	// "fleet") and a per-host login-only cert (deliberately does not).
	sessionCert := ca.sign(t, "alice/session", []string{princ.Global, princ.User("alice")})
	loginTierPrincipals := []string{princ.GlobalLogin, princ.User("alice")}
	hostCert := ca.sign(t, "alice/host", append(loginTierPrincipals, princ.HostLogin(hostID)))

	// The bug: one credential for both hops. The jump host refuses it.
	if _, err := g.dialWithSigners(context.Background(), hostCert, hostCert, managedHost, managedPort, "fleet-login"); err == nil {
		t.Fatal("expected the jump host to refuse a login-only certificate; if this now passes, the jump host's trusted principals changed and this test no longer covers the regression")
	} else if !strings.Contains(err.Error(), "dial jump host") {
		t.Fatalf("expected failure at the jump hop, got %v", err)
	}
	// Assert WHY it failed. "dial jump host" is also what an unreachable stub
	// produces, so without this the test would pass even if the arrangement never
	// authenticated anything.
	select {
	case why := <-jump.rejected:
		if !strings.Contains(why, princ.GlobalLogin) {
			t.Fatalf("jump host rejected something other than the login-only cert: %s", why)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("jump host never evaluated a certificate — the stub was not reached, so this test proves nothing")
	}

	// The fix: session cert for the jump hop, per-host cert for the managed host.
	conn, err := g.dialWithSigners(context.Background(), sessionCert, hostCert, managedHost, managedPort, "fleet-login")
	if err != nil {
		t.Fatalf("login-only tier must reach the host through the jump hop: %v", err)
	}
	conn.Close()
}

// The account split is the reason the login tier's certificate omits "fleet", so
// that omission has to keep costing the login tier the sudo account — including on
// a host not yet under FLEET_HOST_SCOPED_ONLY, which still trusts bare "fleet".
// This is what a fix that simply added "fleet" to the login cert would break.
func TestLoginOnlyCertCannotOpenTheSudoAccount(t *testing.T) {
	ca := newTestCA(t)
	hostID := uuid.New()

	managed := startSSHD(t, ca, map[string][]string{
		"fleet":       {princ.Global, princ.Host(hostID)}, // not locked down: still trusts "fleet"
		"fleet-login": {princ.GlobalLogin, princ.HostLogin(hostID)},
	}, false)
	jump := startSSHD(t, ca, map[string][]string{"fleet": {princ.Global}}, true)

	g := testGateway(t, jump.addr)
	managedHost, managedPort := splitHostPort(t, managed.addr)

	sessionCert := ca.sign(t, "alice/session", []string{princ.Global, princ.User("alice")})
	hostCert := ca.sign(t, "alice/host", []string{princ.GlobalLogin, princ.User("alice"), princ.HostLogin(hostID)})

	// Even with a valid jump-hop credential, the login-only cert must not open the
	// privileged account. sshd enforces this, not the backend.
	_, err := g.dialWithSigners(context.Background(), sessionCert, hostCert, managedHost, managedPort, "fleet")
	if err == nil {
		t.Fatal("a login-only certificate opened the sudo account — the account split is only enforced by sshd, and it just failed")
	}
	if !strings.Contains(err.Error(), "ssh handshake") {
		t.Fatalf("expected rejection at the managed host, got %v", err)
	}
	select {
	case why := <-managed.rejected:
		if !strings.Contains(why, `account "fleet"`) {
			t.Fatalf("managed host rejected an unexpected attempt: %s", why)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("managed host never evaluated a certificate — the jump hop did not forward, so this test proves nothing")
	}
}

// LoginTier's principals are for the managed-host hop only. Documenting the
// invariant the two-hop tests depend on: the login set must never carry "fleet"
// (that would surrender the account split above), and the sudo set must resolve to
// principals that do (the issuer default), so both hops keep working.
func TestLoginTierPrincipalsAreForTheHostHopOnly(t *testing.T) {
	_, sudoPrincipals := LoginTier(true, "fleet", "alice")
	if sudoPrincipals != nil {
		t.Fatalf("sudo tier should defer to the issuer default (which carries %q), got %v", princ.Global, sudoPrincipals)
	}
	_, loginPrincipals := LoginTier(false, "fleet", "alice")
	for _, p := range loginPrincipals {
		if p == princ.Global {
			t.Fatalf("login-only principals must not carry %q; the jump hop is authenticated by the session certificate instead: %v", princ.Global, loginPrincipals)
		}
	}
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("port %q: %v", p, err)
	}
	return h, n
}
