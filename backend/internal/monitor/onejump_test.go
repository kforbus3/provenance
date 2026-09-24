package monitor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kforbus3/provenance/backend/internal/config"
	"github.com/kforbus3/provenance/backend/internal/credinject"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/sshgw"
)

// These tests run a real probe through a real two-hop SSH arrangement in
// process: a jump host that forwards direct-tcpip and counts every TCP
// connection it accepts, and a managed host that answers commands.
//
// What they pin down: a probe opens ONE connection to the jump host however many
// addresses it races. Each connection is a pre-auth handshake the jump host's
// sshd counts against MaxStartups (10), and the monitor runs six probes at a
// time -- so when every address opened its own, a sweep put up to twelve in
// flight and the jump host dropped about forty connections an hour.

type stubServer struct {
	addr     string
	accepted atomic.Int32
}

func hostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// startStub serves SSH on loopback, accepting any key or password. With forward
// it acts as the jump host; otherwise it is a managed host whose every command
// succeeds with no output.
func startStub(t *testing.T, forward bool) *stubServer {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil },
		PasswordCallback:  func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil },
	}
	cfg.AddHostKey(hostSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &stubServer{addr: ln.Addr().String()}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			go serveStub(nc, cfg, forward)
		}
	}()
	return s
}

func serveStub(nc net.Conn, cfg *ssh.ServerConfig, forward bool) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		_ = nc.Close()
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		switch {
		case forward && newCh.ChannelType() == "direct-tcpip":
			go forwardChannel(newCh)
		case !forward && newCh.ChannelType() == "session":
			go answerSession(newCh)
		default:
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

// forwardChannel is the jump host's direct-tcpip, including sshd's refusal of a
// name it cannot resolve -- the case of the access point's bare hostname.
func forwardChannel(newCh ssh.NewChannel) {
	var p struct {
		DestAddr string
		DestPort uint32
		SrcAddr  string
		SrcPort  uint32
	}
	if err := ssh.Unmarshal(newCh.ExtraData(), &p); err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, "bad payload")
		return
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort(p.DestAddr, strconv.Itoa(int(p.DestPort))), 5*time.Second)
	if err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		_ = up.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() { _, _ = io.Copy(up, ch); _ = up.Close() }()
	go func() { _, _ = io.Copy(ch, up); _ = ch.Close() }()
}

func answerSession(newCh ssh.NewChannel) {
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	for req := range reqs {
		if req.Type == "exec" {
			_ = req.Reply(true, nil)
			status := make([]byte, 4)
			binary.BigEndian.PutUint32(status, 0)
			_, _ = ch.SendRequest("exit-status", false, status)
			_ = ch.Close()
			return
		}
		_ = req.Reply(req.Type == "pty-req" || req.Type == "env", nil)
	}
}

// fresh returns inventory the probe will not re-collect, so it never reaches for
// the store (these tests have none).
func fresh() *models.HostInventory {
	now := time.Now()
	return &models.HostInventory{CollectedAt: &now, ContainersCheckedAt: &now, UpdatesCheckedAt: &now}
}

func jumpTestMonitor(t *testing.T, jumpAddr string) *Monitor {
	t.Helper()
	cfg := &config.Config{JumpHost: jumpAddr, JumpUser: "prov", SSHInsecureHostKeys: true, WGInterface: "wg0"}
	return &Monitor{
		cfg: cfg,
		gw:  sshgw.New(cfg, nil, nil, nil, nil),
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func splitPort(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return n
}

func TestAProbeOpensOneJumpConnectionWhateverItRaces(t *testing.T) {
	managed := startStub(t, false)
	port := splitPort(t, managed.addr)
	signer := hostSigner(t) // the stubs accept any key; this stands in for the system cert

	for _, tc := range []struct {
		name string
		host models.Host
		inj  *credinject.Injection
	}{
		{
			// Overlay address plus hostname: the shape of 16 of the 17 enrolled
			// hosts. Both reach the managed stub, so both dials really complete.
			name: "certificate host, two addresses",
			host: models.Host{Hostname: "localhost", WGAddress: "127.0.0.1", SSHPort: port, SSHUser: "prov", Inventory: fresh()},
		},
		{
			name: "vaulted host, two addresses",
			host: models.Host{Hostname: "localhost", WGAddress: "127.0.0.1", SSHPort: port, SSHUser: "prov", Inventory: fresh()},
			inj:  &credinject.Injection{Auth: ssh.Password("pw"), LoginUser: "admin"},
		},
		{
			// The access point: a banner probe, a working address, and a bare
			// hostname the jump host cannot resolve.
			name: "RouterOS device, unresolvable hostname",
			host: models.Host{Hostname: "wap.invalid", Address: "127.0.0.1", SSHPort: port, SSHUser: "admin",
				Options: models.HostOptions{DeviceType: "routeros"}, Inventory: fresh()},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jump := startStub(t, true)
			m := jumpTestMonitor(t, jump.addr)

			st, _, _ := m.probe(context.Background(), signer, tc.inj, &tc.host)

			if st.Status != "online" {
				t.Fatalf("expected the host online, got %q (%s)", st.Status, st.LastError)
			}
			if n := jump.accepted.Load(); n != 1 {
				t.Fatalf("the probe opened %d connections to the jump host; want 1 for %d addresses",
					n, len(dedupe([]string{tc.host.WGAddress, tc.host.Address, tc.host.Hostname})))
			}
		})
	}
}

// Sharing the jump connection must not change which address the probe credits:
// the overlay address still wins when it answers, because that is what proves
// the overlay works.
func TestTheSharedJumpStillCreditsTheOverlay(t *testing.T) {
	managed := startStub(t, false)
	jump := startStub(t, true)
	m := jumpTestMonitor(t, jump.addr)
	h := models.Host{Hostname: "localhost", WGAddress: "127.0.0.1", SSHPort: splitPort(t, managed.addr), SSHUser: "prov", Inventory: fresh()}

	st, _, _ := m.probe(context.Background(), hostSigner(t), nil, &h)
	if st.Status != "online" || !st.WGOK {
		t.Fatalf("expected online over the overlay, got status=%q wgOk=%v (%s)", st.Status, st.WGOK, st.LastError)
	}
}

// A jump host that cannot be reached leaves the host offline with the jump
// host's error as the reason, not a per-address error that hides it.
func TestAnUnreachableJumpHostIsTheReason(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()

	m := jumpTestMonitor(t, dead)
	h := models.Host{Hostname: "localhost", WGAddress: "127.0.0.1", SSHPort: 22, SSHUser: "prov", Inventory: fresh()}
	st, _, _ := m.probe(context.Background(), hostSigner(t), nil, &h)
	if st.Status != "offline" {
		t.Fatalf("expected offline, got %q", st.Status)
	}
	if want := "dial jump host"; len(st.LastError) < len(want) || st.LastError[:len(want)] != want {
		t.Fatalf("expected the jump host's failure as the reason, got %q", st.LastError)
	}
}
