package monitor

import (
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/kforbus3/provenance/backend/internal/sshgw"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// startExecHost is an SSH server that runs each exec request with sh on this
// machine and returns its output and exit status -- so readStackFile's real command
// runs against a real file.
func startExecHost(t *testing.T) string {
	t.Helper()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(hostSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					ch, creqs, err := newCh.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range creqs {
							if req.Type != "exec" {
								_ = req.Reply(false, nil)
								continue
							}
							var p struct{ Cmd string }
							_ = ssh.Unmarshal(req.Payload, &p)
							_ = req.Reply(true, nil)
							cmd := exec.Command("sh", "-c", p.Cmd)
							cmd.Stdout, cmd.Stderr = ch, ch.Stderr()
							code := 0
							if err := cmd.Run(); err != nil {
								code = 1
								if ee, ok := err.(*exec.ExitError); ok {
									code = ee.ExitCode()
								}
							}
							st := make([]byte, 4)
							binary.BigEndian.PutUint32(st, uint32(code))
							_, _ = ch.SendRequest("exit-status", false, st)
							_ = ch.Close()
							return
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func dialExecHost(t *testing.T, addr string) *sshgw.Conn {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "prov", Auth: []ssh.AuthMethod{ssh.PublicKeys(hostSigner(t))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey()}) //nolint:gosec // in-process test server
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &sshgw.Conn{Client: c}
}

// Keycloak's stored copy was the plain-HTTP configuration while the host ran TLS,
// both at revision 5, and nothing could see it. The file on the host is now read and
// compared -- and the comparison must not call every stack drifted over the final
// newline the deploy adds and the stored copy lacks.
func TestAStackFileChangedOnTheHostIsSeen(t *testing.T) {
	dir := t.TempDir()
	stored := "services:\n  keycloak:\n    ports:\n      - \"8080:8080\""
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(stored+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	conn := dialExecHost(t, startExecHost(t))

	sha, readErr := readStackFile(conn, dir)
	if readErr != "" {
		t.Fatalf("read failed: %s", readErr)
	}
	if sha != store.ComposeHash(stored) {
		t.Fatal("the file as deployed (with its final newline) must match the stored copy")
	}

	// The change made on the host.
	edited := strings.Replace(stored, `"8080:8080"`, `"8443:8443"`, 1) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	sha, _ = readStackFile(conn, dir)
	if sha == store.ComposeHash(stored) {
		t.Fatal("a file changed on the host hashed the same as the stored copy")
	}
}

// A file that cannot be read is reported as such, never as a hash.
func TestAnUnreadableStackFileSaysWhy(t *testing.T) {
	conn := dialExecHost(t, startExecHost(t))
	sha, readErr := readStackFile(conn, filepath.Join(t.TempDir(), "absent"))
	if sha != "" || !strings.Contains(readErr, "could not read") {
		t.Fatalf("got sha=%q err=%q", sha, readErr)
	}
}
