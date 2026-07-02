package sshgw

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyVerifier implements trust-on-first-use (TOFU) SSH host-key checking. The
// first key seen for a given host is pinned; every later connection to that host
// must present the same key or the dial is refused. This catches an active MITM
// or key swap on any connection after the first — the previous code accepted any
// key on every dial (ssh.InsecureIgnoreHostKey), which let a network attacker
// impersonate the jump host or a managed host and, on the password/bootstrap
// enrollment paths, capture the SSH and sudo passwords.
//
// Pins are held per process (re-pinned after a restart). Persisting them across
// restarts, or pre-provisioning keys to also protect the very first connect, are
// natural follow-ups; TOFU already closes the ongoing-MITM window without
// requiring operators to pre-seed keys (which would break existing deployments).
type hostKeyVerifier struct {
	mu   sync.Mutex
	seen map[string]string // normalized host -> authorized-key line
	log  *slog.Logger
}

func newHostKeyVerifier(log *slog.Logger) *hostKeyVerifier {
	return &hostKeyVerifier{seen: map[string]string{}, log: log}
}

// check is an ssh.HostKeyCallback.
func (v *hostKeyVerifier) check(hostname string, _ net.Addr, key ssh.PublicKey) error {
	id := knownhosts.Normalize(hostname)
	line := string(ssh.MarshalAuthorizedKey(key)) // "<type> <base64>\n"
	v.mu.Lock()
	defer v.mu.Unlock()
	prev, ok := v.seen[id]
	if !ok {
		v.seen[id] = line
		if v.log != nil {
			v.log.Info("pinned SSH host key (trust-on-first-use)", "host", id, "keyType", key.Type())
		}
		return nil
	}
	if prev != line {
		if v.log != nil {
			v.log.Warn("SSH host key mismatch — refusing connection (possible MITM or host rebuilt)",
				"host", id, "keyType", key.Type())
		}
		return fmt.Errorf("host key for %s does not match the pinned key (possible MITM, or the host was rebuilt)", id)
	}
	return nil
}

// hostKeyCallback is used for every gateway dial. Verification is on by default;
// FLEET_SSH_INSECURE_HOST_KEYS=true (local test fabric only; refused in
// production) restores the previous accept-any behavior.
func (g *Gateway) hostKeyCallback() ssh.HostKeyCallback {
	if g.cfg.SSHInsecureHostKeys {
		return ssh.InsecureIgnoreHostKey()
	}
	return g.hostKeys.check
}
