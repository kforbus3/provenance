package sshgw

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/kforbus3/Moorgate/backend/internal/store"
)

// hostKeyPinStore is the persistence the verifier needs. *store.Store satisfies it.
type hostKeyPinStore interface {
	GetHostKey(ctx context.Context, host string) (store.HostKeyPin, bool, error)
	PinHostKey(ctx context.Context, host, keyLine, keyType string) error
}

// hostKeyVerifier implements trust-on-first-use (TOFU) SSH host-key checking. The
// first key seen for a given host is pinned; every later connection to that host
// must present the same key or the dial is refused. This catches an active MITM
// or key swap on any connection after the first — the previous code accepted any
// key on every dial (ssh.InsecureIgnoreHostKey), which let a network attacker
// impersonate the jump host or a managed host and, on the password/bootstrap
// enrollment paths, capture the SSH and sudo passwords.
//
// Pins are PERSISTED to the database (ssh_host_keys) and cached in memory, so they
// survive a backend restart — previously they were per-process, and after a restart the
// first connection to any host was re-pinned blindly, reopening the MITM window. An
// operator can additionally pre-seed a 'pinned' key at enrollment so even the first
// connect is verified; a pin recorded that way is enforced identically here.
type hostKeyVerifier struct {
	mu    sync.Mutex
	seen  map[string]string // in-memory cache: normalized host -> authorized-key line
	store hostKeyPinStore   // nil = memory-only (e.g. tests); DB-backed in production
	log   *slog.Logger
}

func newHostKeyVerifier(st hostKeyPinStore, log *slog.Logger) *hostKeyVerifier {
	return &hostKeyVerifier{seen: map[string]string{}, store: st, log: log}
}

// check is an ssh.HostKeyCallback.
func (v *hostKeyVerifier) check(hostname string, _ net.Addr, key ssh.PublicKey) error {
	id := knownhosts.Normalize(hostname)
	line := string(ssh.MarshalAuthorizedKey(key)) // "<type> <base64>\n"

	v.mu.Lock()
	defer v.mu.Unlock()

	// 1. In-memory cache (fast path, also the whole story when store is nil).
	if prev, ok := v.seen[id]; ok {
		return v.compare(id, prev, line, key)
	}

	// 2. Persisted pin. If present, cache + enforce it (survives restart).
	if v.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pin, ok, err := v.store.GetHostKey(ctx, id)
		if err != nil {
			// Fail closed on a lookup error: we can't confirm the host, so don't
			// blindly re-pin — refuse rather than risk trusting a MITM key.
			if v.log != nil {
				v.log.Warn("SSH host-key pin lookup failed — refusing connection", "host", id, "err", err)
			}
			return fmt.Errorf("could not verify host key for %s (pin lookup failed): %w", id, err)
		}
		if ok {
			v.seen[id] = pin.KeyLine
			return v.compare(id, pin.KeyLine, line, key)
		}
	}

	// 3. First time we've seen this host: pin it (durably, if a store is present).
	v.seen[id] = line
	if v.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := v.store.PinHostKey(ctx, id, line, key.Type()); err != nil && v.log != nil {
			v.log.Warn("could not persist SSH host-key pin (in-memory only this run)", "host", id, "err", err)
		}
	}
	if v.log != nil {
		v.log.Info("pinned SSH host key (trust-on-first-use)", "host", id, "keyType", key.Type())
	}
	return nil
}

// compare enforces a known pin against the presented key.
func (v *hostKeyVerifier) compare(id, pinned, presented string, key ssh.PublicKey) error {
	if pinned == presented {
		return nil
	}
	if v.log != nil {
		v.log.Warn("SSH host key mismatch — refusing connection (possible MITM or host rebuilt)",
			"host", id, "keyType", key.Type())
	}
	return fmt.Errorf("host key for %s does not match the pinned key (possible MITM, or the host was rebuilt — remove its pin to re-trust)", id)
}

// HostKeyID is the identity a host is pinned under: the dialed address,
// normalized the way the verifier normalizes it. A host is reachable by several
// addresses (overlay IP, management address, hostname) and each is pinned
// separately, so clearing a host's trust means clearing every identity it can be
// dialed as — miss one and the next dial still refuses on the stale pin.
func HostKeyID(addr string, port int) string {
	return knownhosts.Normalize(net.JoinHostPort(addr, strconv.Itoa(port)))
}

// PinFingerprint renders a stored pin's key line as the SHA256 fingerprint ssh
// itself prints, so an operator can compare it against `ssh-keyscan | ssh-keygen
// -lf -` on the host. Returns "" for a line that no longer parses.
func PinFingerprint(keyLine string) string {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(key)
}

// HostKeyIDs returns the pin identities for every address a host can be dialed
// as, skipping blanks and duplicates. Callers that clear a host's trust must
// clear all of them — a host pinned under both its overlay address and its
// hostname still refuses on whichever one is left behind.
func HostKeyIDs(port int, addrs ...string) []string {
	if port <= 0 {
		port = 22
	}
	var ids []string
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		id := HostKeyID(a, port)
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids
}

// ForgetHostKeys drops the given identities from the in-memory pin cache. The
// database row alone is not enough: a pin is cached per process on first use, so
// a running backend keeps enforcing a deleted pin until it restarts. Callers that
// delete pins MUST call this, or "trust the new key" appears to do nothing.
func (v *hostKeyVerifier) ForgetHostKeys(ids ...string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, id := range ids {
		delete(v.seen, id)
	}
}

// ForgetHostKeys drops cached pins for the given identities (see the verifier's
// method). Safe to call on a gateway whose verification is disabled.
func (g *Gateway) ForgetHostKeys(ids ...string) {
	if g.hostKeys != nil {
		g.hostKeys.ForgetHostKeys(ids...)
	}
}

// hostKeyCallback is used for every gateway dial. Verification is on by default;
// FLEET_SSH_INSECURE_HOST_KEYS=true (local test fabric only; refused in
// production) restores the previous accept-any behavior.
func (g *Gateway) hostKeyCallback() ssh.HostKeyCallback {
	if g.cfg.SSHInsecureHostKeys {
		//nolint:gosec // opt-in FLEET_SSH_INSECURE_HOST_KEYS dev path only; config.go refuses it outside development
		return ssh.InsecureIgnoreHostKey()
	}
	return g.hostKeys.check
}
