package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	princ "github.com/fleet-terminal/backend/internal/principals"
)

// systemHolder caches a service certificate used by background workers (monitor,
// scan, support, KRL distribution) that act without a user session. It is minted
// from the same CA with a short principal set and refreshed before expiry. The
// private key lives only in memory.
type systemHolder struct {
	signer    ssh.Signer
	expiresAt time.Time
}

// systemCache holds one holder per principal set (keyed by the joined principals)
// so a host-scoped signer for host A is never confused with one for host B.
var (
	systemCacheMu sync.Mutex
	systemCache   = map[string]*systemHolder{}
)

// SystemSigner returns a certificate-backed signer for the given principals,
// minting (and caching, per principal set) one as needed. ttl bounds the
// certificate lifetime.
func (i *Issuer) SystemSigner(ctx context.Context, principals []string, ttl time.Duration) (ssh.Signer, error) {
	key := strings.Join(principals, ",")
	systemCacheMu.Lock()
	defer systemCacheMu.Unlock()
	if h := systemCache[key]; h != nil && h.signer != nil && time.Until(h.expiresAt) > 5*time.Minute {
		return h.signer, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	serial, err := i.store.NextCertSerial(ctx)
	if err != nil {
		return nil, err
	}
	keyID := fmt.Sprintf("system/monitor/%d", serial)
	cert, err := i.ca.SignUserCertificate(sshPub, keyID, principals, serial, ttl)
	if err != nil {
		return nil, err
	}
	keySigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	certSigner, err := ssh.NewCertSigner(cert, keySigner)
	if err != nil {
		return nil, err
	}
	systemCache[key] = &systemHolder{signer: certSigner, expiresAt: time.Unix(int64(cert.ValidBefore), 0)}
	return certSigner, nil
}

// SystemHostPrincipals returns the principal set a system worker should use to
// authenticate to a specific host. In lockdown mode this is the host-scoped
// principal alone (so the system certificate, like a user's, only works on that
// host); otherwise it is the fleet-wide "fleet" principal (one cached cert reused
// across the fleet, exactly as before host scoping).
func (i *Issuer) SystemHostPrincipals(hostID uuid.UUID) []string {
	if i.cfg.HostScopedOnly {
		return []string{princ.Host(hostID)}
	}
	return []string{princ.Global}
}
