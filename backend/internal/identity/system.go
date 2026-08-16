package identity

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/kforbus3/Moorgate/backend/internal/cryptoprofile"
	princ "github.com/kforbus3/Moorgate/backend/internal/principals"
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
	priv, err := cryptoprofile.For(i.cfg.FIPSMode).GenerateSigningKey()
	if err != nil {
		return nil, err
	}
	keySigner, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return nil, err
	}
	sshPub := keySigner.PublicKey()
	serial, err := i.store.NextCertSerial(ctx)
	if err != nil {
		return nil, err
	}
	keyID := fmt.Sprintf("system/monitor/%d", serial)
	cert, err := i.ca.SignUserCertificate(sshPub, keyID, principals, serial, ttl)
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
// authenticate to a specific host. It always includes the fleet-wide "fleet"
// principal for the jump-host hop; in lockdown mode it also includes the host's
// scoped principal, which the (now locked) managed host requires for the inner
// hop. Outside lockdown, managed hosts still trust "fleet", so one cached "fleet"
// cert is reused across the fleet exactly as before host scoping.
func (i *Issuer) SystemHostPrincipals(hostID uuid.UUID) []string {
	if i.cfg.HostScopedOnly {
		return []string{princ.Global, princ.Host(hostID)}
	}
	return []string{princ.Global}
}

// SystemHostLoginPrincipals is the login-only counterpart of SystemHostPrincipals:
// the principal set that maps to a host's no-sudo account. Paths that act on a
// user's behalf without an interactive session (the ad-hoc command runner) use it
// so a user without Host.Sudo does not silently land in the privileged account.
//
// Like sshgw.LoginTier, it deliberately omits the fleet-wide "fleet" principal:
// carrying it would open the privileged account on any host that still trusts
// "fleet" (i.e. not yet under FLEET_HOST_SCOPED_ONLY), leaving the account split
// enforced only by the backend naming the right account. That means this set
// authenticates the MANAGED-HOST hop only — pair it with SystemHostPrincipals for
// the jump hop via Gateway.DialWithSigners.
func (i *Issuer) SystemHostLoginPrincipals(hostID uuid.UUID) []string {
	if i.cfg.HostScopedOnly {
		return []string{princ.GlobalLogin, princ.HostLogin(hostID)}
	}
	return []string{princ.GlobalLogin}
}
