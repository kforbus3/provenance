// Package identity issues and holds ephemeral per-session SSH identities. Private
// keys exist ONLY in process memory (this vault) and are zeroized on cleanup —
// never written to disk, database, cookies, or caches.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// sessionScope is the host key for a session-level credential (the identity used
// for the jump host, enrollment and system operations). Per-host credentials are
// keyed by the managed host's id instead.
var sessionScope = uuid.Nil

// Credential is a live ephemeral SSH identity. It is bound to a browser session
// and, for per-host certificates, to a specific managed host (HostID). A session
// holds one session-scoped credential plus one unique credential per host it
// connects to, so every (user, host) pair authenticates with a distinct key and
// certificate serial.
type Credential struct {
	SessionID  uuid.UUID
	HostID     uuid.UUID // uuid.Nil for the session-level credential
	UserID     uuid.UUID
	Username   string
	Serial     uint64
	Principals []string
	ExpiresAt  time.Time

	privateKey crypto.Signer // Ed25519 or ECDSA; zeroized on Destroy
	cert       *ssh.Certificate
	certSigner ssh.Signer // signer presenting the certificate to hosts
}

// CertSigner returns the ssh.Signer that authenticates with the certificate.
func (c *Credential) CertSigner() ssh.Signer { return c.certSigner }

// Certificate returns the issued certificate.
func (c *Credential) Certificate() *ssh.Certificate { return c.cert }

// Vault stores live credentials keyed by session id, then by host id (with
// uuid.Nil holding the session-level credential).
type Vault struct {
	mu    sync.RWMutex
	creds map[uuid.UUID]map[uuid.UUID]*Credential
}

// NewVault constructs an empty Vault.
func NewVault() *Vault {
	return &Vault{creds: make(map[uuid.UUID]map[uuid.UUID]*Credential)}
}

func (v *Vault) put(c *Credential) {
	v.mu.Lock()
	defer v.mu.Unlock()
	byHost, ok := v.creds[c.SessionID]
	if !ok {
		byHost = make(map[uuid.UUID]*Credential)
		v.creds[c.SessionID] = byHost
	}
	if existing, ok := byHost[c.HostID]; ok {
		existing.zero()
	}
	byHost[c.HostID] = c
}

// Get returns the session-level credential for a session, if present.
func (v *Vault) Get(sessionID uuid.UUID) (*Credential, bool) {
	return v.lookup(sessionID, sessionScope)
}

// GetHost returns the per-host credential for a session+host, if present.
func (v *Vault) GetHost(sessionID, hostID uuid.UUID) (*Credential, bool) {
	return v.lookup(sessionID, hostID)
}

func (v *Vault) lookup(sessionID, hostID uuid.UUID) (*Credential, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	byHost, ok := v.creds[sessionID]
	if !ok {
		return nil, false
	}
	c, ok := byHost[hostID]
	return c, ok
}

// Destroy zeroizes and removes ALL of a session's credentials — the
// session-level identity and every per-host identity (logout/idle/cleanup).
func (v *Vault) Destroy(sessionID uuid.UUID) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	byHost, ok := v.creds[sessionID]
	if !ok {
		return false
	}
	for _, c := range byHost {
		c.zero()
	}
	delete(v.creds, sessionID)
	return true
}

// Sessions returns the session ids that currently hold credentials.
func (v *Vault) Sessions() []uuid.UUID {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]uuid.UUID, 0, len(v.creds))
	for id := range v.creds {
		out = append(out, id)
	}
	return out
}

// zero overwrites the private key material before the reference is dropped.
//
// Ed25519 keys are byte slices and are overwritten in place, which is complete.
//
// ECDSA is weaker than it looks, and worth being precise about. The secret is
// exposed as a big.Int in the deprecated D field, and its backing words are
// overwritten here -- but since Go 1.25 the key also holds its own internal
// copy, which no exported API can reach. So this scrubs the copy an attacker
// would find by walking a big.Int and does not scrub the one inside the key.
// It is worth doing and it is not a guarantee.
//
// D is deprecated precisely because modifying it is not supported; the
// suggested replacements (PrivateKey.Bytes, ParseRawPrivateKey) encode and
// decode keys and cannot zero one. There is no supported way to do this, so
// the check is silenced here rather than at the linter, where it would also
// silence real findings.
func (c *Credential) zero() {
	switch k := c.privateKey.(type) {
	case ed25519.PrivateKey:
		for i := range k {
			k[i] = 0
		}
	case *ecdsa.PrivateKey:
		if k.D != nil { //nolint:staticcheck // SA1019: no supported way to scrub an ECDSA key; see above
			words := k.D.Bits() //nolint:staticcheck // SA1019: ditto
			for i := range words {
				words[i] = 0
			}
			k.D.SetInt64(0) //nolint:staticcheck // SA1019: ditto
		}
	}
	c.privateKey = nil
	c.certSigner = nil
}
