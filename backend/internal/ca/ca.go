// Package ca implements the internal OpenSSH Certificate Authority. The CA
// private key is generated and held by the backend, encrypted at rest, and never
// leaves the process. It signs short-lived user certificates and supports
// rotation and revocation.
package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/kforbus3/provenance/backend/internal/config"
	"github.com/kforbus3/provenance/backend/internal/cryptoprofile"
	princ "github.com/kforbus3/provenance/backend/internal/principals"
	"github.com/kforbus3/provenance/backend/internal/secretbox"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// CA manages the signing key material in memory and persists encrypted keys.
type CA struct {
	store      *store.Store
	passphrase []byte
	reencrypt  bool                  // upgrade a legacy CA-key envelope on boot
	profile    cryptoprofile.Profile // selects the CA key type (Ed25519 vs ECDSA P-256)

	mu     sync.RWMutex
	signer ssh.Signer // active user-CA signer, held only in RAM
	caID   string     // active ca_keys.id
	// A rotation's key: trusted (pushed to hosts) but not signing until promoted.
	// Held so the jump host's trust in it can be proved with a real login before
	// anything is signed with it. Nil when no rotation is pending.
	pending   ssh.Signer
	pendingID string
}

// New constructs a CA bound to the store and at-rest encryption passphrase.
func New(st *store.Store, cfg *config.Config) *CA {
	return &CA{
		store:      st,
		passphrase: cfg.CAKeyPassphrase,
		reencrypt:  cfg.ReencryptSecrets,
		profile:    cryptoprofile.For(cfg.FIPSMode),
	}
}

// EnsureUserCA loads the active user CA into memory, generating one on first run.
func (c *CA) EnsureUserCA(ctx context.Context) error {
	rec, priv, err := c.store.GetActiveCAKey(ctx, "user")
	if errors.Is(err, store.ErrNotFound) {
		return c.generate(ctx, true)
	}
	if err != nil {
		return err
	}
	signer, err := c.decryptSigner(priv)
	if err != nil {
		// Name the cause, because the one underneath does not.
		//
		// An authentication failure here means exactly one thing: the CA key in this
		// database was sealed with a DIFFERENT passphrase from the one this process
		// has. The underlying error is "cipher: message authentication failed", which
		// tells an operator nothing about which of the two to change.
		//
		// The moment this is most likely to be read is a disaster failover, where a
		// standby has inherited the primary's database but not its secret set —
		// documented ("keep the secret set identical") and, until now, presented as a
		// cipher error to somebody under time pressure at 3am.
		if secretbox.IsAuthFailure(err) {
			return fmt.Errorf("the certificate authority key in this database cannot be "+
				"decrypted with this instance's PROV_CA_PASSPHRASE. The key was sealed "+
				"with a different passphrase — on a DR standby or a restored backup, that "+
				"means this instance has not been given the same secret set as the "+
				"deployment whose database it is now serving (PROV_CA_PASSPHRASE, and "+
				"usually PROV_VAULT_PASSPHRASE and PROV_JWT_SECRET with it): %w", err)
		}
		return fmt.Errorf("load CA signer: %w", err)
	}
	c.mu.Lock()
	c.signer, c.caID = signer, rec.ID.String()
	c.mu.Unlock()
	if err := c.loadPending(ctx); err != nil {
		return err
	}
	// Opportunistically upgrade the CA-key envelope to match the active KDF profile:
	// legacy(SHA-256)/argon2id -> argon2id normally, and legacy/argon2id -> PBKDF2
	// under FIPS. Gated behind the opt-in flag because the upgraded blob can't be read
	// by an older build (a one-way step). reSealActiveKey verifies the re-sealed value
	// decrypts identically before overwriting, so it can never brick the CA key.
	if c.reencrypt && secretbox.NeedsReseal(priv) {
		c.reSealActiveKey(ctx, rec.ID, priv)
	}
	return nil
}

// reSealActiveKey re-encrypts an already-decrypted CA-key blob with the current
// (argon2id) envelope. It is best-effort and safe: it overwrites the stored blob
// ONLY after verifying the re-sealed value decrypts back to the identical
// plaintext, so a bug can never leave the CA key unrecoverable. On any failure it
// leaves the legacy blob in place (which still decrypts via the dual-read path).
func (c *CA) reSealActiveKey(ctx context.Context, id uuid.UUID, oldEnc []byte) {
	plain, err := secretbox.OpenBytes(c.passphrase, oldEnc)
	if err != nil {
		return
	}
	newEnc, err := secretbox.SealBytes(c.passphrase, plain)
	if err != nil {
		return
	}
	check, err := secretbox.OpenBytes(c.passphrase, newEnc)
	if err != nil || !bytes.Equal(check, plain) {
		return // refuse to overwrite unless the new blob round-trips exactly
	}
	_ = c.store.ReSealCAKey(ctx, id, newEnc)
}

// ResealActiveKey re-seals the active user CA private key to the active KDF profile
// (argon2id→PBKDF2 under FIPS) if it needs it, verifying the new envelope decrypts
// identically before overwriting. Returns whether it changed. This is the on-demand
// form of the opportunistic boot upgrade; used by the FIPS migration sweep.
func (c *CA) ResealActiveKey(ctx context.Context) (bool, error) {
	rec, priv, err := c.store.GetActiveCAKey(ctx, "user")
	if err != nil {
		return false, err
	}
	newEnc, changed, err := secretbox.ResealBytes(c.passphrase, priv)
	if err != nil || !changed {
		return false, err
	}
	if err := c.store.ReSealCAKey(ctx, rec.ID, newEnc); err != nil {
		return false, err
	}
	return true, nil
}

// generate creates a fresh user CA of the profile's key type (Ed25519 by default,
// ECDSA P-256 under FIPS), encrypts the private key, and stores it.
func (c *CA) generate(ctx context.Context, signing bool) error {
	priv, err := c.profile.GenerateSigningKey()
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return err
	}
	sshPub := signer.PublicKey()
	enc, err := c.encryptKey(priv)
	if err != nil {
		return err
	}
	authorized := string(ssh.MarshalAuthorizedKey(sshPub))
	// The algorithm string (ssh-ed25519 / ecdsa-sha2-nistp256) is taken from the key
	// itself, so the stored CA record reflects whichever type the profile generated.
	rec, err := c.store.InsertCAKey(ctx, "user", sshPub.Type(), authorized, enc, ssh.FingerprintSHA256(sshPub), signing)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if signing {
		c.signer, c.caID = signer, rec.ID.String()
	} else {
		c.pending, c.pendingID = signer, rec.ID.String()
	}
	c.mu.Unlock()
	return nil
}

// ErrRotationPending is returned by Rotate while a previous rotation's key has not
// been promoted yet. A second pending key would be a third trusted key, with no
// answer to which of the two new ones should win.
var ErrRotationPending = errors.New("a CA rotation is already in progress: its new key is trusted but not signing yet")

// Rotate generates a new CA key that is TRUSTED but does not sign yet.
//
// It used to become the signer the moment it existed, before anything trusted it:
// every certificate issued from then on was signed by a key the jump host would not
// learn for up to five minutes, and that a host which missed the trust push would
// never learn. Now the key is pushed first and signs only once Promote is called,
// which the caller does when every host and the jump host have confirmed it. Until
// then the previous key goes on signing, and nothing about reachability changes.
func (c *CA) Rotate(ctx context.Context) error {
	c.mu.RLock()
	busy := c.pending != nil
	c.mu.RUnlock()
	if busy {
		return ErrRotationPending
	}
	if _, _, err := c.store.GetPendingCAKey(ctx, "user"); err == nil {
		return ErrRotationPending
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return c.generate(ctx, false)
}

// loadPending loads a rotation's key from the store (a rotation started before a
// restart, or by provctl in another process).
func (c *CA) loadPending(ctx context.Context) error {
	rec, priv, err := c.store.GetPendingCAKey(ctx, "user")
	if errors.Is(err, store.ErrNotFound) {
		c.mu.Lock()
		c.pending, c.pendingID = nil, ""
		c.mu.Unlock()
		return nil
	}
	if err != nil {
		return err
	}
	signer, err := c.decryptSigner(priv)
	if err != nil {
		return fmt.Errorf("load pending CA key: %w", err)
	}
	c.mu.Lock()
	c.pending, c.pendingID = signer, rec.ID.String()
	c.mu.Unlock()
	return nil
}

// Refresh re-reads which key signs and which is pending, so a change made by another
// process (provctl rotate-ca, another instance) is picked up.
func (c *CA) Refresh(ctx context.Context) error {
	rec, priv, err := c.store.GetActiveCAKey(ctx, "user")
	if err != nil {
		return err
	}
	c.mu.RLock()
	same := rec.ID.String() == c.caID
	c.mu.RUnlock()
	if !same {
		signer, err := c.decryptSigner(priv)
		if err != nil {
			return fmt.Errorf("load signing CA key: %w", err)
		}
		c.mu.Lock()
		c.signer, c.caID = signer, rec.ID.String()
		c.mu.Unlock()
	}
	return c.loadPending(ctx)
}

// Promote makes the pending key the signer. The previous key stays trusted, so
// certificates it already signed keep working, until it is retired.
func (c *CA) Promote(ctx context.Context) error {
	c.mu.RLock()
	pending, id := c.pending, c.pendingID
	c.mu.RUnlock()
	if pending == nil {
		return errors.New("no CA rotation is pending")
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return err
	}
	if err := c.store.PromoteCAKey(ctx, uid); err != nil {
		return fmt.Errorf("promote CA key: %w", err)
	}
	c.mu.Lock()
	c.signer, c.caID = pending, id
	c.pending, c.pendingID = nil, ""
	c.mu.Unlock()
	return nil
}

// PendingID is the pending rotation key's id, or "".
func (c *CA) PendingID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pendingID
}

// SignWithPending signs a user certificate with the PENDING key. It exists for one
// purpose: proving the jump host trusts that key with a real login before it signs
// anything that matters.
func (c *CA) SignWithPending(pub ssh.PublicKey, keyID string, principals []string, serial uint64, validFor time.Duration) (*ssh.Certificate, error) {
	c.mu.RLock()
	pending := c.pending
	c.mu.RUnlock()
	if pending == nil {
		return nil, errors.New("no CA rotation is pending")
	}
	return signUser(pending, pub, keyID, principals, serial, validFor)
}

// SignUserCertificate signs pub as a user certificate with the given identity.
// validFor bounds the certificate lifetime; serial uniquely identifies it.
//
// Every certificate also carries the pre-rename spelling of each principal
// (principals.WithLegacy). Hosts enrolled before the product was renamed have the
// old names in their AuthorizedPrincipalsFile, and it is sshd that checks them, so
// a certificate carrying only the new names would be rejected by every host not yet
// migrated. This is the one place principals are stamped into a certificate, so
// doing it here means no issuance path can forget.
func (c *CA) SignUserCertificate(pub ssh.PublicKey, keyID string, principals []string, serial uint64, validFor time.Duration) (*ssh.Certificate, error) {
	c.mu.RLock()
	signer := c.signer
	c.mu.RUnlock()
	if signer == nil {
		return nil, errors.New("user CA not initialized")
	}
	return signUser(signer, pub, keyID, principals, serial, validFor)
}

func signUser(signer ssh.Signer, pub ssh.PublicKey, keyID string, principals []string, serial uint64, validFor time.Duration) (*ssh.Certificate, error) {
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: princ.WithLegacy(principals),
		ValidAfter:      uint64(now.Add(-1 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(validFor).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-user-rc":          "",
				"permit-agent-forwarding": "",
				// Required so the gateway can open the ProxyJump direct-tcpip
				// channel from the jump host onward to the managed host.
				"permit-port-forwarding": "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}
	return cert, nil
}

// ActiveKeyType returns the active CA signer's SSH key algorithm (e.g.
// "ssh-ed25519" or "ecdsa-sha2-nistp256"), or "" if uninitialized. Used by the
// FIPS boot self-check to refuse a non-approved (Ed25519) CA.
func (c *CA) ActiveKeyType() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.signer == nil {
		return ""
	}
	return c.signer.PublicKey().Type()
}

// ActiveID returns the active CA key id.
func (c *CA) ActiveID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.caID
}

// PublicKeyAuthorized returns the active CA public key in authorized_keys form.
func (c *CA) PublicKeyAuthorized() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.signer == nil {
		return ""
	}
	return string(ssh.MarshalAuthorizedKey(c.signer.PublicKey()))
}

// --- at-rest encryption (AES-256-GCM, key derived from the passphrase) ---

// encryptKey / decryptSigner delegate to the shared secretbox envelope, which
// derives its key with argon2id and reads both the new (v2) and the legacy
// SHA-256 format — so a CA key sealed by an older build still decrypts.
func (c *CA) encryptKey(priv crypto.Signer) ([]byte, error) {
	block, err := pemPrivate(priv)
	if err != nil {
		return nil, err
	}
	return secretbox.SealBytes(c.passphrase, block)
}

func (c *CA) decryptSigner(enc []byte) (ssh.Signer, error) {
	plain, err := secretbox.OpenBytes(c.passphrase, enc)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(plain)
}
