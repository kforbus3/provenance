// Package ca implements the internal OpenSSH Certificate Authority. The CA
// private key is generated and held by the backend, encrypted at rest, and never
// leaves the process. It signs short-lived user certificates and supports
// rotation and revocation.
package ca

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/secretbox"
	"github.com/fleet-terminal/backend/internal/store"
)

// CA manages the signing key material in memory and persists encrypted keys.
type CA struct {
	store      *store.Store
	passphrase []byte
	reencrypt  bool // upgrade a legacy CA-key envelope to argon2id on boot

	mu     sync.RWMutex
	signer ssh.Signer // active user-CA signer, held only in RAM
	caID   string     // active ca_keys.id
}

// New constructs a CA bound to the store and at-rest encryption passphrase.
func New(st *store.Store, cfg *config.Config) *CA {
	return &CA{store: st, passphrase: cfg.CAKeyPassphrase, reencrypt: cfg.ReencryptSecrets}
}

// EnsureUserCA loads the active user CA into memory, generating one on first run.
func (c *CA) EnsureUserCA(ctx context.Context) error {
	rec, priv, err := c.store.GetActiveCAKey(ctx, "user")
	if errors.Is(err, store.ErrNotFound) {
		return c.generate(ctx)
	}
	if err != nil {
		return err
	}
	signer, err := c.decryptSigner(priv)
	if err != nil {
		return fmt.Errorf("load CA signer: %w", err)
	}
	c.mu.Lock()
	c.signer, c.caID = signer, rec.ID.String()
	c.mu.Unlock()
	// Opportunistically upgrade a legacy (SHA-256) CA-key envelope to argon2id,
	// but only when explicitly enabled (a v2 blob can't be read by an older build,
	// so this is a one-way, opt-in step).
	if c.reencrypt && secretbox.IsLegacy(priv) {
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

// generate creates a fresh Ed25519 user CA, encrypts the private key, and stores it.
func (c *CA) generate(ctx context.Context) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	enc, err := c.encryptKey(priv)
	if err != nil {
		return err
	}
	authorized := string(ssh.MarshalAuthorizedKey(sshPub))
	rec, err := c.store.InsertCAKey(ctx, "user", "ssh-ed25519", authorized, enc, ssh.FingerprintSHA256(sshPub))
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.signer, c.caID = signer, rec.ID.String()
	c.mu.Unlock()
	return nil
}

// Rotate generates a new active CA while leaving the previous one active too, so
// hosts that trust either key keep working until the old key is retired.
func (c *CA) Rotate(ctx context.Context) error {
	return c.generate(ctx)
}

// SignUserCertificate signs pub as a user certificate with the given identity.
// validFor bounds the certificate lifetime; serial uniquely identifies it.
func (c *CA) SignUserCertificate(pub ssh.PublicKey, keyID string, principals []string, serial uint64, validFor time.Duration) (*ssh.Certificate, error) {
	c.mu.RLock()
	signer := c.signer
	c.mu.RUnlock()
	if signer == nil {
		return nil, errors.New("user CA not initialized")
	}
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: principals,
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
func (c *CA) encryptKey(priv ed25519.PrivateKey) ([]byte, error) {
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
