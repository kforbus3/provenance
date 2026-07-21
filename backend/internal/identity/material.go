package identity

import (
	"context"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/cryptoprofile"
)

// KeyMaterial is an ephemeral key + signed certificate exported as files for an
// out-of-process SSH client (the ansible-runner sidecar), which cannot use an
// in-memory ssh.Signer. PrivateKeyPEM is an OpenSSH-format private key;
// CertAuthorizedKey is the certificate in authorized_keys form (written as
// `<key>-cert.pub` so OpenSSH loads it automatically).
type KeyMaterial struct {
	PrivateKeyPEM     []byte
	CertAuthorizedKey []byte
	Serial            uint64
	ExpiresAt         time.Time
}

// SystemKeyMaterial mints a fresh ephemeral keypair and a short-lived user
// certificate for the given principals (same CA + principal model as
// SystemSigner), returning the key + cert as bytes. Unlike SystemSigner it is
// never cached: the caller writes the material to a temporary location, uses it
// for a single operation, and is responsible for prompt cleanup. The TTL should
// be only as long as the operation needs.
func (i *Issuer) SystemKeyMaterial(ctx context.Context, principals []string, ttl time.Duration) (*KeyMaterial, error) {
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
	keyID := fmt.Sprintf("system/ansible/%d", serial)
	cert, err := i.ca.SignUserCertificate(sshPub, keyID, principals, serial, ttl)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "fleet-ansible")
	if err != nil {
		return nil, err
	}
	return &KeyMaterial{
		PrivateKeyPEM:     pem.EncodeToMemory(block),
		CertAuthorizedKey: ssh.MarshalAuthorizedKey(cert),
		Serial:            serial,
		ExpiresAt:         time.Unix(int64(cert.ValidBefore), 0),
	}, nil
}
