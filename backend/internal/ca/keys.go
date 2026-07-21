package ca

import (
	"crypto"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

// pemPrivate serializes a signing key (Ed25519 or ECDSA) to OpenSSH PEM bytes,
// which is what ssh.ParsePrivateKey reads back after decryption.
func pemPrivate(priv crypto.PrivateKey) ([]byte, error) {
	block, err := ssh.MarshalPrivateKey(priv, "fleet-ca")
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}
