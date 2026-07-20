// Package cryptoprofile centralizes every FIPS-sensitive cryptographic choice
// behind a single profile selected once at boot from FLEET_FIPS_MODE. The default
// profile is byte-for-byte today's behavior (Ed25519, SHA-1 TOTP, default SSH
// negotiation, Argon2id KDF); the FIPS profile substitutes the FIPS 140-3 approved
// set (ECDSA P-256, SHA-256 TOTP, pinned SSH suites, PBKDF2 KDF). Non-FIPS installs
// are unaffected.
//
// Nothing here depends on Fleet's other packages, so any crypto call site can route
// through it without an import cycle.
package cryptoprofile

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"fmt"

	"github.com/pquerna/otp"
	"golang.org/x/crypto/ssh"
)

// Profile is the resolved crypto policy for this instance.
type Profile struct{ fips bool }

// For returns the profile for the given FIPS flag.
func For(fips bool) Profile { return Profile{fips: fips} }

// FIPS reports whether this is the FIPS-approved profile.
func (p Profile) FIPS() bool { return p.fips }

// Name is "fips" or "default", for logs/attestation.
func (p Profile) Name() string {
	if p.fips {
		return "fips"
	}
	return "default"
}

// GenerateSigningKey returns a fresh SSH signing key of the profile's approved
// type: ECDSA P-256 under FIPS, Ed25519 otherwise. Used for the CA and every
// per-session/host/system identity, so the whole certificate chain is one algorithm.
func (p Profile) GenerateSigningKey() (crypto.Signer, error) {
	if p.fips {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// TOTPAlgorithm is the HMAC hash for TOTP: SHA-256 under FIPS (SHA-1 is disallowed
// by most FIPS programs), SHA-1 otherwise (maximum authenticator-app compatibility).
func (p Profile) TOTPAlgorithm() otp.Algorithm {
	if p.fips {
		return otp.AlgorithmSHA256
	}
	return otp.AlgorithmSHA1
}

// ApplySSHClientConfig pins the SSH transport to FIPS-approved primitives that the
// Go standard library (which the validated module covers) implements — AES-GCM,
// ECDH P-256/384, ECDSA/RSA host keys, HMAC-SHA-256 — so a FIPS session never
// negotiates curve25519 / chacha20-poly1305. A no-op for the default profile, which
// keeps Go's normal negotiation.
func (p Profile) ApplySSHClientConfig(c *ssh.ClientConfig) {
	if !p.fips || c == nil {
		return
	}
	c.Ciphers = []string{"aes256-gcm@openssh.com", "aes128-gcm@openssh.com"}
	c.KeyExchanges = []string{"ecdh-sha2-nistp256", "ecdh-sha2-nistp384"}
	c.MACs = []string{"hmac-sha2-256", "hmac-sha2-512"}
	c.HostKeyAlgorithms = []string{
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512,
	}
}

// ServerSSHConfig returns the pinned algorithm lists for an SSH *server* config
// (the enroll/terminal-side listeners), or empty slices for the default profile.
func (p Profile) ServerSSHConfig() (ciphers, kex, macs []string) {
	if !p.fips {
		return nil, nil, nil
	}
	return []string{"aes256-gcm@openssh.com", "aes128-gcm@openssh.com"},
		[]string{"ecdh-sha2-nistp256", "ecdh-sha2-nistp384"},
		[]string{"hmac-sha2-256", "hmac-sha2-512"}
}

// VerifyModuleActive fails closed when FIPS mode is requested but the Go FIPS 140-3
// cryptographic module isn't active at runtime (GODEBUG=fips140=on, built with a
// GOFIPS140 toolchain). A no-op for the default profile.
func (p Profile) VerifyModuleActive() error {
	if !p.fips {
		return nil
	}
	if !fips140.Enabled() {
		return fmt.Errorf("FLEET_FIPS_MODE is on but the Go FIPS 140-3 module is not active: " +
			"build with GOFIPS140 and run with GODEBUG=fips140=on (see docs/fips-mode-plan.md)")
	}
	return nil
}

// ModuleActive reports whether the validated module is currently active (for the
// readiness report / attestation), independent of the profile.
func ModuleActive() bool { return fips140.Enabled() }
