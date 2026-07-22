// Package credinject resolves a host's vaulted credential into an SSH auth method
// at connection time. The plaintext is decrypted only here, in RAM, to build the
// auth method; it is never returned to the caller or the operator — the point of
// injection is that the user connects without ever seeing the credential.
package credinject

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/credresolve"
	"github.com/fleet-terminal/backend/internal/extsecret"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// Injection is the resolved SSH auth for a vaulted host.
type Injection struct {
	Auth      ssh.AuthMethod
	LoginUser string    // the account to log in as (the credential's username, else the host's)
	SecretID  uuid.UUID // for audit
}

// For returns the injected SSH auth for a host, or (nil, nil) if the host uses
// Fleet's ephemeral certificates (the caller then takes the normal cert path). The
// connecting userID is required so a credential with a check-out policy is only
// injected while that user holds an active check-out.
func For(ctx context.Context, st *store.Store, vaultKey []byte, extCfg extsecret.Config, host *models.Host, userID uuid.UUID) (*Injection, error) {
	switch host.AuthMethod {
	case "", "fleet_cert":
		return nil, nil
	case "vault_password", "vault_ssh_key":
		// handled below
	default:
		return nil, fmt.Errorf("unknown host auth method %q", host.AuthMethod)
	}
	if host.CredentialID == nil {
		return nil, errors.New("host is set to use a vault credential but none is attached")
	}
	secret, err := st.GetVaultSecret(ctx, *host.CredentialID)
	if err != nil {
		return nil, errors.New("the attached credential no longer exists")
	}
	if secret.AccessPolicy != "open" {
		active, _ := st.HasActiveCheckout(ctx, *host.CredentialID, userID)
		if !active {
			return nil, errors.New("check out this credential before connecting to the host")
		}
	}
	plaintext, err := credresolve.Open(ctx, st, secret, vaultKey, extCfg)
	if err != nil {
		return nil, errors.New("could not resolve the attached credential")
	}
	defer zero(plaintext)

	loginUser := secret.Username
	if loginUser == "" {
		loginUser = host.SSHUser
	}
	inj := &Injection{LoginUser: loginUser, SecretID: *host.CredentialID}
	switch host.AuthMethod {
	case "vault_password":
		inj.Auth = ssh.Password(string(plaintext))
	case "vault_ssh_key":
		signer, err := ssh.ParsePrivateKey(plaintext)
		if err != nil {
			return nil, errors.New("the attached credential is not a valid SSH private key")
		}
		inj.Auth = ssh.PublicKeys(signer)
	}
	return inj, nil
}

// PasswordForSystem resolves a host's attached vault credential to a raw username and
// password for a SYSTEM operation (the background monitor collecting Windows facts over
// WinRM — no user context). It only returns credentials whose access policy is "open":
// a check-out-gated secret is never used by the unattended monitor, so fact collection
// is simply skipped for such hosts.
func PasswordForSystem(ctx context.Context, st *store.Store, vaultKey []byte, extCfg extsecret.Config, host *models.Host) (username, password string, err error) {
	if host.CredentialID == nil {
		return "", "", errors.New("no credential is attached to this host")
	}
	secret, err := st.GetVaultSecret(ctx, *host.CredentialID)
	if err != nil {
		return "", "", errors.New("the attached credential no longer exists")
	}
	if secret.AccessPolicy != "open" {
		return "", "", errors.New("credential requires check-out; fact collection skipped")
	}
	plaintext, err := credresolve.Open(ctx, st, secret, vaultKey, extCfg)
	if err != nil {
		return "", "", errors.New("could not resolve the attached credential")
	}
	defer zero(plaintext)
	return secret.Username, string(plaintext), nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// PasswordFor resolves a host's attached vault credential to a raw username and
// password (for protocols like RDP that need them directly, brokered by guacd).
// It enforces the same check-out policy as SSH injection. The plaintext is for the
// broker only — never the operator.
func PasswordFor(ctx context.Context, st *store.Store, vaultKey []byte, extCfg extsecret.Config, host *models.Host, userID uuid.UUID) (username, password string, err error) {
	if host.CredentialID == nil {
		return "", "", errors.New("no credential is attached to this host")
	}
	secret, err := st.GetVaultSecret(ctx, *host.CredentialID)
	if err != nil {
		return "", "", errors.New("the attached credential no longer exists")
	}
	if secret.AccessPolicy != "open" {
		active, _ := st.HasActiveCheckout(ctx, *host.CredentialID, userID)
		if !active {
			return "", "", errors.New("check out this credential before connecting to the host")
		}
	}
	plaintext, err := credresolve.Open(ctx, st, secret, vaultKey, extCfg)
	if err != nil {
		return "", "", errors.New("could not resolve the attached credential")
	}
	defer zero(plaintext)
	return secret.Username, string(plaintext), nil
}
