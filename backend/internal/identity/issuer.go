package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/ca"
	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/metrics"
	"github.com/fleet-terminal/backend/internal/models"
	princ "github.com/fleet-terminal/backend/internal/principals"
	"github.com/fleet-terminal/backend/internal/store"
)

// Issuer mints ephemeral identities, persists certificate metadata, and keeps
// the live private keys in the Vault.
type Issuer struct {
	store *store.Store
	ca    *ca.CA
	cfg   *config.Config
	log   *slog.Logger
	vault *Vault
}

// NewIssuer constructs an Issuer.
func NewIssuer(st *store.Store, c *ca.CA, cfg *config.Config, log *slog.Logger, vault *Vault) *Issuer {
	return &Issuer{store: st, ca: c, cfg: cfg, log: log, vault: vault}
}

// Vault exposes the live credential store.
func (i *Issuer) Vault() *Vault { return i.vault }

// Issue generates the session-level ephemeral identity (used for the jump host,
// enrollment and system operations). The private key is retained only in the
// Vault. Per-host connection certificates are minted by IssueForHost.
func (i *Issuer) Issue(ctx context.Context, sessionID, userID uuid.UUID, username string, principals []string) (*Credential, error) {
	if len(principals) == 0 {
		principals = []string{username}
	}
	keyID := fmt.Sprintf("%s/%s", username, sessionID.String()[:8])
	return i.issue(ctx, sessionID, sessionScope, userID, username, principals, keyID, "")
}

// IssueForHost mints a UNIQUE per-host certificate for a session: a fresh
// keypair and serial scoped to one managed host, so every (user, host) pair
// authenticates with distinct key material and an independently revocable cert.
// The host id is embedded in the certificate's key id and recorded against the
// certificate row for audit.
func (i *Issuer) IssueForHost(ctx context.Context, sessionID, userID, hostID uuid.UUID, username, hostname string, principals []string) (*Credential, error) {
	if len(principals) == 0 {
		principals = []string{princ.Global, username}
	}
	principals = i.scopeForHost(principals, hostID)
	label := hostname
	if label == "" {
		label = hostID.String()[:8]
	}
	keyID := fmt.Sprintf("%s/host:%s", username, label)
	return i.issue(ctx, sessionID, hostID, userID, username, principals, keyID, hostname)
}

// issue mints a keypair, signs a user certificate with the given key id, records
// metadata (binding it to hostID when non-nil) and stores the live key in the
// vault under (sessionID, hostID).
func (i *Issuer) issue(ctx context.Context, sessionID, hostID, userID uuid.UUID, username string, principals []string, keyID, _hostname string) (*Credential, error) {
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
	auditID := uuid.New()
	fullKeyID := fmt.Sprintf("%s/%d", keyID, serial)

	cert, err := i.ca.SignUserCertificate(sshPub, fullKeyID, principals, serial, i.cfg.UserCertTTL)
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

	caID, _ := uuid.Parse(i.ca.ActiveID())
	expiresAt := time.Unix(int64(cert.ValidBefore), 0)
	params := store.InsertCertificateParams{
		Serial: serial, Kind: "user", CAKeyID: caID, UserID: &userID, SessionID: &sessionID,
		KeyID: fullKeyID, Principals: principals,
		PublicKey: string(ssh.MarshalAuthorizedKey(sshPub)), AuditID: auditID, ExpiresAt: expiresAt,
	}
	if hostID != sessionScope {
		hid := hostID
		params.HostID = &hid
	}
	if _, err := i.store.InsertCertificate(ctx, params); err != nil {
		return nil, err
	}

	cred := &Credential{
		SessionID: sessionID, HostID: hostID, UserID: userID, Username: username, Serial: serial,
		Principals: principals, ExpiresAt: expiresAt,
		privateKey: priv, cert: cert, certSigner: certSigner,
	}
	i.vault.put(cred)
	metrics.CertificatesIssued.WithLabelValues("user").Inc()

	detail := map[string]any{"principals": principals, "expiresAt": expiresAt, "auditId": auditID}
	if hostID != sessionScope {
		detail["hostId"] = hostID
	}
	_, _ = i.store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &userID, ActorName: username, Action: "certificate.issue",
		TargetKind: "certificate", TargetID: fmt.Sprintf("%d", serial),
		Detail: detail,
	})
	return cred, nil
}

// EnsureHostCredential guarantees the session holds a live, unexpired per-host
// certificate for hostID, minting one if absent or close to expiry. Returns the
// certificate serial in use. This is called by the gateway just before dialing.
// principals selects the certificate principals (and thus which host account the
// cert may log into); nil falls back to the default privileged principals.
func (i *Issuer) EnsureHostCredential(ctx context.Context, sessionID, userID, hostID uuid.UUID, username, hostname string, principals []string) (uint64, error) {
	if c, ok := i.vault.GetHost(sessionID, hostID); ok && time.Until(c.ExpiresAt) > i.cfg.CertRenewBefore {
		return c.Serial, nil
	}
	cred, err := i.IssueForHost(ctx, sessionID, userID, hostID, username, hostname, principals)
	if err != nil {
		return 0, err
	}
	return cred.Serial, nil
}

// scopeForHost adds each fleet-wide principal's host-scoped counterpart to a
// certificate: "fleet" also gets "fleet-h-<hostID>", "fleet-login" also gets
// "fleet-login-h-<hostID>". The fleet-wide principals are always retained — they
// are what authenticates the jump-host hop (the jump host always trusts "fleet"),
// and once a managed host is locked down it trusts ONLY its host-scoped principal,
// so a certificate minted for another host is rejected there regardless of also
// carrying "fleet". Non-fleet principals (e.g. the informational username) pass
// through unchanged.
func (i *Issuer) scopeForHost(in []string, hostID uuid.UUID) []string {
	out := make([]string, 0, len(in)+2)
	for _, p := range in {
		out = append(out, p)
		switch p {
		case princ.Global:
			out = append(out, princ.Host(hostID))
		case princ.GlobalLogin:
			out = append(out, princ.HostLogin(hostID))
		}
	}
	return dedupePrincipals(out)
}

// dedupePrincipals removes empty/duplicate principals, preserving order.
func dedupePrincipals(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// IssueForSession implements app.CAIssuer.
func (i *Issuer) IssueForSession(sessionID, userID, username string, principals []string) (string, error) {
	sid, err := uuid.Parse(sessionID)
	if err != nil {
		return "", err
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return "", err
	}
	if _, err := i.Issue(context.Background(), sid, uid, username, principals); err != nil {
		return "", err
	}
	return sessionID, nil
}

// DestroySession zeroizes a session's live key and revokes its certificates.
func (i *Issuer) DestroySession(ctx context.Context, sessionID uuid.UUID) {
	i.vault.Destroy(sessionID)
	if n, err := i.store.RevokeSessionCertificates(ctx, sessionID, "session_ended"); err != nil {
		i.log.Warn("revoke session certs", "err", err)
	} else if n > 0 {
		i.log.Info("revoked session certificates", "session", sessionID, "count", n)
	}
}

// RenewExpiring re-issues certificates that will expire within the renewal window
// for sessions still holding live credentials, without disrupting active use.
func (i *Issuer) RenewExpiring(ctx context.Context) {
	cutoff := time.Now().Add(i.cfg.CertRenewBefore)
	expiring, err := i.store.ExpiringCertificates(ctx, cutoff)
	if err != nil {
		i.log.Warn("scan expiring certs", "err", err)
		return
	}
	for _, c := range expiring {
		if c.SessionID == nil {
			continue
		}
		if _, live := i.vault.Get(*c.SessionID); !live {
			continue // session gone; nothing to renew
		}
		if c.UserID == nil {
			continue
		}
		username := ""
		if u, err := i.store.GetUserByID(ctx, *c.UserID); err == nil {
			username = u.Username
		}
		if _, err := i.Issue(ctx, *c.SessionID, *c.UserID, username, c.Principals); err != nil {
			i.log.Warn("renew cert", "session", c.SessionID, "err", err)
			continue
		}
		// Revoke the superseded certificate.
		_ = i.store.RevokeCertificate(ctx, c.Serial, "renewed")
		i.log.Info("renewed ephemeral certificate", "session", c.SessionID, "oldSerial", c.Serial)
	}
}
