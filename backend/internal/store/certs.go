package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/jackc/pgx/v5/pgconn"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// NextCertSerial allocates a unique, never-reused certificate serial.
func (s *Store) NextCertSerial(ctx context.Context) (uint64, error) {
	var serial int64
	err := s.pool.QueryRow(ctx, `SELECT nextval('ssh_cert_serial_seq')`).Scan(&serial)
	return uint64(serial), err
}

const caCols = `id, kind, algo, public_key, fingerprint, active, created_at, retired_at, signing_since`

func scanCA(row pgx.Row, c *models.CACert, extra ...any) error {
	return row.Scan(append([]any{&c.ID, &c.Kind, &c.Algo, &c.PublicKey, &c.Fingerprint, &c.Active,
		&c.CreatedAt, &c.RetiredAt, &c.SigningSince}, extra...)...)
}

// InsertCAKey stores a CA keypair (private material already encrypted).
//
// signing says whether it signs from the moment it exists. Only the first key does:
// a rotation's key is inserted trusted-but-not-signing and promoted later
// (PromoteCAKey), once everything that must trust it does. See migration 0112.
func (s *Store) InsertCAKey(ctx context.Context, kind, algo, publicKey string, privateEnc []byte, fingerprint string, signing bool) (*models.CACert, error) {
	var c models.CACert
	err := scanCA(s.pool.QueryRow(ctx, `
		INSERT INTO ca_keys (kind, algo, public_key, private_enc, fingerprint, signing_since)
		VALUES ($1,$2,$3,$4,$5, CASE WHEN $6 THEN now() END)
		RETURNING `+caCols,
		kind, algo, publicKey, privateEnc, fingerprint, signing), &c)
	return &c, err
}

// GetActiveCAKey returns the SIGNING CA of a kind plus its encrypted private key: the
// active key promoted most recently. A rotation's pending key is active (trusted)
// but not this.
func (s *Store) GetActiveCAKey(ctx context.Context, kind string) (*models.CACert, []byte, error) {
	var c models.CACert
	var priv []byte
	err := scanCA(s.pool.QueryRow(ctx, `
		SELECT `+caCols+`, private_enc
		FROM ca_keys WHERE kind=$1 AND active AND signing_since IS NOT NULL
		ORDER BY signing_since DESC LIMIT 1`, kind), &c, &priv)
	if err != nil {
		return nil, nil, mapNotFound(err)
	}
	return &c, priv, nil
}

// GetPendingCAKey returns a rotation's key that is trusted but not yet signing.
func (s *Store) GetPendingCAKey(ctx context.Context, kind string) (*models.CACert, []byte, error) {
	var c models.CACert
	var priv []byte
	err := scanCA(s.pool.QueryRow(ctx, `
		SELECT `+caCols+`, private_enc
		FROM ca_keys WHERE kind=$1 AND active AND signing_since IS NULL
		ORDER BY created_at DESC LIMIT 1`, kind), &c, &priv)
	if err != nil {
		return nil, nil, mapNotFound(err)
	}
	return &c, priv, nil
}

// PromoteCAKey makes a pending key the signer.
func (s *Store) PromoteCAKey(ctx context.Context, id uuid.UUID) error {
	// Matching nothing is a failure: a key reported promoted that is not would leave
	// the old one signing while the operator believes the rotation finished.
	tag, err := s.pool.Exec(ctx,
		`UPDATE ca_keys SET signing_since=now() WHERE id=$1 AND active AND signing_since IS NULL`, id)
	return changed(tag, err)
}

// ActiveCACreatedAt returns when the signing CA key of a kind was created (for
// rotation-age checks), without fetching private material.
func (s *Store) ActiveCACreatedAt(ctx context.Context, kind string) (time.Time, error) {
	var t time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT created_at FROM ca_keys WHERE kind=$1 AND active AND signing_since IS NOT NULL
		 ORDER BY signing_since DESC LIMIT 1`, kind).
		Scan(&t)
	if err != nil {
		return time.Time{}, mapNotFound(err)
	}
	return t, nil
}

// ListCAKeys returns CA metadata (no private material).
func (s *Store) ListCAKeys(ctx context.Context) ([]models.CACert, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+caCols+` FROM ca_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.CACert
	for rows.Next() {
		var c models.CACert
		if err := scanCA(rows, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListActiveCAPublicKeys returns the authorized_keys lines of all CAs of a kind
// that hosts should trust (supports rotation: old + new active simultaneously).
func (s *Store) ListActiveCAPublicKeys(ctx context.Context, kind string) ([]string, error) {
	return s.scanStrings(ctx, `SELECT public_key FROM ca_keys WHERE kind=$1 AND active=true`, kind)
}

// RetireCAKey marks a CA inactive, so it stops being trusted at the next push. It
// refuses the signing key: retiring that would leave nothing to sign with.
func (s *Store) RetireCAKey(ctx context.Context, id uuid.UUID) error {
	// Matching nothing is a failure, not a no-op: a CA key reported retired still signs.
	tag, err := s.pool.Exec(ctx, `
		UPDATE ca_keys SET active=false, retired_at=now()
		 WHERE id=$1 AND active
		   AND id <> (SELECT id FROM ca_keys k WHERE k.kind=ca_keys.kind AND k.active AND k.signing_since IS NOT NULL
		              ORDER BY k.signing_since DESC LIMIT 1)`, id)
	return changed(tag, err)
}

// CATrustHash is the identity of a set of trusted CA keys: what a host is recorded as
// confirming, and what "in sync" is compared against. Order and whitespace do not
// change what sshd trusts, so neither changes the hash.
func CATrustHash(keys []string) string {
	norm := make([]string, 0, len(keys))
	for _, k := range keys {
		f := strings.Fields(k)
		if len(f) >= 2 {
			norm = append(norm, f[0]+" "+f[1])
		}
	}
	sort.Strings(norm)
	sum := sha256.Sum256([]byte(strings.Join(norm, "\n")))
	return hex.EncodeToString(sum[:])
}

// RecordHostCATrust stores the outcome of pushing CA trust to a host: on success the
// hash it confirmed; on failure why, leaving the last confirmed hash in place.
func (s *Store) RecordHostCATrust(ctx context.Context, hostID uuid.UUID, hash, failure string) error {
	var tag pgconn.CommandTag
	var err error
	if failure == "" {
		tag, err = s.pool.Exec(ctx, `UPDATE hosts SET ca_trust_hash=$2, ca_trust_confirmed_at=now(),
			ca_trust_error='', ca_trust_attempted_at=now() WHERE id=$1`, hostID, hash)
	} else {
		tag, err = s.pool.Exec(ctx, `UPDATE hosts SET ca_trust_error=$2, ca_trust_attempted_at=now()
			WHERE id=$1`, hostID, failure)
	}
	return changed(tag, err)
}

// HostCATrust is what one host has confirmed about CA trust.
type HostCATrust struct {
	HostID      uuid.UUID  `json:"hostId"`
	Hostname    string     `json:"hostname"`
	Hash        string     `json:"-"`
	InSync      bool       `json:"inSync"`
	ConfirmedAt *time.Time `json:"confirmedAt,omitempty"`
	AttemptedAt *time.Time `json:"attemptedAt,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// HostsCATrust lists every enrolled SSH host with what it has confirmed, and whether
// that is the current trusted set (want). Windows hosts are not listed: they do not
// authenticate with the SSH CA.
func (s *Store) HostsCATrust(ctx context.Context, want string) ([]HostCATrust, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, ca_trust_hash, ca_trust_confirmed_at, ca_trust_attempted_at, ca_trust_error
		  FROM hosts WHERE enrolled AND protocol <> 'rdp' ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostCATrust
	for rows.Next() {
		var h HostCATrust
		if err := rows.Scan(&h.HostID, &h.Hostname, &h.Hash, &h.ConfirmedAt, &h.AttemptedAt, &h.Error); err != nil {
			return nil, err
		}
		h.InSync = h.Hash != "" && h.Hash == want
		out = append(out, h)
	}
	return out, rows.Err()
}

// InsertCertificateParams carries issued-certificate metadata.
type InsertCertificateParams struct {
	Serial     uint64
	Kind       string
	CAKeyID    uuid.UUID
	UserID     *uuid.UUID
	SessionID  *uuid.UUID
	HostID     *uuid.UUID
	KeyID      string
	Principals []string
	PublicKey  string
	AuditID    uuid.UUID
	ExpiresAt  time.Time
}

// InsertCertificate records issued-certificate metadata (NEVER the private key).
func (s *Store) InsertCertificate(ctx context.Context, p InsertCertificateParams) (*models.SSHCertificate, error) {
	if p.Principals == nil {
		p.Principals = []string{}
	}
	var c models.SSHCertificate
	var serial, expSerial int64
	serial = int64(p.Serial)
	err := s.pool.QueryRow(ctx, `
		INSERT INTO ssh_certificates
			(serial, kind, ca_key_id, user_id, session_id, host_id, key_id, principals, public_key, audit_id, expires_at, instance_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING serial, id, kind, key_id, principals, public_key, audit_id, issued_at, expires_at`,
		serial, p.Kind, p.CAKeyID, p.UserID, p.SessionID, p.HostID, p.KeyID, p.Principals, p.PublicKey, p.AuditID, p.ExpiresAt, s.ownerArg()).
		Scan(&expSerial, &c.ID, &c.Kind, &c.KeyID, &c.Principals, &c.PublicKey, &c.AuditID, &c.IssuedAt, &c.ExpiresAt)
	if err != nil {
		return nil, err
	}
	c.Serial = uint64(expSerial)
	c.CAKeyID = p.CAKeyID
	c.UserID = p.UserID
	c.SessionID = p.SessionID
	c.HostID = p.HostID
	return &c, nil
}

// ListCertificates returns certificate metadata, newest first.
func (s *Store) ListCertificates(ctx context.Context, sessionID *uuid.UUID, limit int) ([]models.SSHCertificate, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var rows pgx.Rows
	var err error
	base := `SELECT serial, id, kind, ca_key_id, user_id, session_id, host_id, key_id, principals,
		public_key, audit_id, issued_at, expires_at, revoked_at, COALESCE(revoke_reason,'')
		FROM ssh_certificates`
	if sessionID != nil {
		rows, err = s.pool.Query(ctx, base+` WHERE session_id=$1 ORDER BY issued_at DESC LIMIT $2`, *sessionID, limit)
	} else {
		rows, err = s.pool.Query(ctx, base+` ORDER BY issued_at DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SSHCertificate
	for rows.Next() {
		var c models.SSHCertificate
		var serial int64
		if err := rows.Scan(&serial, &c.ID, &c.Kind, &c.CAKeyID, &c.UserID, &c.SessionID, &c.HostID,
			&c.KeyID, &c.Principals, &c.PublicKey, &c.AuditID, &c.IssuedAt, &c.ExpiresAt, &c.RevokedAt, &c.RevokeReason); err != nil {
			return nil, err
		}
		c.Serial = uint64(serial)
		out = append(out, c)
	}
	return out, rows.Err()
}

// RevokeCertificate marks a certificate revoked and records it in the KRL table.
func (s *Store) RevokeCertificate(ctx context.Context, serial uint64, reason string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		// A serial this instance never issued matches nothing here. The KRL entry
		// below is still written -- refusing an unknown serial is the safe
		// direction -- but the caller is told, because "revoked" for a
		// certificate that was never found is the kind of success nobody should
		// act on.
		tag, err := tx.Exec(ctx,
			`UPDATE ssh_certificates SET revoked_at=now(), revoke_reason=$2 WHERE serial=$1`,
			int64(serial), reason)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO cert_revocations (serial, reason) VALUES ($1,$2) ON CONFLICT (serial) DO NOTHING`,
			int64(serial), reason); err != nil {
			return err
		}
		return changed(tag, nil)
	})
}

// RevokeSessionCertificates revokes all certs bound to a browser session
// (called on logout/idle/cleanup), marking them revoked AND recording their
// serials in the KRL (cert_revocations) so the revocation survives even if the
// certificate rows are later deleted (e.g. by a cascading user delete).
func (s *Store) RevokeSessionCertificates(ctx context.Context, sessionID uuid.UUID, reason string) (int64, error) {
	var count int64
	err := s.tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			UPDATE ssh_certificates SET revoked_at=now(), revoke_reason=$2
			WHERE session_id=$1 AND revoked_at IS NULL
			RETURNING serial`, sessionID, reason)
		if err != nil {
			return err
		}
		var serials []int64
		for rows.Next() {
			var serial int64
			if err := rows.Scan(&serial); err != nil {
				rows.Close()
				return err
			}
			serials = append(serials, serial)
		}
		rows.Close()
		for _, serial := range serials {
			if _, err := tx.Exec(ctx,
				`INSERT INTO cert_revocations (serial, reason) VALUES ($1,$2) ON CONFLICT (serial) DO NOTHING`,
				serial, reason); err != nil {
				return err
			}
		}
		count = int64(len(serials))
		return nil
	})
	return count, err
}

// RevokeDeadInstanceCertificates revokes still-valid ephemeral certificates whose
// issuing instance is no longer alive (heartbeat older than lease). Those certs are
// keyless — their private key died with the instance's RAM — so revoking them is safe
// hygiene and never touches a live instance's own cert for the same session. Only
// rows with a known (non-NULL) dead issuer are revoked; legacy NULL-issuer certs are
// left alone, as are the caller's own certs — the caller is alive by definition even
// when a stall has let its heartbeat row go stale (same self-guard as
// deadOwnerPredicate). Returns the number revoked so the caller can refresh the KRL.
func (s *Store) RevokeDeadInstanceCertificates(ctx context.Context, lease time.Duration, self uuid.UUID) (int64, error) {
	var count int64
	err := s.tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			UPDATE ssh_certificates SET revoked_at=now(), revoke_reason='issuing instance died'
			WHERE revoked_at IS NULL AND expires_at > now() AND instance_id IS NOT NULL
			  AND instance_id <> $2
			  AND NOT EXISTS (
			    SELECT 1 FROM cluster_instances ci
			    WHERE ci.id = ssh_certificates.instance_id
			      AND ci.last_heartbeat > now() - $1::interval)
			RETURNING serial`, lease.String(), self)
		if err != nil {
			return err
		}
		var serials []int64
		for rows.Next() {
			var serial int64
			if err := rows.Scan(&serial); err != nil {
				rows.Close()
				return err
			}
			serials = append(serials, serial)
		}
		rows.Close()
		for _, serial := range serials {
			if _, err := tx.Exec(ctx,
				`INSERT INTO cert_revocations (serial, reason) VALUES ($1,'issuing instance died') ON CONFLICT (serial) DO NOTHING`,
				serial); err != nil {
				return err
			}
		}
		count = int64(len(serials))
		return nil
	})
	return count, err
}

// PruneExpiredRevocations drops KRL entries older than the cutoff. A revoked
// certificate that has already expired is rejected by its validity dates anyway,
// so keeping its serial in the KRL is unnecessary — this bounds the KRL size.
func (s *Store) PruneExpiredRevocations(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM cert_revocations WHERE revoked_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RevokedSerials returns all revoked serials (for KRL generation).
func (s *Store) RevokedSerials(ctx context.Context) ([]uint64, error) {
	rows, err := s.pool.Query(ctx, `SELECT serial FROM cert_revocations ORDER BY serial`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uint64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, uint64(s))
	}
	return out, rows.Err()
}

// ExpiringCertificates returns non-revoked user certs expiring before the cutoff,
// used by the renewal scheduler.
func (s *Store) ExpiringCertificates(ctx context.Context, before time.Time) ([]models.SSHCertificate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT serial, id, kind, ca_key_id, user_id, session_id, host_id, key_id, principals,
			public_key, audit_id, issued_at, expires_at
		FROM ssh_certificates
		WHERE kind='user' AND revoked_at IS NULL
		   AND expires_at > now() AND expires_at < $1
		ORDER BY expires_at ASC`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SSHCertificate
	for rows.Next() {
		var c models.SSHCertificate
		var serial int64
		if err := rows.Scan(&serial, &c.ID, &c.Kind, &c.CAKeyID, &c.UserID, &c.SessionID, &c.HostID,
			&c.KeyID, &c.Principals, &c.PublicKey, &c.AuditID, &c.IssuedAt, &c.ExpiresAt); err != nil {
			return nil, err
		}
		c.Serial = uint64(serial)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ReSealCAKey replaces the encrypted private key blob for a CA key (used to
// opportunistically upgrade the at-rest encryption envelope in place).
func (s *Store) ReSealCAKey(ctx context.Context, id uuid.UUID, privateEnc []byte) error {
	_, err := s.pool.Exec(ctx, `UPDATE ca_keys SET private_enc=$2 WHERE id=$1`, id, privateEnc)
	return err
}
