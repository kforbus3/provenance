package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

// NextCertSerial allocates a unique, never-reused certificate serial.
func (s *Store) NextCertSerial(ctx context.Context) (uint64, error) {
	var serial int64
	err := s.pool.QueryRow(ctx, `SELECT nextval('ssh_cert_serial_seq')`).Scan(&serial)
	return uint64(serial), err
}

// InsertCAKey stores a CA keypair (private material already encrypted).
func (s *Store) InsertCAKey(ctx context.Context, kind, algo, publicKey string, privateEnc []byte, fingerprint string) (*models.CACert, error) {
	var c models.CACert
	err := s.pool.QueryRow(ctx, `
		INSERT INTO ca_keys (kind, algo, public_key, private_enc, fingerprint)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, kind, algo, public_key, fingerprint, active, created_at, retired_at`,
		kind, algo, publicKey, privateEnc, fingerprint).
		Scan(&c.ID, &c.Kind, &c.Algo, &c.PublicKey, &c.Fingerprint, &c.Active, &c.CreatedAt, &c.RetiredAt)
	return &c, err
}

// GetActiveCAKey returns the active CA of a kind plus its encrypted private key.
func (s *Store) GetActiveCAKey(ctx context.Context, kind string) (*models.CACert, []byte, error) {
	var c models.CACert
	var priv []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, kind, algo, public_key, private_enc, fingerprint, active, created_at, retired_at
		FROM ca_keys WHERE kind=$1 AND active=true ORDER BY created_at DESC LIMIT 1`, kind).
		Scan(&c.ID, &c.Kind, &c.Algo, &c.PublicKey, &priv, &c.Fingerprint, &c.Active, &c.CreatedAt, &c.RetiredAt)
	if err != nil {
		return nil, nil, mapNotFound(err)
	}
	return &c, priv, nil
}

// ActiveCACreatedAt returns when the active CA key of a kind was created (for
// rotation-age checks), without fetching private material.
func (s *Store) ActiveCACreatedAt(ctx context.Context, kind string) (time.Time, error) {
	var t time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT created_at FROM ca_keys WHERE kind=$1 AND active=true ORDER BY created_at DESC LIMIT 1`, kind).
		Scan(&t)
	if err != nil {
		return time.Time{}, mapNotFound(err)
	}
	return t, nil
}

// ListCAKeys returns CA metadata (no private material).
func (s *Store) ListCAKeys(ctx context.Context) ([]models.CACert, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, kind, algo, public_key, fingerprint, active, created_at, retired_at
		FROM ca_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.CACert
	for rows.Next() {
		var c models.CACert
		if err := rows.Scan(&c.ID, &c.Kind, &c.Algo, &c.PublicKey, &c.Fingerprint, &c.Active, &c.CreatedAt, &c.RetiredAt); err != nil {
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

// RetireCAKey marks a CA inactive.
func (s *Store) RetireCAKey(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE ca_keys SET active=false, retired_at=now() WHERE id=$1`, id)
	return err
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
			(serial, kind, ca_key_id, user_id, session_id, host_id, key_id, principals, public_key, audit_id, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING serial, id, kind, key_id, principals, public_key, audit_id, issued_at, expires_at`,
		serial, p.Kind, p.CAKeyID, p.UserID, p.SessionID, p.HostID, p.KeyID, p.Principals, p.PublicKey, p.AuditID, p.ExpiresAt).
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
		if _, err := tx.Exec(ctx,
			`UPDATE ssh_certificates SET revoked_at=now(), revoke_reason=$2 WHERE serial=$1`,
			int64(serial), reason); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO cert_revocations (serial, reason) VALUES ($1,$2) ON CONFLICT (serial) DO NOTHING`,
			int64(serial), reason)
		return err
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
		WHERE kind='user' AND revoked_at IS NULL AND expires_at < $1
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
