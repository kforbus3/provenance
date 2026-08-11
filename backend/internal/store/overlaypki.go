package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// OverlayCARecord is the persisted X.509 overlay CA (cert + sealed key).
type OverlayCARecord struct {
	ID          uuid.UUID
	CertPEM     string
	KeyEnc      []byte
	Fingerprint string
}

// GetActiveOverlayCA returns the active overlay CA, or ErrNotFound if none exists.
func (s *Store) GetActiveOverlayCA(ctx context.Context) (*OverlayCARecord, error) {
	var r OverlayCARecord
	err := s.pool.QueryRow(ctx, `
		SELECT id, cert_pem, key_enc, fingerprint
		FROM overlay_ca WHERE active = true ORDER BY created_at DESC LIMIT 1`).
		Scan(&r.ID, &r.CertPEM, &r.KeyEnc, &r.Fingerprint)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &r, nil
}

// InsertOverlayCA stores a freshly generated overlay CA and returns its id.
func (s *Store) InsertOverlayCA(ctx context.Context, certPEM string, keyEnc []byte, fingerprint string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO overlay_ca (cert_pem, key_enc, fingerprint) VALUES ($1,$2,$3) RETURNING id`,
		certPEM, keyEnc, fingerprint).Scan(&id)
	return id, err
}

// UpdateOverlayCAKeyEnc replaces the sealed key blob for an overlay CA in place (used
// by the FIPS re-seal sweep to re-KDF the envelope without rotating the CA).
func (s *Store) UpdateOverlayCAKeyEnc(ctx context.Context, id uuid.UUID, keyEnc []byte) error {
	_, err := s.pool.Exec(ctx, `UPDATE overlay_ca SET key_enc=$2 WHERE id=$1`, id, keyEnc)
	return err
}

// RecordOverlayClient records an issued client certificate for a host.
func (s *Store) RecordOverlayClient(ctx context.Context, hostID uuid.UUID, commonName, serial string, notAfter time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO overlay_clients (host_id, common_name, serial, not_after)
		VALUES ($1,$2,$3,$4)`, hostID, commonName, serial, notAfter)
	return err
}

// OverlayClientCert is an issued overlay client certificate.
type OverlayClientCert struct {
	CommonName string
	Serial     string
	NotAfter   time.Time
}

// OverlayClientsForHost lists the client certificates issued to a host. Call it
// BEFORE deleting the host — overlay_clients cascades on host delete.
func (s *Store) OverlayClientsForHost(ctx context.Context, hostID uuid.UUID) ([]OverlayClientCert, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT common_name, serial, not_after FROM overlay_clients
		 WHERE host_id = $1 AND revoked_at IS NULL`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OverlayClientCert
	for rows.Next() {
		var c OverlayClientCert
		if err := rows.Scan(&c.CommonName, &c.Serial, &c.NotAfter); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RevokeOverlayClients marks the given certificates revoked and records them in the
// revocation list. The overlay_clients update is best-effort bookkeeping — those rows
// disappear with the host — while the overlay_revocations insert is what the CRL is
// built from, so it must survive the host.
func (s *Store) RevokeOverlayClients(ctx context.Context, certs []OverlayClientCert, reason string) error {
	for _, c := range certs {
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO overlay_revocations(serial, common_name, not_after, reason)
			 VALUES ($1, $2, $3, $4) ON CONFLICT (serial) DO NOTHING`,
			c.Serial, c.CommonName, c.NotAfter, reason); err != nil {
			return err
		}
		_, _ = s.pool.Exec(ctx,
			`UPDATE overlay_clients SET revoked_at = now() WHERE serial = $1 AND revoked_at IS NULL`, c.Serial)
	}
	return nil
}

// RevokedOverlaySerials returns every revoked serial that has not yet expired. An
// expired certificate is refused on its own dates, so listing it only grows the CRL.
func (s *Store) RevokedOverlaySerials(ctx context.Context) ([]OverlayClientCert, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT common_name, serial, not_after FROM overlay_revocations
		 WHERE not_after > now() ORDER BY revoked_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OverlayClientCert
	for rows.Next() {
		var c OverlayClientCert
		if err := rows.Scan(&c.CommonName, &c.Serial, &c.NotAfter); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PruneExpiredOverlayRevocations drops entries whose certificate has expired.
func (s *Store) PruneExpiredOverlayRevocations(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM overlay_revocations WHERE not_after <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
