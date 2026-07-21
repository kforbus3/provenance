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
