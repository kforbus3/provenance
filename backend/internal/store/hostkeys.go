package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// HostKeyPin is a persisted SSH host-key pin used by the gateway's TOFU verifier.
type HostKeyPin struct {
	Host    string
	KeyLine string
	KeyType string
	Source  string // "tofu" | "pinned"
}

// GetHostKey returns the pinned key line for a normalized host, or ok=false if none.
func (s *Store) GetHostKey(ctx context.Context, host string) (HostKeyPin, bool, error) {
	var p HostKeyPin
	err := s.pool.QueryRow(ctx,
		`SELECT host, key_line, key_type, source FROM ssh_host_keys WHERE host=$1`, host).
		Scan(&p.Host, &p.KeyLine, &p.KeyType, &p.Source)
	if errors.Is(err, pgx.ErrNoRows) {
		return HostKeyPin{}, false, nil
	}
	if err != nil {
		return HostKeyPin{}, false, err
	}
	return p, true, nil
}

// PinHostKey records a first-seen (TOFU) host key. It never overwrites an existing pin
// (ON CONFLICT DO NOTHING) so a durable pin can't be silently replaced by a later,
// possibly-hostile key — a changed key surfaces as a mismatch at the verifier instead.
func (s *Store) PinHostKey(ctx context.Context, host, keyLine, keyType string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO ssh_host_keys (host, key_line, key_type, source)
		 VALUES ($1,$2,$3,'tofu') ON CONFLICT (host) DO NOTHING`,
		host, keyLine, keyType)
	return err
}

// SetPinnedHostKey deliberately pins (or re-pins) a host key with source='pinned' — for
// operator pre-provisioning at enrollment, so the very first connect is verified rather
// than trusted. Overwrites any existing pin for the host.
func (s *Store) SetPinnedHostKey(ctx context.Context, host, keyLine, keyType string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO ssh_host_keys (host, key_line, key_type, source)
		 VALUES ($1,$2,$3,'pinned')
		 ON CONFLICT (host) DO UPDATE SET key_line=$2, key_type=$3, source='pinned', updated_at=now()`,
		host, keyLine, keyType)
	return err
}

// DeleteHostKey removes a host's pin (e.g. after a legitimate rebuild) so the next
// connection re-pins.
func (s *Store) DeleteHostKey(ctx context.Context, host string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM ssh_host_keys WHERE host=$1`, host)
	return err
}
