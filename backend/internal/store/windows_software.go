package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

// ReplaceWindowsSoftware replaces a host's installed-software inventory with the
// given set (a full re-collection each time), atomically.
func (s *Store) ReplaceWindowsSoftware(ctx context.Context, hostID uuid.UUID, items []models.WindowsSoftware) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM windows_software WHERE host_id=$1`, hostID); err != nil {
			return err
		}
		for _, it := range items {
			if it.Name == "" {
				continue
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO windows_software (host_id, name, version, publisher) VALUES ($1,$2,$3,$4)
				 ON CONFLICT (host_id, name, version) DO UPDATE SET publisher=EXCLUDED.publisher, collected_at=now()`,
				hostID, it.Name, it.Version, it.Publisher); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListWindowsSoftware returns a host's installed-software inventory, name-sorted.
func (s *Store) ListWindowsSoftware(ctx context.Context, hostID uuid.UUID) ([]models.WindowsSoftware, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT name, version, publisher, collected_at FROM windows_software WHERE host_id=$1 ORDER BY lower(name), version`,
		hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.WindowsSoftware
	for rows.Next() {
		var w models.WindowsSoftware
		if err := rows.Scan(&w.Name, &w.Version, &w.Publisher, &w.CollectedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}
