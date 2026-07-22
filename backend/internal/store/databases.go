package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

const databaseCols = `d.id, d.name, d.engine, d.address, d.port, d.database_name, d.credential_id,
	COALESCE(s.name,''), d.description, COALESCE(u.username,''), d.created_at, d.updated_at`

func scanDatabase(row interface{ Scan(...any) error }) (*models.Database, error) {
	var d models.Database
	if err := row.Scan(&d.ID, &d.Name, &d.Engine, &d.Address, &d.Port, &d.DatabaseName,
		&d.CredentialID, &d.CredentialName, &d.Description, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return nil, err
	}
	return &d, nil
}

const databaseFrom = `FROM databases d
	LEFT JOIN vault_secrets s ON s.id = d.credential_id
	LEFT JOIN users u ON u.id = d.created_by`

// ListDatabases returns all registered database targets, alphabetical.
func (s *Store) ListDatabases(ctx context.Context) ([]models.Database, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+databaseCols+` `+databaseFrom+` ORDER BY d.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Database
	for rows.Next() {
		d, err := scanDatabase(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// GetDatabase returns one database target.
func (s *Store) GetDatabase(ctx context.Context, id uuid.UUID) (*models.Database, error) {
	return scanDatabase(s.pool.QueryRow(ctx, `SELECT `+databaseCols+` `+databaseFrom+` WHERE d.id=$1`, id))
}

// DatabaseInput is the payload to create or update a database target.
type DatabaseInput struct {
	Name         string
	Engine       string
	Address      string
	Port         int
	DatabaseName string
	CredentialID *uuid.UUID
	Description  string
	CreatedBy    uuid.UUID
}

// CreateDatabase registers a database target. The engine is validated by the handler
// (dbbroker.engineSupported) before reaching here.
func (s *Store) CreateDatabase(ctx context.Context, in DatabaseInput) (*models.Database, error) {
	var id uuid.UUID
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO databases (name, engine, address, port, database_name, credential_id, description, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		in.Name, in.Engine, in.Address, in.Port, in.DatabaseName, in.CredentialID, in.Description, in.CreatedBy).Scan(&id); err != nil {
		return nil, err
	}
	return s.GetDatabase(ctx, id)
}

// UpdateDatabase edits a database target's metadata.
func (s *Store) UpdateDatabase(ctx context.Context, id uuid.UUID, in DatabaseInput) (*models.Database, error) {
	if _, err := s.pool.Exec(ctx, `
		UPDATE databases SET name=$2, engine=$3, address=$4, port=$5, database_name=$6,
			credential_id=$7, description=$8, updated_at=now()
		WHERE id=$1`,
		id, in.Name, in.Engine, in.Address, in.Port, in.DatabaseName, in.CredentialID, in.Description); err != nil {
		return nil, err
	}
	return s.GetDatabase(ctx, id)
}

// DeleteDatabase removes a database target.
func (s *Store) DeleteDatabase(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM databases WHERE id=$1`, id)
	return err
}
