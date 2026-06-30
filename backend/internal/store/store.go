// Package store is the repository layer over PostgreSQL. Every query uses
// parameterized statements (no string concatenation) to prevent SQL injection.
// Methods attach to *Store across multiple files grouped by domain entity.
package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fleet-terminal/backend/internal/models"
)

// ErrNotFound is returned when a lookup matches no rows.
var ErrNotFound = errors.New("not found")

// Store wraps a pgx pool and exposes repository methods.
type Store struct {
	pool      *pgxpool.Pool
	auditSink func(models.AuditEvent) // optional: forward each appended audit event
}

// New constructs a Store.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// SetAuditSink registers a callback invoked (asynchronously) for every audit
// event written via AppendAudit — used to forward events to syslog/SIEM. Set
// once at startup before serving.
func (s *Store) SetAuditSink(fn func(models.AuditEvent)) { s.auditSink = fn }

// Pool exposes the underlying pool for advanced/transactional use.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// tx runs fn inside a transaction, committing on success and rolling back on error.
func (s *Store) tx(ctx context.Context, fn func(pgx.Tx) error) error {
	t, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	if err := fn(t); err != nil {
		_ = t.Rollback(ctx)
		return err
	}
	return t.Commit(ctx)
}

// mapNotFound converts pgx.ErrNoRows into the package ErrNotFound.
func mapNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
