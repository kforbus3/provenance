package store

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

// The tenants table is not itself RLS-scoped, but the per-tenant user/host counts read
// RLS'd tables, so callers of these provider-admin methods pass a bypass context.

var slugRE = regexp.MustCompile(`[^a-z0-9-]+`)

func slugify(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = slugRE.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "tenant"
	}
	if len(s) > 48 {
		s = s[:48]
	}
	return s
}

// CreateTenant creates a customer tenant with a unique slug derived from name.
func (s *Store) CreateTenant(ctx context.Context, name string) (*models.Tenant, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("tenant name is required")
	}
	base := slugify(name)
	// Find a free slug (base, base-2, base-3, …).
	slug := base
	for n := 2; ; n++ {
		var exists bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE slug=$1)`, slug).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			break
		}
		slug = fmt.Sprintf("%s-%d", base, n)
	}
	var t models.Tenant
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, kind, status) VALUES ($1,$2,'customer','active')
		RETURNING id, name, slug, kind, status, created_at, updated_at`, name, slug).
		Scan(&t.ID, &t.Name, &t.Slug, &t.Kind, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ListTenants returns every tenant, provider first, with per-tenant user + host counts.
// The count subqueries read RLS'd tables, so the caller must pass a bypass context.
func (s *Store) ListTenants(ctx context.Context) ([]models.Tenant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t.id, t.name, t.slug, t.kind, t.status, t.created_at, t.updated_at,
			(SELECT count(*) FROM users u WHERE u.tenant_id = t.id),
			(SELECT count(*) FROM hosts h WHERE h.tenant_id = t.id)
		FROM tenants t
		ORDER BY (t.kind <> 'provider'), t.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Tenant{}
	for rows.Next() {
		var t models.Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Kind, &t.Status, &t.CreatedAt, &t.UpdatedAt,
			&t.UserCount, &t.HostCount); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTenant loads one tenant by id (no counts).
func (s *Store) GetTenant(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	var t models.Tenant
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, slug, kind, status, created_at, updated_at FROM tenants WHERE id=$1`, id).
		Scan(&t.ID, &t.Name, &t.Slug, &t.Kind, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &t, nil
}

// SetTenantStatus suspends or re-activates a customer tenant. The provider tenant
// cannot be suspended.
func (s *Store) SetTenantStatus(ctx context.Context, id uuid.UUID, status string) error {
	if status != "active" && status != "suspended" {
		return fmt.Errorf("invalid status %q", status)
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE tenants SET status=$2, updated_at=now() WHERE id=$1 AND kind <> 'provider'`, id, status)
	return err
}

// RenameTenant updates a customer tenant's display name.
func (s *Store) RenameTenant(ctx context.Context, id uuid.UUID, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("tenant name is required")
	}
	_, err := s.pool.Exec(ctx, `UPDATE tenants SET name=$2, updated_at=now() WHERE id=$1`, id, name)
	return err
}
