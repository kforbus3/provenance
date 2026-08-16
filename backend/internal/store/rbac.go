package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kforbus3/Moorgate/backend/internal/models"
)

// ListPermissions returns the permission catalog.
func (s *Store) ListPermissions(ctx context.Context) ([]models.Permission, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, description FROM permissions ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Permission
	for rows.Next() {
		var p models.Permission
		if err := rows.Scan(&p.Key, &p.Description); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListRoles returns all roles with their permission keys.
func (s *Store) ListRoles(ctx context.Context) ([]models.Role, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, description, is_builtin, created_at FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []models.Role
	for rows.Next() {
		var r models.Role
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.IsBuiltin, &r.CreatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range roles {
		roles[i].Permissions, _ = s.RolePermissions(ctx, roles[i].ID)
	}
	return roles, nil
}

// GetRoleByName returns a single role by name.
func (s *Store) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	var r models.Role
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, description, is_builtin, created_at FROM roles WHERE name=$1`, name).
		Scan(&r.ID, &r.Name, &r.Description, &r.IsBuiltin, &r.CreatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &r, nil
}

// CreateRole creates a custom role.
func (s *Store) CreateRole(ctx context.Context, name, description string) (*models.Role, error) {
	var r models.Role
	err := s.pool.QueryRow(ctx,
		`INSERT INTO roles (name, description, is_builtin) VALUES ($1,$2,false)
		 RETURNING id, name, description, is_builtin, created_at`, name, description).
		Scan(&r.ID, &r.Name, &r.Description, &r.IsBuiltin, &r.CreatedAt)
	return &r, err
}

// DeleteRole removes a non-builtin role.
func (s *Store) DeleteRole(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM roles WHERE id=$1 AND is_builtin=false`, id)
	return err
}

// RolePermissions lists permission keys assigned to a role.
func (s *Store) RolePermissions(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	return s.scanStrings(ctx,
		`SELECT permission_key FROM role_permissions WHERE role_id=$1 ORDER BY permission_key`, roleID)
}

// SetRolePermissions replaces a role's permission set.
func (s *Store) SetRolePermissions(ctx context.Context, roleID uuid.UUID, keys []string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id=$1`, roleID); err != nil {
			return err
		}
		for _, k := range keys {
			if _, err := tx.Exec(ctx,
				`INSERT INTO role_permissions (role_id, permission_key) VALUES ($1,$2)
				 ON CONFLICT DO NOTHING`, roleID, k); err != nil {
				return err
			}
		}
		return nil
	})
}

// AssignRole grants a role to a user.
func (s *Store) AssignRole(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, userID, roleID)
	return err
}

// AssignRoleByName grants a role to a user by role name.
func (s *Store) AssignRoleByName(ctx context.Context, userID uuid.UUID, roleName string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id)
		SELECT $1, id FROM roles WHERE name=$2 ON CONFLICT DO NOTHING`, userID, roleName)
	return err
}

// RoleName returns a role's name by id ("" when the role does not exist).
func (s *Store) RoleName(ctx context.Context, roleID uuid.UUID) (string, error) {
	var name string
	err := s.pool.QueryRow(ctx, `SELECT name FROM roles WHERE id=$1`, roleID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return name, err
}

// RemoveRole revokes a role from a user.
func (s *Store) RemoveRole(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2`, userID, roleID)
	return err
}

// RemoveRoleByName revokes a role from a user by role name.
func (s *Store) RemoveRoleByName(ctx context.Context, userID uuid.UUID, roleName string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM user_roles WHERE user_id=$1
		AND role_id IN (SELECT id FROM roles WHERE name=$2)`, userID, roleName)
	return err
}

// UserRoleNames lists a user's role names.
func (s *Store) UserRoleNames(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return s.scanStrings(ctx, `
		SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id
		WHERE ur.user_id=$1 ORDER BY r.name`, userID)
}

// UserPermissions resolves the effective permission set for a user across all
// roles. Super admins and holders of Admin.All implicitly have everything; the
// enforcement layer treats Admin.All as a wildcard.
func (s *Store) UserPermissions(ctx context.Context, userID uuid.UUID) (map[string]bool, error) {
	keys, err := s.scanStrings(ctx, `
		SELECT DISTINCT rp.permission_key
		FROM user_roles ur
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		WHERE ur.user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(keys))
	for _, k := range keys {
		set[k] = true
	}
	return set, nil
}

func (s *Store) scanStrings(ctx context.Context, sql string, args ...any) ([]string, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
