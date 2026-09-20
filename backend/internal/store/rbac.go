package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kforbus3/provenance/backend/internal/models"
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
	// Matching nothing is a failure, not a no-op: a role reported deleted still carries its permissions.
	tag, err := s.pool.Exec(ctx, `DELETE FROM roles WHERE id=$1 AND is_builtin=false`, id)
	return changed(tag, err)
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
	// The role is resolved first, so a name that names nothing is an error rather
	// than a successful no-op.
	//
	// This was `INSERT ... SELECT id FROM roles WHERE name=$2 ON CONFLICT DO
	// NOTHING`, which inserts nothing and returns nil when no such role exists.
	// Every caller is an identity provider mapping an IdP group to a Provenance
	// role, and the roles here are named Administrator and Read-Only -- so an
	// operator who wires up SSO with "Admin" and "Viewer", which is what most
	// products call them, gets users who authenticate perfectly and hold no
	// permissions at all, with nothing logged and nothing refused. Found by
	// mapping three Keycloak groups and having exactly the one whose spelling
	// happened to match take effect.
	//
	// RowsAffected cannot tell the two cases apart on its own: ON CONFLICT DO
	// NOTHING also reports zero rows for a role the user already holds, which is a
	// genuine no-op success.
	var roleID uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT id FROM roles WHERE name=$1`, roleName).Scan(&roleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %q", ErrNoSuchRole, roleName)
	}
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, userID, roleID)
	return err
}

// ErrNoSuchRole reports a role name that does not name a role. Distinguished from
// any other failure because the remedy is different: nothing is wrong with the
// database, the configuration names something that is not there.
var ErrNoSuchRole = errors.New("no such role")

// RoleNames lists every role name, for validating a configuration against the
// roles that exist and for telling an operator what the valid answers are.
func (s *Store) RoleNames(ctx context.Context) ([]string, error) {
	return s.scanStrings(ctx, `SELECT name FROM roles ORDER BY name`)
}

// UnknownRoleNames returns those of the given names that do not name a role,
// in the order given, with duplicates and blanks dropped.
//
// Used by the identity-provider configuration endpoints so a group→role mapping
// that cannot work is refused when it is saved, rather than at the login of the
// person it silently grants nothing to.
func (s *Store) UnknownRoleNames(ctx context.Context, names []string) ([]string, error) {
	have, err := s.RoleNames(ctx)
	if err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(have))
	for _, n := range have {
		known[n] = true
	}
	var unknown []string
	seen := map[string]bool{}
	for _, n := range names {
		if n == "" || seen[n] || known[n] {
			continue
		}
		seen[n] = true
		unknown = append(unknown, n)
	}
	return unknown, nil
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
	// Matching nothing is a failure, not a no-op: the user keeps every permission the role carries.
	tag, err := s.pool.Exec(ctx, `DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2`, userID, roleID)
	return changed(tag, err)
}

// RemoveRoleByName revokes a role from a user by role name.
func (s *Store) RemoveRoleByName(ctx context.Context, userID uuid.UUID, roleName string) error {
	// Matching nothing is a failure, not a no-op: same, by name.
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM user_roles WHERE user_id=$1
		AND role_id IN (SELECT id FROM roles WHERE name=$2)`, userID, roleName)
	return changed(tag, err)
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
