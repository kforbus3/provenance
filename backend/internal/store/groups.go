package store

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

// likeEscape escapes LIKE/ILIKE wildcards so user input is matched literally
// (paired with `ESCAPE '\'` in the query). Without it, a typed `%` or `_` would
// act as a wildcard.
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// SearchGroups returns groups whose name matches q (case-insensitive substring),
// ordered by name and capped at limit.
func (s *Store) SearchGroups(ctx context.Context, q string, limit int) ([]models.Group, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, description, created_at FROM groups
		 WHERE name ILIKE '%' || $1 || '%' ESCAPE '\'
		 ORDER BY name LIMIT $2`, likeEscape(q), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Group
	for rows.Next() {
		var g models.Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// AccessibleGroupIDs returns the set of group IDs a user already has access to —
// direct membership or an active temporary grant (all groups for super admins).
func (s *Store) AccessibleGroupIDs(ctx context.Context, userID uuid.UUID, isSuperAdmin bool) (map[uuid.UUID]bool, error) {
	query := `SELECT id FROM groups`
	args := []any{}
	if !isSuperAdmin {
		query = `
			SELECT group_id FROM user_groups WHERE user_id=$1
			UNION SELECT group_id FROM temporary_permissions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now() AND group_id IS NOT NULL`
		args = []any{userID}
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	set := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		set[id] = true
	}
	return set, rows.Err()
}

// ListGroups returns all groups.
func (s *Store) ListGroups(ctx context.Context) ([]models.Group, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, description, created_at FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Group
	for rows.Next() {
		var g models.Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GetGroup loads one group by id.
func (s *Store) GetGroup(ctx context.Context, id uuid.UUID) (*models.Group, error) {
	var g models.Group
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, description, created_at FROM groups WHERE id=$1`, id).
		Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &g, nil
}

// HostsInGroup returns the hosts that belong to a group (identity + connection
// fields only; no status/inventory fan-out — enough to run against them).
func (s *Store) HostsInGroup(ctx context.Context, groupID uuid.UUID) ([]models.Host, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+hostCols+` FROM hosts h
		 JOIN host_groups hg ON hg.host_id = h.id
		 WHERE hg.group_id = $1 ORDER BY h.hostname`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *h)
	}
	return out, rows.Err()
}

// CreateGroup creates a group.
func (s *Store) CreateGroup(ctx context.Context, name, description string) (*models.Group, error) {
	var g models.Group
	err := s.pool.QueryRow(ctx,
		`INSERT INTO groups (name, description) VALUES ($1,$2)
		 RETURNING id, name, description, created_at`, name, description).
		Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt)
	return &g, err
}

// DeleteGroup removes a group.
func (s *Store) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, id)
	return err
}

// AddUserToGroup adds a user to a group.
func (s *Store) AddUserToGroup(ctx context.Context, userID, groupID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_groups (user_id, group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, userID, groupID)
	return err
}

// RemoveUserFromGroup removes a user from a group.
func (s *Store) RemoveUserFromGroup(ctx context.Context, userID, groupID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM user_groups WHERE user_id=$1 AND group_id=$2`, userID, groupID)
	return err
}

// AddHostToGroup adds a host to a group.
func (s *Store) AddHostToGroup(ctx context.Context, hostID, groupID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO host_groups (host_id, group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, hostID, groupID)
	return err
}

// RemoveHostFromGroup removes a host from a group.
func (s *Store) RemoveHostFromGroup(ctx context.Context, hostID, groupID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM host_groups WHERE host_id=$1 AND group_id=$2`, hostID, groupID)
	return err
}

// UserGroupNames lists a user's group names.
func (s *Store) UserGroupNames(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return s.scanStrings(ctx, `
		SELECT g.name FROM user_groups ug JOIN groups g ON g.id=ug.group_id
		WHERE ug.user_id=$1 ORDER BY g.name`, userID)
}

// AddUserToHost grants a user direct access to an individual host.
func (s *Store) AddUserToHost(ctx context.Context, hostID, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO host_users (host_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, hostID, userID)
	return err
}

// RemoveUserFromHost revokes a user's direct access to a host.
func (s *Store) RemoveUserFromHost(ctx context.Context, hostID, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM host_users WHERE host_id=$1 AND user_id=$2`, hostID, userID)
	return err
}

// HostDirectUsers lists users granted direct (non-group) access to a host.
func (s *Store) HostDirectUsers(ctx context.Context, hostID uuid.UUID) ([]models.User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.username, COALESCE(u.display_name,''), COALESCE(u.email,'')
		FROM host_users hu JOIN users u ON u.id = hu.user_id
		WHERE hu.host_id = $1 ORDER BY u.username`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserCanAccessHost reports whether a user has access to a host through a shared
// group, a direct host grant, OR an active (non-expired) temporary permission.
func (s *Store) UserCanAccessHost(ctx context.Context, userID, hostID uuid.UUID) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			-- permanent: user and host share a group
			SELECT 1 FROM user_groups ug
			JOIN host_groups hg ON hg.group_id = ug.group_id
			WHERE ug.user_id = $1 AND hg.host_id = $2
			UNION
			-- permanent: direct user-to-host grant
			SELECT 1 FROM host_users hu
			WHERE hu.user_id = $1 AND hu.host_id = $2
			UNION
			-- temporary: direct host grant still active
			SELECT 1 FROM temporary_permissions tp
			WHERE tp.user_id = $1 AND tp.host_id = $2
			  AND tp.revoked_at IS NULL AND tp.expires_at > now()
			UNION
			-- temporary: group grant covering the host, still active
			SELECT 1 FROM temporary_permissions tp
			JOIN host_groups hg ON hg.group_id = tp.group_id
			WHERE tp.user_id = $1 AND hg.host_id = $2
			  AND tp.revoked_at IS NULL AND tp.expires_at > now()
		)
		-- an explicit per-user denial overrides every source above
		AND NOT EXISTS (
			SELECT 1 FROM host_access_denials WHERE user_id = $1 AND host_id = $2
		)`, userID, hostID).Scan(&ok)
	return ok, err
}

// DenyHostAccess records a per-user denial for a host, overriding all access
// sources. Idempotent.
func (s *Store) DenyHostAccess(ctx context.Context, userID, hostID uuid.UUID, by *uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO host_access_denials (user_id, host_id, created_by) VALUES ($1,$2,$3)
		 ON CONFLICT (user_id, host_id) DO NOTHING`, userID, hostID, by)
	return err
}

// AllowHostAccess removes a per-user denial, restoring whatever access the user
// would otherwise have.
func (s *Store) AllowHostAccess(ctx context.Context, userID, hostID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM host_access_denials WHERE user_id=$1 AND host_id=$2`, userID, hostID)
	return err
}

// UserHostAccess is one host a user can reach, with how (the source) and whether
// an admin has explicitly denied it. Used by the Users-page access editor.
type UserHostAccess struct {
	models.Host
	ViaDirect bool `json:"viaDirect"`
	ViaGroup  bool `json:"viaGroup"`
	ViaTemp   bool `json:"viaTemp"`
	Denied    bool `json:"denied"`
}

// ListUserHostAccess returns every host the user has access to through any source
// (ignoring denials for the listing), each annotated with its source(s) and
// whether it is currently denied, so an admin can review and toggle per host.
func (s *Store) ListUserHostAccess(ctx context.Context, userID uuid.UUID) ([]UserHostAccess, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT h.id, h.hostname, COALESCE(h.description,''), COALESCE(h.environment,''),
		       COALESCE(h.owner,''), COALESCE(h.address,''),
		       EXISTS (SELECT 1 FROM host_users hu WHERE hu.user_id=$1 AND hu.host_id=h.id) AS via_direct,
		       EXISTS (SELECT 1 FROM user_groups ug JOIN host_groups hg ON hg.group_id=ug.group_id
		               WHERE ug.user_id=$1 AND hg.host_id=h.id) AS via_group,
		       EXISTS (SELECT 1 FROM temporary_permissions tp LEFT JOIN host_groups hg ON hg.group_id=tp.group_id
		               WHERE tp.user_id=$1 AND (tp.host_id=h.id OR hg.host_id=h.id)
		                 AND tp.revoked_at IS NULL AND tp.expires_at>now()) AS via_temp,
		       EXISTS (SELECT 1 FROM host_access_denials d WHERE d.user_id=$1 AND d.host_id=h.id) AS denied
		FROM hosts h
		WHERE EXISTS (SELECT 1 FROM host_users hu WHERE hu.user_id=$1 AND hu.host_id=h.id)
		   OR EXISTS (SELECT 1 FROM user_groups ug JOIN host_groups hg ON hg.group_id=ug.group_id
		              WHERE ug.user_id=$1 AND hg.host_id=h.id)
		   OR EXISTS (SELECT 1 FROM temporary_permissions tp LEFT JOIN host_groups hg ON hg.group_id=tp.group_id
		              WHERE tp.user_id=$1 AND (tp.host_id=h.id OR hg.host_id=h.id)
		                AND tp.revoked_at IS NULL AND tp.expires_at>now())
		ORDER BY h.hostname`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserHostAccess{}
	for rows.Next() {
		var a UserHostAccess
		if err := rows.Scan(&a.ID, &a.Hostname, &a.Description, &a.Environment, &a.Owner, &a.Address,
			&a.ViaDirect, &a.ViaGroup, &a.ViaTemp, &a.Denied); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
