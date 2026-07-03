package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

const hostCols = `id, hostname, description, environment, owner,
	COALESCE(address,''), COALESCE(host(wg_address),''), ssh_port, ssh_user,
	tags, enrolled, created_at, updated_at`

func scanHost(row pgx.Row) (*models.Host, error) {
	var h models.Host
	err := row.Scan(&h.ID, &h.Hostname, &h.Description, &h.Environment, &h.Owner,
		&h.Address, &h.WGAddress, &h.SSHPort, &h.SSHUser, &h.Tags, &h.Enrolled,
		&h.CreatedAt, &h.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &h, nil
}

// HostInput carries create/update fields for a host.
type HostInput struct {
	Hostname    string
	Description string
	Environment string
	Owner       string
	Address     string
	WGAddress   string
	SSHPort     int
	SSHUser     string
	Tags        []string
}

// CreateHost inserts a host plus empty inventory/status rows.
func (s *Store) CreateHost(ctx context.Context, in HostInput) (*models.Host, error) {
	if in.SSHPort == 0 {
		in.SSHPort = 22
	}
	if in.SSHUser == "" {
		in.SSHUser = "fleet"
	}
	if in.Tags == nil {
		in.Tags = []string{}
	}
	var h *models.Host
	err := s.tx(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO hosts (hostname, description, environment, owner, address, wg_address, ssh_port, ssh_user, tags)
			VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,'')::inet,$7,$8,$9)
			RETURNING `+hostCols,
			in.Hostname, in.Description, in.Environment, in.Owner, in.Address, in.WGAddress,
			in.SSHPort, in.SSHUser, in.Tags)
		var err error
		h, err = scanHost(row)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO host_inventory (host_id) VALUES ($1) ON CONFLICT DO NOTHING`, h.ID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO host_status (host_id) VALUES ($1) ON CONFLICT DO NOTHING`, h.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return h, nil
}

// GetHost loads a host with inventory, status, and groups.
func (s *Store) GetHost(ctx context.Context, id uuid.UUID) (*models.Host, error) {
	h, err := scanHost(s.pool.QueryRow(ctx, `SELECT `+hostCols+` FROM hosts WHERE id=$1`, id))
	if err != nil {
		return nil, err
	}
	s.attachHostDetails(ctx, h)
	return h, nil
}

// HostnamesByIDs resolves a set of host IDs to their hostnames in one query,
// returning a map of only those that exist. Used to make the audit log readable.
func (s *Store) HostnamesByIDs(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	out := map[uuid.UUID]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT id, hostname FROM hosts WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}

func (s *Store) attachHostDetails(ctx context.Context, h *models.Host) {
	h.Groups, _ = s.scanStrings(ctx, `
		SELECT g.name FROM host_groups hg JOIN groups g ON g.id=hg.group_id
		WHERE hg.host_id=$1 ORDER BY g.name`, h.ID)
	var inv models.HostInventory
	if err := s.pool.QueryRow(ctx, `
		SELECT os_name, os_version, kernel_version, architecture, ssh_version, cpu_count, memory_mb, collected_at,
			updates_available, security_updates, updates_checked_at
		FROM host_inventory WHERE host_id=$1`, h.ID).
		Scan(&inv.OSName, &inv.OSVersion, &inv.KernelVersion, &inv.Architecture,
			&inv.SSHVersion, &inv.CPUCount, &inv.MemoryMB, &inv.CollectedAt,
			&inv.UpdatesAvailable, &inv.SecurityUpdates, &inv.UpdatesCheckedAt); err == nil {
		h.Inventory = &inv
	}
	var st models.HostStatus
	if err := s.pool.QueryRow(ctx, `
		SELECT status, ssh_ok, wg_ok, latency_ms, uptime_seconds, last_success_at, last_failure_at, last_error, checked_at
		FROM host_status WHERE host_id=$1`, h.ID).
		Scan(&st.Status, &st.SSHOK, &st.WGOK, &st.LatencyMS, &st.UptimeSeconds,
			&st.LastSuccessAt, &st.LastFailureAt, &st.LastError, &st.CheckedAt); err == nil {
		h.Status = &st
	}
	h.Metrics = s.loadMetrics(ctx, h.ID)
}

// ListHosts returns all hosts with details. Filtering/sorting is applied in the
// handler layer for flexibility; pagination is by limit/offset.
func (s *Store) ListHosts(ctx context.Context, limit, offset int) ([]models.Host, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+hostCols+` FROM hosts ORDER BY hostname LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hosts []models.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, *h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range hosts {
		s.attachHostDetails(ctx, &hosts[i])
	}
	return hosts, nil
}

// SearchHosts returns hosts whose hostname matches q (case-insensitive
// substring), ordered by hostname and capped at limit. Only identity fields
// (id, hostname, environment) are populated — enough for name pickers — so it
// skips the per-host detail/status fan-out that ListHosts does.
func (s *Store) SearchHosts(ctx context.Context, q string, limit int) ([]models.Host, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, hostname, environment FROM hosts
		 WHERE hostname ILIKE '%' || $1 || '%' ESCAPE '\'
		 ORDER BY hostname LIMIT $2`, likeEscape(q), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Host
	for rows.Next() {
		var h models.Host
		if err := rows.Scan(&h.ID, &h.Hostname, &h.Environment); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// AccessibleHostIDs returns the set of host IDs a user can already reach — via
// group, direct grant, or active temporary grant (all hosts for super admins).
// IDs only (no detail fan-out), so it's cheap enough to call on every keystroke
// when filtering pickers.
func (s *Store) AccessibleHostIDs(ctx context.Context, userID uuid.UUID, isSuperAdmin bool) (map[uuid.UUID]bool, error) {
	query := `SELECT id FROM hosts`
	args := []any{}
	if !isSuperAdmin {
		query = `
			SELECT hg.host_id FROM user_groups ug JOIN host_groups hg ON hg.group_id=ug.group_id WHERE ug.user_id=$1
			UNION SELECT host_id FROM host_users WHERE user_id=$1
			UNION SELECT host_id FROM temporary_permissions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now() AND host_id IS NOT NULL
			UNION SELECT hg.host_id FROM temporary_permissions tp JOIN host_groups hg ON hg.group_id=tp.group_id WHERE tp.user_id=$1 AND tp.revoked_at IS NULL AND tp.expires_at>now()`
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

// ListAccessibleHosts returns hosts a user may access (group or temp grant), or
// all hosts for super admins.
func (s *Store) ListAccessibleHosts(ctx context.Context, userID uuid.UUID, isSuperAdmin bool) ([]models.Host, error) {
	if isSuperAdmin {
		return s.ListHosts(ctx, 1000, 0)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+hostCols+` FROM hosts WHERE id IN (
			SELECT hg.host_id FROM user_groups ug JOIN host_groups hg ON hg.group_id=ug.group_id WHERE ug.user_id=$1
			UNION
			SELECT host_id FROM host_users WHERE user_id=$1
			UNION
			SELECT host_id FROM temporary_permissions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now() AND host_id IS NOT NULL
			UNION
			SELECT hg.host_id FROM temporary_permissions tp JOIN host_groups hg ON hg.group_id=tp.group_id
			  WHERE tp.user_id=$1 AND tp.revoked_at IS NULL AND tp.expires_at>now()
		) AND id NOT IN (
			SELECT host_id FROM host_access_denials WHERE user_id=$1
		) ORDER BY hostname`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hosts []models.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, *h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range hosts {
		s.attachHostDetails(ctx, &hosts[i])
	}
	return hosts, nil
}

// UpdateHost updates editable host fields.
func (s *Store) UpdateHost(ctx context.Context, id uuid.UUID, in HostInput) (*models.Host, error) {
	if in.Tags == nil {
		in.Tags = []string{}
	}
	row := s.pool.QueryRow(ctx, `
		UPDATE hosts SET hostname=$2, description=$3, environment=$4, owner=$5,
			address=NULLIF($6,''), wg_address=NULLIF($7,'')::inet, ssh_port=$8, ssh_user=$9,
			tags=$10, updated_at=now()
		WHERE id=$1 RETURNING `+hostCols,
		id, in.Hostname, in.Description, in.Environment, in.Owner, in.Address, in.WGAddress,
		in.SSHPort, in.SSHUser, in.Tags)
	return scanHost(row)
}

// DeleteHost removes a host.
func (s *Store) DeleteHost(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM hosts WHERE id=$1`, id)
	return err
}

// CountHostsByStatus returns counts grouped by status for dashboards/metrics.
func (s *Store) CountHostsByStatus(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT status, count(*) FROM host_status GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{"online": 0, "offline": 0, "unknown": 0}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// UpsertInventory updates collected facts for a host.
func (s *Store) UpsertInventory(ctx context.Context, hostID uuid.UUID, inv models.HostInventory) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO host_inventory (host_id, os_name, os_version, kernel_version, architecture, ssh_version, cpu_count, memory_mb,
			updates_available, security_updates, updates_checked_at, collected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, now())
		ON CONFLICT (host_id) DO UPDATE SET
			os_name=EXCLUDED.os_name, os_version=EXCLUDED.os_version, kernel_version=EXCLUDED.kernel_version,
			architecture=EXCLUDED.architecture, ssh_version=EXCLUDED.ssh_version, cpu_count=EXCLUDED.cpu_count,
			memory_mb=EXCLUDED.memory_mb,
			-- keep the last-known update counts when a check didn't return one
			updates_available=COALESCE(EXCLUDED.updates_available, host_inventory.updates_available),
			security_updates=COALESCE(EXCLUDED.security_updates, host_inventory.security_updates),
			updates_checked_at=COALESCE(EXCLUDED.updates_checked_at, host_inventory.updates_checked_at),
			collected_at=now()`,
		hostID, inv.OSName, inv.OSVersion, inv.KernelVersion, inv.Architecture, inv.SSHVersion, inv.CPUCount, inv.MemoryMB,
		inv.UpdatesAvailable, inv.SecurityUpdates, inv.UpdatesCheckedAt)
	return err
}

// UpdateStatus writes a fresh health-check result for a host.
func (s *Store) UpdateStatus(ctx context.Context, hostID uuid.UUID, st models.HostStatus) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO host_status (host_id, status, ssh_ok, wg_ok, latency_ms, uptime_seconds, last_success_at, last_failure_at, last_error, checked_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now())
		ON CONFLICT (host_id) DO UPDATE SET
			status=EXCLUDED.status, ssh_ok=EXCLUDED.ssh_ok, wg_ok=EXCLUDED.wg_ok, latency_ms=EXCLUDED.latency_ms,
			uptime_seconds=EXCLUDED.uptime_seconds,
			last_success_at=COALESCE(EXCLUDED.last_success_at, host_status.last_success_at),
			last_failure_at=COALESCE(EXCLUDED.last_failure_at, host_status.last_failure_at),
			last_error=EXCLUDED.last_error, checked_at=now()`,
		hostID, st.Status, st.SSHOK, st.WGOK, st.LatencyMS, st.UptimeSeconds,
		st.LastSuccessAt, st.LastFailureAt, st.LastError)
	return err
}

// SetHostEnrolled marks a host enrolled/unenrolled.
func (s *Store) SetHostEnrolled(ctx context.Context, hostID uuid.UUID, enrolled bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE hosts SET enrolled=$2, updated_at=now() WHERE id=$1`, hostID, enrolled)
	return err
}
