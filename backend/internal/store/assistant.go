package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

// HostQuery is the validated, structured filter the AI assistant builds from a
// natural-language question. All fields are optional; nil/empty means "no
// constraint". Results are always scoped to hosts the user may access.
type HostQuery struct {
	Status           string // online|offline|unknown
	Environment      string
	OSContains       string
	HostnameContains string
	DiskFreePctMax   *float64
	DiskFreePctMin   *float64
	MemUsedPctMin    *float64
	LoadPerCoreMin   *float64
	Limit            int

	UserID       uuid.UUID
	IsSuperAdmin bool
}

// buildHostQueryWhere builds the parameterized WHERE clause + args for a
// HostQuery. Pure (no DB) so it can be unit-tested. Column aliases: h (hosts),
// s (host_status), m (host_metrics), i (host_inventory).
func buildHostQueryWhere(q HostQuery) (string, []any) {
	var conds []string
	var args []any
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if q.Status != "" {
		add("COALESCE(s.status,'unknown')=$%d", q.Status)
	}
	if q.Environment != "" {
		add("h.environment=$%d", q.Environment)
	}
	if q.OSContains != "" {
		add("i.os_name ILIKE '%%'||$%d||'%%'", q.OSContains)
	}
	if q.HostnameContains != "" {
		add("h.hostname ILIKE '%%'||$%d||'%%'", q.HostnameContains)
	}
	if q.DiskFreePctMax != nil {
		add("m.min_disk_free_pct <= $%d", *q.DiskFreePctMax)
	}
	if q.DiskFreePctMin != nil {
		add("m.min_disk_free_pct >= $%d", *q.DiskFreePctMin)
	}
	if q.MemUsedPctMin != nil {
		add("m.mem_used_pct >= $%d", *q.MemUsedPctMin)
	}
	if q.LoadPerCoreMin != nil {
		add("m.load_per_core >= $%d", *q.LoadPerCoreMin)
	}
	// Authorization: non-super-admins only see hosts they can reach.
	if !q.IsSuperAdmin {
		args = append(args, q.UserID)
		conds = append(conds, fmt.Sprintf(`h.id IN (
			SELECT hg.host_id FROM user_groups ug JOIN host_groups hg ON hg.group_id=ug.group_id WHERE ug.user_id=$%[1]d
			UNION SELECT host_id FROM host_users WHERE user_id=$%[1]d
			UNION SELECT host_id FROM temporary_permissions WHERE user_id=$%[1]d AND revoked_at IS NULL AND expires_at>now() AND host_id IS NOT NULL
			UNION SELECT hg.host_id FROM temporary_permissions tp JOIN host_groups hg ON hg.group_id=tp.group_id WHERE tp.user_id=$%[1]d AND tp.revoked_at IS NULL AND tp.expires_at>now())`, len(args)))
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// QueryHostsForAssistant runs a HostQuery and returns compact rows. Single query
// (no per-host fan-out). Limit is clamped to [1,200].
func (s *Store) QueryHostsForAssistant(ctx context.Context, q HostQuery) ([]models.AssistantHostRow, error) {
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 200
	}
	where, args := buildHostQueryWhere(q)
	args = append(args, q.Limit)
	sql := `
		SELECT h.hostname, h.environment, COALESCE(s.status,'unknown'),
			COALESCE(m.primary_ip,''), COALESCE(i.os_name,''),
			m.min_disk_free_pct, m.mem_used_pct, m.load_per_core
		FROM hosts h
		LEFT JOIN host_status s ON s.host_id=h.id
		LEFT JOIN host_metrics m ON m.host_id=h.id
		LEFT JOIN host_inventory i ON i.host_id=h.id
		` + where + `
		ORDER BY h.hostname LIMIT $` + fmt.Sprint(len(args))
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AssistantHostRow{}
	for rows.Next() {
		var r models.AssistantHostRow
		if err := rows.Scan(&r.Hostname, &r.Environment, &r.Status, &r.PrimaryIP, &r.OSName,
			&r.MinDiskFreePct, &r.MemUsedPct, &r.LoadPerCore); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
