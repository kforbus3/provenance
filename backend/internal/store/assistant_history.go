package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/Moorgate/backend/internal/models"
)

// accessibleHostsSubquery returns a SQL predicate (appending the user id arg)
// limiting `col` to hosts the user can reach. Empty string for super admins.
func accessibleHostsSubquery(col string, userID uuid.UUID, isSuperAdmin bool, args *[]any) string {
	if isSuperAdmin {
		return ""
	}
	*args = append(*args, userID)
	n := len(*args)
	return fmt.Sprintf(` AND %s IN (
		SELECT hg.host_id FROM user_groups ug JOIN host_groups hg ON hg.group_id=ug.group_id WHERE ug.user_id=$%[2]d
		UNION SELECT host_id FROM host_users WHERE user_id=$%[2]d
		UNION SELECT host_id FROM temporary_permissions WHERE user_id=$%[2]d AND revoked_at IS NULL AND expires_at>now() AND host_id IS NOT NULL
		UNION SELECT hg.host_id FROM temporary_permissions tp JOIN host_groups hg ON hg.group_id=tp.group_id WHERE tp.user_id=$%[2]d AND tp.revoked_at IS NULL AND tp.expires_at>now())`, col, n)
}

// RecentScansForAssistant returns recent security scans (scoped to hosts the
// user can reach), optionally limited to one hostname.
func (s *Store) RecentScansForAssistant(ctx context.Context, userID uuid.UUID, isSuperAdmin bool, hostname string, limit int) ([]models.AssistantScanRow, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	args := []any{}
	where := "WHERE 1=1"
	if hostname != "" {
		args = append(args, hostname)
		where += fmt.Sprintf(" AND h.hostname = $%d", len(args))
	}
	where += accessibleHostsSubquery("sc.host_id", userID, isSuperAdmin, &args)
	args = append(args, limit)
	sql := `SELECT h.hostname, COALESCE(NULLIF(sc.profile_title,''), sc.profile), sc.status, sc.score,
			sc.pass_count, sc.fail_count, sc.requester, sc.scheduled, sc.finished_at, sc.created_at
		FROM host_scans sc JOIN hosts h ON h.id = sc.host_id ` + where +
		` ORDER BY sc.created_at DESC LIMIT $` + fmt.Sprint(len(args))
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AssistantScanRow{}
	for rows.Next() {
		var r models.AssistantScanRow
		if err := rows.Scan(&r.Hostname, &r.Profile, &r.Status, &r.Score,
			&r.PassCount, &r.FailCount, &r.Requester, &r.Scheduled, &r.FinishedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LatestComplianceScansForAssistant returns each accessible host's CURRENT
// compliance posture: its most recent OpenSCAP scan, or a NeverScanned row when
// the host has none.
//
// This is deliberately not RecentScansForAssistant with a limit. That returns the
// newest N scans fleet-wide, so on a fleet with a nightly schedule the newest 50
// rows can be a handful of hosts scanned repeatedly — "the latest result for each
// host" cannot be answered from it, and a host that is silently missing looks
// identical to a host that is fine. Rolling up per host, and keeping the hosts with
// no scan at all, makes both cases visible. Worst-first (failed rules descending)
// so the actionable hosts lead.
func (s *Store) LatestComplianceScansForAssistant(ctx context.Context, userID uuid.UUID, isSuperAdmin bool) ([]models.AssistantComplianceRow, error) {
	args := []any{}
	sub := accessibleHostsSubquery("h.id", userID, isSuperAdmin, &args)
	// DISTINCT ON picks the newest scan per host; the LEFT JOIN keeps hosts that have
	// never been scanned. Scans still pending/running are included so "the scan is
	// stuck" is answerable rather than looking like no scan at all.
	sql := `SELECT h.hostname, sc.id, COALESCE(NULLIF(sc.profile_title,''), sc.profile, ''),
			COALESCE(sc.benchmark,''), COALESCE(sc.status,''), sc.score,
			COALESCE(sc.pass_count,0), COALESCE(sc.fail_count,0), COALESCE(sc.other_count,0),
			COALESCE(sc.total_rules,0), COALESCE(sc.error,''), COALESCE(sc.scheduled,false),
			sc.finished_at, sc.created_at
		FROM hosts h
		LEFT JOIN LATERAL (
			SELECT * FROM host_scans s2 WHERE s2.host_id = h.id
			ORDER BY s2.created_at DESC LIMIT 1
		) sc ON true
		WHERE 1=1` + sub + `
		ORDER BY sc.fail_count DESC NULLS LAST, sc.score ASC NULLS FIRST, h.hostname`
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AssistantComplianceRow{}
	for rows.Next() {
		var r models.AssistantComplianceRow
		var id *uuid.UUID
		if err := rows.Scan(&r.Hostname, &id, &r.Profile, &r.Benchmark, &r.Status, &r.Score,
			&r.PassCount, &r.FailCount, &r.OtherCount, &r.TotalRules, &r.Error, &r.Scheduled,
			&r.FinishedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.ScanID = id
		r.NeverScanned = id == nil
		out = append(out, r)
	}
	return out, rows.Err()
}

// LatestScanIDForHost returns the id of a host's most recent COMPLETED compliance
// scan, for pulling its failed rules. Access-scoped like every assistant query.
func (s *Store) LatestScanIDForHost(ctx context.Context, userID uuid.UUID, isSuperAdmin bool, hostname string) (uuid.UUID, error) {
	args := []any{hostname}
	sub := accessibleHostsSubquery("sc.host_id", userID, isSuperAdmin, &args)
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT sc.id FROM host_scans sc JOIN hosts h ON h.id=sc.host_id
		WHERE h.hostname=$1 AND sc.status='completed'`+sub+`
		ORDER BY sc.created_at DESC LIMIT 1`, args...).Scan(&id)
	return id, err
}

// LatestVulnScansForAssistant returns the most recent completed vulnerability
// scan for every accessible host that has one — the fleet CVE roll-up, ordered
// worst-first. Mirrors LatestVulnScans but scoped to the caller's hosts.
func (s *Store) LatestVulnScansForAssistant(ctx context.Context, userID uuid.UUID, isSuperAdmin bool) ([]models.VulnScan, error) {
	args := []any{}
	sub := accessibleHostsSubquery("vs.host_id", userID, isSuperAdmin, &args)
	sql := `SELECT ` + vulnScanCols + `
		FROM vuln_scans vs JOIN hosts h ON h.id=vs.host_id
		WHERE vs.status='completed' AND vs.created_at = (
			SELECT max(v2.created_at) FROM vuln_scans v2 WHERE v2.host_id=vs.host_id AND v2.status='completed')` + sub +
		// Actionable first: max_cvss is 10.0 on essentially every Linux host (it is the
		// worst NVD score of any CVE touching any installed package), so it sorts nothing.
		` ORDER BY vs.fixable DESC, vs.critical DESC, vs.high DESC, h.hostname`
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.VulnScan{}
	for rows.Next() {
		v, err := scanVulnScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

// RecentSSHSessionsForAssistant returns past + active SSH sessions (scoped to
// hosts the user can reach), optionally filtered to one hostname/username and
// bounded to sessions that started after `since`.
func (s *Store) RecentSSHSessionsForAssistant(ctx context.Context, userID uuid.UUID, isSuperAdmin bool, hostname, username string, since time.Time, limit int) ([]models.AssistantSSHSessionRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args := []any{since}
	where := "WHERE ss.started_at >= $1"
	if hostname != "" {
		args = append(args, hostname)
		where += fmt.Sprintf(" AND ss.hostname = $%d", len(args))
	}
	if username != "" {
		args = append(args, username)
		where += fmt.Sprintf(" AND ss.username ILIKE '%%'||$%d||'%%'", len(args))
	}
	where += accessibleHostsSubquery("ss.host_id", userID, isSuperAdmin, &args)
	args = append(args, limit)
	sql := `SELECT COALESCE(ss.username,''), COALESCE(ss.hostname,''), COALESCE(host(ss.client_ip),''),
			ss.status, ss.started_at, ss.ended_at
		FROM ssh_sessions ss ` + where +
		` ORDER BY ss.started_at DESC LIMIT $` + fmt.Sprint(len(args))
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AssistantSSHSessionRow{}
	for rows.Next() {
		var r models.AssistantSSHSessionRow
		if err := rows.Scan(&r.Username, &r.Hostname, &r.ClientIP, &r.Status, &r.StartedAt, &r.EndedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecentAuditForAssistant returns recent audit events, newest first. The audit
// trail is not host-scoped; the caller gates access by the Audit.View
// permission (mirroring the audit page). Detail JSON is truncated so one noisy
// event cannot blow up the model context.
// AuditActionCountsForAssistant returns a count per action over the whole window (no row
// limit), so a "what changed" summary reflects every change in the period rather than only
// what fits in the display row cap — where high-volume routine rows (assistant queries,
// certificate issuance) would otherwise crowd real changes out. A zero `until` leaves the
// window open-ended; a non-zero one bounds it (calendar ranges like "yesterday").
func (s *Store) AuditActionCountsForAssistant(ctx context.Context, since, until time.Time) (map[string]int, error) {
	var up *time.Time
	if !until.IsZero() {
		up = &until
	}
	rows, err := s.pool.Query(ctx,
		`SELECT action, count(*) FROM audit_events
		 WHERE created_at >= $1 AND ($2::timestamptz IS NULL OR created_at < $2)
		 GROUP BY action`, since, up)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var action string
		var n int
		if err := rows.Scan(&action, &n); err != nil {
			return nil, err
		}
		out[action] = n
	}
	return out, rows.Err()
}

func (s *Store) RecentAuditForAssistant(ctx context.Context, actionContains, actorContains string, since time.Time, limit int) ([]models.AssistantAuditRow, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT created_at, COALESCE(actor_name,''), action, target_kind, target_id,
		       COALESCE(host(ip),''), left(detail::text, 300)
		FROM audit_events
		WHERE created_at >= $1
		  AND ($2='' OR action ILIKE '%'||$2||'%')
		  AND ($3='' OR actor_name ILIKE '%'||$3||'%')
		ORDER BY seq DESC LIMIT $4`,
		since, actionContains, actorContains, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AssistantAuditRow{}
	for rows.Next() {
		var r models.AssistantAuditRow
		if err := rows.Scan(&r.Time, &r.Actor, &r.Action, &r.TargetKind, &r.TargetID, &r.IP, &r.Detail); err != nil {
			return nil, err
		}
		if r.Detail == "{}" {
			r.Detail = ""
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecentSFTPTransfersForAssistant returns recent file transfers (scoped to
// hosts the user can reach), optionally filtered to one hostname.
func (s *Store) RecentSFTPTransfersForAssistant(ctx context.Context, userID uuid.UUID, isSuperAdmin bool, hostname string, since time.Time, limit int) ([]models.AssistantTransferRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args := []any{since}
	where := "WHERE t.created_at >= $1"
	if hostname != "" {
		args = append(args, hostname)
		where += fmt.Sprintf(" AND h.hostname = $%d", len(args))
	}
	where += accessibleHostsSubquery("t.host_id", userID, isSuperAdmin, &args)
	args = append(args, limit)
	sql := `SELECT COALESCE(u.username::text,''), COALESCE(h.hostname,''), t.direction,
			t.remote_path, t.size_bytes, t.status, t.created_at
		FROM sftp_transfers t
		LEFT JOIN hosts h ON h.id = t.host_id
		LEFT JOIN users u ON u.id = t.user_id ` + where +
		` ORDER BY t.created_at DESC LIMIT $` + fmt.Sprint(len(args))
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AssistantTransferRow{}
	for rows.Next() {
		var r models.AssistantTransferRow
		if err := rows.Scan(&r.Username, &r.Hostname, &r.Direction, &r.Path, &r.SizeBytes, &r.Status, &r.Time); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecentPlaybookRunsForAssistant returns recent playbook runs. Runs may target
// groups, so they are not host-scoped; the caller gates access by permission.
func (s *Store) RecentPlaybookRunsForAssistant(ctx context.Context, limit int) ([]models.AssistantPlaybookRunRow, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT p.name, pr.target_kind, pr.target_name, pr.host_count, pr.check_mode,
			pr.scheduled, pr.status, pr.requester, pr.finished_at, pr.created_at
		 FROM playbook_runs pr JOIN playbooks p ON p.id = pr.playbook_id
		 ORDER BY pr.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AssistantPlaybookRunRow{}
	for rows.Next() {
		var r models.AssistantPlaybookRunRow
		if err := rows.Scan(&r.Playbook, &r.TargetKind, &r.TargetName, &r.HostCount,
			&r.CheckMode, &r.Scheduled, &r.Status, &r.Requester, &r.FinishedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordAssistantFeedback stores an operator's thumbs up/down on an Ask answer, with the
// question/answer as shown and which tool produced it — the raw material for finding
// misrouted or unhelpful answers later.
func (s *Store) RecordAssistantFeedback(ctx context.Context, userID uuid.UUID, askID, question, answer, answeredBy string, helpful bool, comment string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO assistant_feedback (user_id, ask_id, question, answer, answered_by, helpful, comment)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		userID, askID, question, answer, answeredBy, helpful, comment)
	return err
}
