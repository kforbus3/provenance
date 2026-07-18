package store

import (
	"context"
	"time"
)

// Retention helpers prune operational history so long-lived deployments don't
// grow without bound. Each is an independent, idempotent delete keyed on a time
// cutoff; the caller (retentionLoop) decides the window and whether pruning is
// enabled at all (0 = keep forever).

// PruneAuthEventsBefore deletes login-attempt records older than cutoff.
// auth_events has no dependents, so this is an unconditional delete.
func (s *Store) PruneAuthEventsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM auth_events WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PruneAuditEventsBefore deletes audit-chain rows older than cutoff. The rows
// that remain still verify forward from the new oldest entry, but a genesis-to-
// now verification then only covers the retained window — so this is gated by a
// separate, opt-in knob (audit retention 0 keeps the whole chain) and is never
// driven by the operational-activity window.
func (s *Store) PruneAuditEventsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM audit_events WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PruneSFTPTransfersBefore deletes file-transfer records older than cutoff.
func (s *Store) PruneSFTPTransfersBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sftp_transfers WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PrunePlaybookRunsBefore deletes finished playbook runs (and their per-host
// results, via ON DELETE CASCADE) older than cutoff. In-flight runs are left
// alone.
func (s *Store) PrunePlaybookRunsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM playbook_runs WHERE created_at < $1 AND status IN ('completed','failed')`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PruneScansBefore deletes finished scan rows (cascading their remediations)
// older than cutoff and returns the on-disk report/results file paths that the
// caller must remove — the DB delete alone would orphan them under ScanDir.
func (s *Store) PruneScansBefore(ctx context.Context, cutoff time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`DELETE FROM host_scans WHERE created_at < $1 AND status IN ('completed','failed')
		 RETURNING report_path, results_path`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var paths []string
	for rows.Next() {
		var report, results string
		if err := rows.Scan(&report, &results); err != nil {
			return nil, err
		}
		if report != "" {
			paths = append(paths, report)
		}
		if results != "" {
			paths = append(paths, results)
		}
	}
	return paths, rows.Err()
}

// PruneSSHSessionsBefore deletes ended SSH-session rows older than cutoff, but
// only those with no surviving recording: session_recordings cascades from
// ssh_sessions, so deleting a session whose recording is still within its own
// (independent, often longer) retention would destroy that recording early.
// Sessions whose recording has already been pruned become eligible on a later
// pass. Active sessions (ended_at IS NULL) are never touched.
func (s *Store) PruneSSHSessionsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM ssh_sessions
		WHERE ended_at IS NOT NULL AND ended_at < $1
		  AND id NOT IN (SELECT ssh_session_id FROM session_recordings WHERE ssh_session_id IS NOT NULL)`,
		cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
