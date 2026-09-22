package store

import (
	"context"
	"github.com/jackc/pgx/v5"
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

// PruneAuditEventsBefore deletes audit-chain rows older than cutoff and DECLARES the
// boundary it left behind, so verification can tell a retention policy apart from a
// quiet deletion.
//
// This comment used to claim "the rows that remain still verify forward from the new
// oldest entry". They do not. Verification walks from prev="" and compares each row's
// prev_hash to the previous row's hash, so the first retained row still points at a
// hash that is no longer present — which reads as an UNLINKED break, the signature of
// rows being removed. Measured, not reasoned: pruning two of six rows reported
// intact=false at the first survivor. Anyone who enabled PROV_AUDIT_RETENTION got a
// chain that declared itself broken for ever.
//
// So the prune records where it stopped and which hash the new first row chains to,
// backed by an audit event the CALLER writes afterwards (see DeclareAuditPrune). An
// undeclared deletion still breaks the chain, because writing the boundary row alone
// is not enough: verification honours it only when its evidence event verifies, which
// needs the HMAC key.
//
// A genesis-to-now verification then covers only the retained window, which is the
// real cost of retention and why it is opt-in (0 keeps the whole chain).
func (s *Store) PruneAuditEventsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	var removed int64
	var throughSeq int64
	var boundary string
	err := s.tx(ctx, func(tx pgx.Tx) error {
		// The highest sequence about to go, and the hash the first survivor carries.
		err := tx.QueryRow(ctx, `
			SELECT COALESCE(MAX(seq), 0) FROM audit_events WHERE created_at < $1`, cutoff).Scan(&throughSeq)
		if err != nil {
			return err
		}
		if throughSeq == 0 {
			return nil // nothing to prune
		}
		// prev_hash of the first row that will remain. Taken BEFORE the delete, so a
		// concurrent append cannot change which row that is.
		err = tx.QueryRow(ctx, `
			SELECT prev_hash FROM audit_events WHERE seq > $1 ORDER BY seq LIMIT 1`, throughSeq).Scan(&boundary)
		if err == pgx.ErrNoRows {
			// Pruning everything: there is no survivor to anchor, so there is no
			// boundary to declare and the next append starts a fresh chain.
			boundary = ""
		} else if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM audit_events WHERE created_at < $1`, cutoff)
		if err != nil {
			return err
		}
		removed = tag.RowsAffected()
		if removed == 0 || boundary == "" {
			return nil
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO audit_chain_prunes (through_seq, boundary_hash, rows_removed, evidence_seq, cutoff)
			VALUES ($1,$2,$3,0,$4)`, throughSeq, boundary, removed, cutoff)
		return err
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

// DeclareAuditPrune attaches the chained audit event that makes the most recent prune
// boundary trustworthy.
//
// Written after the delete so the event survives into the retained chain, and kept
// separate from the delete itself because the event has to chain from the last
// SURVIVING row. Until it lands the boundary is unbacked and the chain still reports
// the break — which is the correct state: a prune nobody could evidence is
// indistinguishable from a deletion nobody declared.
func (s *Store) DeclareAuditPrune(ctx context.Context, evidenceSeq int64) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE audit_chain_prunes SET evidence_seq = $1
		WHERE id = (SELECT id FROM audit_chain_prunes ORDER BY id DESC LIMIT 1)
		  AND evidence_seq = 0`, evidenceSeq)
	return changed(tag, err)
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
		`DELETE FROM playbook_runs WHERE created_at < $1 AND status IN ('completed','failed','interrupted')`, cutoff)
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

// PruneExpiredCertificatesBefore deletes issued-cert metadata rows whose validity
// ended before cutoff. Keyed on expires_at (not issued_at) so an unexpired cert is
// never removed regardless of retention window. Safe against the revocation path:
// the KRL is built from cert_revocations (pruned separately once past the cert TTL),
// not from this table, so removing long-expired rows can't un-revoke anything.
// ssh_certificates has no FK dependents.
func (s *Store) PruneExpiredCertificatesBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM ssh_certificates WHERE expires_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PruneApprovalRequestsBefore deletes resolved access-request rows older than cutoff.
// Two guards keep it from destroying live state: pending requests are never removed
// (they may still be actionable), and a request with an active temporary_permission
// is never removed — temporary_permissions cascades from approval_requests, so deleting
// a request whose grant has not yet expired/been revoked would silently strip that
// user's access. Such requests become eligible on a later pass once the grant lapses.
func (s *Store) PruneApprovalRequestsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM approval_requests ar
		WHERE ar.created_at < $1
		  AND ar.status <> 'pending'
		  AND NOT EXISTS (
		      SELECT 1 FROM temporary_permissions tp
		      WHERE tp.request_id = ar.id
		        AND tp.revoked_at IS NULL
		        AND tp.expires_at > now()
		  )`,
		cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
