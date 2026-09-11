package store

import (
	"context"
	"time"
)

// EvidenceSummary is every number the evidence pack prints.
//
// Fourteen scalars. The pack used to obtain them by running the five CSV export
// queries and measuring the results in Go: `len(rows)`, `distinct(rows, 0)`,
// `countEqual(rows, 2, "completed")`, `sumInt(...)`. Correct, and it materialised
// five complete tables — every SSH session, every certificate, every scan, every
// vulnerability finding, and every audit event with its untruncated detail JSON —
// into memory at once, to print fourteen numbers.
//
// The date range comes from the caller and is not otherwise bounded, so an
// auditor asking for five years asked the server to hold five years. At ten
// million audit rows with a few hundred bytes of detail each, that is gigabytes
// of Go strings before the PDF buffer is touched, and the request cannot be shed
// because the HTTP server sets no write timeout.
//
// Postgres counts rows without sending them. These are the same numbers from the
// same tables with the same window and the same filters, so the pack still cannot
// disagree with the CSVs — that was the reason for reusing the export queries,
// and it is preserved by matching their WHERE clauses exactly.
type EvidenceSummary struct {
	Sessions        int
	SessionUsers    int
	SessionHosts    int
	CertsIssued     int
	CertsRevoked    int
	Scans           int
	ScansCompleted  int
	RulesPassed     int
	RulesFailed     int
	VulnFindings    int
	VulnCritical    int
	VulnHigh        int
	AuditEvents     int
	CommandsFlagged int
	CommandsBlocked int
}

// EvidenceSummaryFor computes the pack's figures for a window.
func (s *Store) EvidenceSummaryFor(ctx context.Context, from, to time.Time) (*EvidenceSummary, error) {
	var e EvidenceSummary

	// One round trip per table rather than one per row. Each mirrors the WHERE of
	// the export it replaces; a divergence here is a pack that contradicts its own
	// attachments, which is the failure this is written to avoid.
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*), count(DISTINCT username), count(DISTINCT hostname)
		  FROM ssh_sessions
		 WHERE started_at >= $1 AND started_at < $2`, from, to).
		Scan(&e.Sessions, &e.SessionUsers, &e.SessionHosts); err != nil {
		return nil, err
	}

	if err := s.pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE revoked_at IS NOT NULL)
		  FROM ssh_certificates
		 WHERE issued_at >= $1 AND issued_at < $2`, from, to).
		Scan(&e.CertsIssued, &e.CertsRevoked); err != nil {
		return nil, err
	}

	if err := s.pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE status='completed'),
		       COALESCE(sum(pass_count), 0), COALESCE(sum(fail_count), 0)
		  FROM host_scans
		 WHERE created_at >= $1 AND created_at < $2`, from, to).
		Scan(&e.Scans, &e.ScansCompleted, &e.RulesPassed, &e.RulesFailed); err != nil {
		return nil, err
	}

	// Severity is compared case-insensitively because the export's own counter
	// did: scanners disagree about capitalisation and the pack must not.
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE lower(f.severity) = 'critical'),
		       count(*) FILTER (WHERE lower(f.severity) = 'high')
		  FROM vuln_findings f
		  JOIN vuln_scans vs ON vs.id = f.scan_id
		 WHERE vs.created_at >= $1 AND vs.created_at < $2 AND vs.status='completed'`, from, to).
		Scan(&e.VulnFindings, &e.VulnCritical, &e.VulnHigh); err != nil {
		return nil, err
	}

	if err := s.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE action LIKE 'command.flagged%'),
		       count(*) FILTER (WHERE action LIKE 'command.blocked%')
		  FROM audit_events
		 WHERE created_at >= $1 AND created_at < $2`, from, to).
		Scan(&e.AuditEvents, &e.CommandsFlagged, &e.CommandsBlocked); err != nil {
		return nil, err
	}

	return &e, nil
}
