package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

// VulnSummary is the per-severity breakdown recorded on a scan. Every count is of
// DISTINCT CVEs — a CVE affecting eight binary packages from one source package is
// one vulnerability, not eight.
type VulnSummary struct {
	Total, Critical, High, Medium, Low, Negligible, Unknown int
	Fixable                                                 int // a fixed version exists — actionable now
	WontFix                                                 int // assessed upstream as never-to-be-fixed
	MaxCVSS                                                 float64
}

// CreateVulnScan inserts a pending vulnerability scan and returns its id.
func (s *Store) CreateVulnScan(ctx context.Context, hostID uuid.UUID, requestedBy *uuid.UUID, requester string, scheduled bool) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx,
		`INSERT INTO vuln_scans (host_id, requested_by, requester, scheduled, status, instance_id)
		 VALUES ($1,$2,$3,$4,'pending',$5) RETURNING id`,
		hostID, requestedBy, requester, scheduled, s.ownerArg()).Scan(&id)
	return id, err
}

// StartVulnScan marks a scan running.
func (s *Store) StartVulnScan(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE vuln_scans SET status='running', started_at=now() WHERE id=$1`, id)
	return err
}

// FailVulnScan marks a scan failed with a reason.
func (s *Store) FailVulnScan(ctx context.Context, id uuid.UUID, reason string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE vuln_scans SET status='failed', error=$2, finished_at=now() WHERE id=$1`, id, reason)
	return err
}

// CompleteVulnScan records the summary and findings of a finished scan in one tx.
func (s *Store) CompleteVulnScan(ctx context.Context, id uuid.UUID, sum VulnSummary, findings []models.VulnFinding, dbBuilt *time.Time) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE vuln_scans SET status='completed', finished_at=now(), db_built_at=$2,
			  total=$3, critical=$4, high=$5, medium=$6, low=$7, negligible=$8, unknown=$9, max_cvss=$10,
			  fixable=$11, wont_fix=$12
			WHERE id=$1`,
			id, dbBuilt, sum.Total, sum.Critical, sum.High, sum.Medium, sum.Low, sum.Negligible, sum.Unknown, sum.MaxCVSS,
			sum.Fixable, sum.WontFix); err != nil {
			return err
		}
		for _, f := range findings {
			if _, err := tx.Exec(ctx, `
				INSERT INTO vuln_findings
				  (scan_id, cve, package, installed_version, fixed_version, fix_state, severity, cvss_score, cvss_vector, data_source, description)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
				id, f.CVE, f.Package, f.InstalledVersion, f.FixedVersion, models.FixStateOf(f), f.Severity, f.CVSSScore, f.CVSSVector, f.DataSource, f.Description); err != nil {
				return err
			}
		}
		return nil
	})
}

const vulnScanCols = `vs.id, vs.host_id, COALESCE(h.hostname,''), vs.requester, vs.scheduled, vs.status,
	vs.error, vs.db_built_at, vs.total, vs.critical, vs.high, vs.medium, vs.low, vs.negligible, vs.unknown,
	vs.fixable, vs.wont_fix, vs.max_cvss, vs.started_at, vs.finished_at, vs.created_at`

func scanVulnScan(row interface{ Scan(...any) error }) (*models.VulnScan, error) {
	var v models.VulnScan
	if err := row.Scan(&v.ID, &v.HostID, &v.Hostname, &v.Requester, &v.Scheduled, &v.Status,
		&v.Error, &v.DBBuiltAt, &v.Total, &v.Critical, &v.High, &v.Medium, &v.Low, &v.Negligible, &v.Unknown,
		&v.Fixable, &v.WontFix, &v.MaxCVSS, &v.StartedAt, &v.FinishedAt, &v.CreatedAt); err != nil {
		return nil, err
	}
	return &v, nil
}

// DeleteFailedVulnScans removes all failed scan records (error rows carry no
// findings), used to clear the "recent failures" surface. Returns the count removed.
func (s *Store) DeleteFailedVulnScans(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM vuln_scans WHERE status='failed'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ListVulnScans returns recent scans, optionally for one host, newest first.
func (s *Store) ListVulnScans(ctx context.Context, hostID *uuid.UUID, limit int) ([]models.VulnScan, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args := []any{}
	where := ""
	if hostID != nil {
		args = append(args, *hostID)
		where = " WHERE vs.host_id=$1"
	}
	args = append(args, limit)
	rows, err := s.pool.Query(ctx,
		`SELECT `+vulnScanCols+` FROM vuln_scans vs JOIN hosts h ON h.id=vs.host_id`+where+
			` ORDER BY vs.created_at DESC LIMIT $`+fmt.Sprint(len(args)), args...)
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

// GetVulnScan returns one scan.
func (s *Store) GetVulnScan(ctx context.Context, id uuid.UUID) (*models.VulnScan, error) {
	v, err := scanVulnScan(s.pool.QueryRow(ctx,
		`SELECT `+vulnScanCols+` FROM vuln_scans vs JOIN hosts h ON h.id=vs.host_id WHERE vs.id=$1`, id))
	if err != nil {
		return nil, mapNotFound(err)
	}
	return v, nil
}

// GetVulnFindings returns a scan's findings, highest CVSS first.
func (s *Store) GetVulnFindings(ctx context.Context, scanID uuid.UUID) ([]models.VulnFinding, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT cve, package, installed_version, fixed_version, fix_state, severity, cvss_score, cvss_vector, data_source, description
		FROM vuln_findings WHERE scan_id=$1 ORDER BY cvss_score DESC, cve`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.VulnFinding{}
	for rows.Next() {
		var f models.VulnFinding
		if err := rows.Scan(&f.CVE, &f.Package, &f.InstalledVersion, &f.FixedVersion, &f.FixState, &f.Severity,
			&f.CVSSScore, &f.CVSSVector, &f.DataSource, &f.Description); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// LatestVulnScans returns the most recent completed scan for every host that has
// one — the fleet vulnerability roll-up.
func (s *Store) LatestVulnScans(ctx context.Context) ([]models.VulnScan, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+vulnScanCols+`
		FROM vuln_scans vs JOIN hosts h ON h.id=vs.host_id
		WHERE vs.status='completed' AND vs.created_at = (
			SELECT max(v2.created_at) FROM vuln_scans v2 WHERE v2.host_id=vs.host_id AND v2.status='completed')
		-- Actionable first. max_cvss is 10.0 on essentially every Linux host (it is the
		-- worst NVD score of any CVE touching any installed package), so it sorts nothing.
		ORDER BY vs.fixable DESC, vs.critical DESC, vs.high DESC, h.hostname`)
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

// FailStaleVulnScans fails any scan left running across a restart.
func (s *Store) FailStaleVulnScans(ctx context.Context, lease time.Duration, self uuid.UUID) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE vuln_scans SET status='failed', error='interrupted (owning instance stopped)', finished_at=now()
		 WHERE status IN ('pending','running') AND `+deadOwnerPredicate("vuln_scans"), lease.String(), self)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// --- SBOM ---------------------------------------------------------------

// VulnSBOM is a stored bill of materials for one scan.
type VulnSBOM struct {
	ScanID     uuid.UUID `json:"scanId"`
	HostID     uuid.UUID `json:"hostId"`
	Hostname   string    `json:"hostname,omitempty"`
	PkgFormat  string    `json:"pkgFormat"`
	OSID       string    `json:"osId,omitempty"`
	OSVersion  string    `json:"osVersion,omitempty"`
	Components int       `json:"components"`
	CreatedAt  time.Time `json:"createdAt"`
	// Document is the raw CycloneDX JSON. Kept as bytes so it is served back
	// byte-for-byte: re-marshalling would reorder keys and change a document a
	// consumer may have hashed.
	Document []byte `json:"-"`
}

// SaveVulnSBOM stores (or replaces) the bill of materials for a scan.
func (s *Store) SaveVulnSBOM(ctx context.Context, scanID, hostID uuid.UUID,
	pkgFormat, osID, osVersion string, components int, doc []byte) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO vuln_sboms (scan_id, host_id, pkg_format, os_id, os_version, components, sbom)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (scan_id) DO UPDATE SET
    pkg_format = EXCLUDED.pkg_format,
    os_id      = EXCLUDED.os_id,
    os_version = EXCLUDED.os_version,
    components = EXCLUDED.components,
    sbom       = EXCLUDED.sbom,
    created_at = now()`,
		scanID, hostID, pkgFormat, osID, osVersion, components, doc)
	return err
}

// GetVulnSBOM returns the bill of materials for one scan.
func (s *Store) GetVulnSBOM(ctx context.Context, scanID uuid.UUID) (*VulnSBOM, error) {
	var b VulnSBOM
	err := s.pool.QueryRow(ctx, `
SELECT sb.scan_id, sb.host_id, COALESCE(h.hostname, ''), sb.pkg_format,
       sb.os_id, sb.os_version, sb.components, sb.created_at, sb.sbom
FROM vuln_sboms sb
LEFT JOIN hosts h ON h.id = sb.host_id
WHERE sb.scan_id = $1`, scanID).
		Scan(&b.ScanID, &b.HostID, &b.Hostname, &b.PkgFormat,
			&b.OSID, &b.OSVersion, &b.Components, &b.CreatedAt, &b.Document)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// LatestVulnSBOMForHost returns a host's most recent bill of materials.
//
// The common question is "what is on this machine now", which is host-scoped and
// time-ordered — asking for it by scan id would mean looking the scan up first.
func (s *Store) LatestVulnSBOMForHost(ctx context.Context, hostID uuid.UUID) (*VulnSBOM, error) {
	var b VulnSBOM
	err := s.pool.QueryRow(ctx, `
SELECT sb.scan_id, sb.host_id, COALESCE(h.hostname, ''), sb.pkg_format,
       sb.os_id, sb.os_version, sb.components, sb.created_at, sb.sbom
FROM vuln_sboms sb
LEFT JOIN hosts h ON h.id = sb.host_id
WHERE sb.host_id = $1
ORDER BY sb.created_at DESC
LIMIT 1`, hostID).
		Scan(&b.ScanID, &b.HostID, &b.Hostname, &b.PkgFormat,
			&b.OSID, &b.OSVersion, &b.Components, &b.CreatedAt, &b.Document)
	if err != nil {
		return nil, err
	}
	return &b, nil
}
