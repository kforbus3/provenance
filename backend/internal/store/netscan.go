package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// NetScanResult is what a finished network scan records.
type NetScanResult struct {
	// Status is models.NetScanCompleted or models.NetScanUnreachable.
	Status           string
	Reason           string
	TemplatesVersion string
	OpenPorts        int
	// Listeners is the host's own view; nil means it was not collected, which is
	// stored as NULL and never as an empty list.
	Listeners   []models.NetListener
	Warnings    []string
	DurationSec float64
	Services    []models.NetService
	Findings    []models.NetFinding
}

// ErrNetScanGone is returned when a write to a scan matched no row: the scan was
// deleted (host removed, failures cleared) while it ran. Reporting success there
// would claim a result was stored when nothing was.
var ErrNetScanGone = errors.New("network scan record no longer exists")

// CreateNetScan inserts a pending network scan of one address.
func (s *Store) CreateNetScan(ctx context.Context, runID uuid.UUID, hostID, rangeID *uuid.UUID,
	target, path string, requestedBy *uuid.UUID, requester string, scheduled bool) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO net_scans (run_id, host_id, range_id, target, path, requested_by, requester, scheduled, status, instance_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9) RETURNING id`,
		runID, hostID, rangeID, target, path, requestedBy, requester, scheduled, s.ownerArg()).Scan(&id)
	return id, err
}

// StartNetScan marks a scan running.
func (s *Store) StartNetScan(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE net_scans SET status='running', started_at=now() WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNetScanGone
	}
	return nil
}

// FailNetScan marks a scan failed with a reason.
func (s *Store) FailNetScan(ctx context.Context, id uuid.UUID, reason string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE net_scans SET status='failed', error=$2, finished_at=now() WHERE id=$1`, id, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNetScanGone
	}
	return nil
}

func severityCounts(findings []models.NetFinding) (crit, high, med, low int) {
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			crit++
		case "high":
			high++
		case "medium":
			med++
		case "low":
			low++
		}
	}
	return
}

// CompleteNetScan records a finished scan, its services and findings, in one tx.
func (s *Store) CompleteNetScan(ctx context.Context, id uuid.UUID, r NetScanResult) error {
	if r.Status != models.NetScanCompleted && r.Status != models.NetScanUnreachable {
		return fmt.Errorf("invalid final status %q", r.Status)
	}
	var listeners any // NULL unless collected
	if r.Listeners != nil {
		b, err := json.Marshal(r.Listeners)
		if err != nil {
			return err
		}
		listeners = b
	}
	warnings := r.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	wb, _ := json.Marshal(warnings)
	unexpected := 0
	for _, sv := range r.Services {
		if sv.Unexpected {
			unexpected++
		}
	}
	crit, high, med, low := severityCounts(r.Findings)
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE net_scans SET status=$2, reason=$3, templates_version=$4, open_ports=$5,
			  total=$6, critical=$7, high=$8, medium=$9, low=$10, unexpected=$11,
			  listeners=$12, warnings=$13, duration_sec=$14, finished_at=now()
			WHERE id=$1`,
			id, r.Status, r.Reason, r.TemplatesVersion, r.OpenPorts,
			len(r.Findings), crit, high, med, low, unexpected,
			listeners, wb, r.DurationSec)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNetScanGone
		}
		for _, sv := range r.Services {
			det := sv.Detections
			if det == nil {
				det = []models.NetDetection{}
			}
			db, _ := json.Marshal(det)
			cpes := sv.CPEs
			if cpes == nil {
				cpes = []string{}
			}
			proto := sv.Proto
			if proto == "" {
				proto = "tcp"
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO net_services (scan_id, port, proto, service, product, version, tls, cpes, detections, process, unexpected)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
				ON CONFLICT (scan_id, proto, port) DO NOTHING`,
				id, sv.Port, proto, sv.Service, sv.Product, sv.Version, sv.TLS, cpes, db, sv.Process, sv.Unexpected); err != nil {
				return err
			}
		}
		for _, f := range r.Findings {
			refs, _ := json.Marshal(nonNil(f.References))
			ext, _ := json.Marshal(nonNil(f.Extracted))
			proto := f.Proto
			if proto == "" {
				proto = "tcp"
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO net_findings (scan_id, template_id, name, severity, port, proto, matched_at, cves, cwes,
				  cvss_score, cvss_vector, description, remediation, refs, extracted, tags)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
				id, f.TemplateID, f.Name, strings.ToLower(f.Severity), f.Port, proto, f.MatchedAt,
				nonNil(f.CVEs), nonNil(f.CWEs), f.CVSSScore, f.CVSSVector, f.Description, f.Remediation,
				refs, ext, nonNil(f.Tags)); err != nil {
				return err
			}
		}
		return nil
	})
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

const netScanCols = `ns.id, ns.run_id, ns.host_id, COALESCE(h.hostname,''), ns.range_id, COALESCE(r.name,''),
	ns.target, ns.path, ns.requester, ns.scheduled, ns.status, ns.error, ns.reason, ns.templates_version,
	ns.open_ports, ns.total, ns.critical, ns.high, ns.medium, ns.low, ns.unexpected, ns.listeners,
	ns.warnings, ns.duration_sec, ns.started_at, ns.finished_at, ns.created_at`

const netScanFrom = ` FROM net_scans ns LEFT JOIN hosts h ON h.id=ns.host_id LEFT JOIN net_scan_ranges r ON r.id=ns.range_id`

func scanNetScan(row interface{ Scan(...any) error }) (*models.NetScan, error) {
	var v models.NetScan
	var listeners, warnings []byte
	if err := row.Scan(&v.ID, &v.RunID, &v.HostID, &v.Hostname, &v.RangeID, &v.RangeName,
		&v.Target, &v.Path, &v.Requester, &v.Scheduled, &v.Status, &v.Error, &v.Reason, &v.TemplatesVersion,
		&v.OpenPorts, &v.Total, &v.Critical, &v.High, &v.Medium, &v.Low, &v.Unexpected, &listeners,
		&warnings, &v.DurationSec, &v.StartedAt, &v.FinishedAt, &v.CreatedAt); err != nil {
		return nil, err
	}
	if listeners != nil {
		v.ListenersKnown = true
		_ = json.Unmarshal(listeners, &v.Listeners)
	}
	_ = json.Unmarshal(warnings, &v.Warnings)
	return &v, nil
}

func collectNetScans(rows pgx.Rows) ([]models.NetScan, error) {
	defer rows.Close()
	out := []models.NetScan{}
	for rows.Next() {
		v, err := scanNetScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

// GetNetScan returns one scan with its services and findings.
func (s *Store) GetNetScan(ctx context.Context, id uuid.UUID) (*models.NetScan, error) {
	v, err := scanNetScan(s.pool.QueryRow(ctx, `SELECT `+netScanCols+netScanFrom+` WHERE ns.id=$1`, id))
	if err != nil {
		return nil, mapNotFound(err)
	}
	if err := s.fillNetScan(ctx, v); err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Store) fillNetScan(ctx context.Context, v *models.NetScan) error {
	svc, err := s.NetServices(ctx, v.ID)
	if err != nil {
		return err
	}
	v.Services = svc
	f, err := s.NetFindings(ctx, v.ID)
	if err != nil {
		return err
	}
	v.Findings = f
	return nil
}

// NetServices returns what answered on a scan's address, by port.
func (s *Store) NetServices(ctx context.Context, scanID uuid.UUID) ([]models.NetService, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT port, proto, service, product, version, tls, cpes, detections, process, unexpected
		FROM net_services WHERE scan_id=$1 ORDER BY proto, port`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.NetService{}
	for rows.Next() {
		var sv models.NetService
		var det []byte
		if err := rows.Scan(&sv.Port, &sv.Proto, &sv.Service, &sv.Product, &sv.Version, &sv.TLS,
			&sv.CPEs, &det, &sv.Process, &sv.Unexpected); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(det, &sv.Detections)
		out = append(out, sv)
	}
	return out, rows.Err()
}

// NetFindings returns a scan's findings, worst first.
func (s *Store) NetFindings(ctx context.Context, scanID uuid.UUID) ([]models.NetFinding, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, template_id, name, severity, port, proto, matched_at, cves, cwes, cvss_score, cvss_vector,
		       description, remediation, refs, extracted, tags
		FROM net_findings WHERE scan_id=$1
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
		         WHEN 'low' THEN 3 ELSE 4 END, cvss_score DESC, port, template_id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.NetFinding{}
	for rows.Next() {
		var f models.NetFinding
		var refs, ext []byte
		if err := rows.Scan(&f.ID, &f.TemplateID, &f.Name, &f.Severity, &f.Port, &f.Proto, &f.MatchedAt,
			&f.CVEs, &f.CWEs, &f.CVSSScore, &f.CVSSVector, &f.Description, &f.Remediation,
			&refs, &ext, &f.Tags); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(refs, &f.References)
		_ = json.Unmarshal(ext, &f.Extracted)
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListNetScans returns recent scans, newest first, optionally for one host or range.
func (s *Store) ListNetScans(ctx context.Context, hostID, rangeID *uuid.UUID, limit int) ([]models.NetScan, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var where []string
	args := []any{}
	if hostID != nil {
		args = append(args, *hostID)
		where = append(where, fmt.Sprintf("ns.host_id=$%d", len(args)))
	}
	if rangeID != nil {
		args = append(args, *rangeID)
		where = append(where, fmt.Sprintf("ns.range_id=$%d", len(args)))
	}
	q := `SELECT ` + netScanCols + netScanFrom
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY ns.created_at DESC LIMIT $%d", len(args))
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return collectNetScans(rows)
}

// LatestNetScans returns the fleet roll-up: each managed host's most recent finished
// host scan (completed or unreachable) on whichever path it was scanned -- overlay or
// LAN, so a host moved onto the overlay stops showing its old LAN scan -- plus the
// latest range scan of each address. A managed host is keyed by host, so a changed
// address does not leave its old one behind; anything else by the address itself.
func (s *Store) LatestNetScans(ctx context.Context) ([]models.NetScan, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+netScanCols+netScanFrom+`
		WHERE ns.id IN (
			SELECT DISTINCT ON (COALESCE(n2.host_id::text, n2.target), n2.path = 'range') n2.id
			FROM net_scans n2
			WHERE n2.status IN ('completed','unreachable')
			ORDER BY COALESCE(n2.host_id::text, n2.target), n2.path = 'range', n2.created_at DESC)
		ORDER BY ns.critical DESC, ns.high DESC, ns.medium DESC, ns.unexpected DESC,
		         COALESCE(h.hostname, ns.target), ns.path`)
	if err != nil {
		return nil, err
	}
	return collectNetScans(rows)
}

// LatestNetScansForHost returns a host's most recent finished host scan (overlay or
// LAN) and its most recent range scan, if any, with services and findings.
func (s *Store) LatestNetScansForHost(ctx context.Context, hostID uuid.UUID) ([]models.NetScan, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+netScanCols+netScanFrom+`
		WHERE ns.id IN (
			SELECT DISTINCT ON (n2.path = 'range') n2.id FROM net_scans n2
			WHERE n2.host_id=$1 AND n2.status IN ('completed','unreachable')
			ORDER BY n2.path = 'range', n2.created_at DESC)
		ORDER BY ns.path`, hostID)
	if err != nil {
		return nil, err
	}
	scans, err := collectNetScans(rows)
	if err != nil {
		return nil, err
	}
	for i := range scans {
		if err := s.fillNetScan(ctx, &scans[i]); err != nil {
			return nil, err
		}
	}
	return scans, nil
}

// PreviousNetPorts returns the ports that answered on the most recent completed scan
// of the same host-or-address and path before the given scan -- what "new service
// appeared" is measured against. ok is false when there is no earlier scan, so the
// first scan of anything does not announce every port as new.
func (s *Store) PreviousNetPorts(ctx context.Context, scanID uuid.UUID) (ports map[string]bool, ok bool, err error) {
	var prev uuid.UUID
	err = s.pool.QueryRow(ctx, `
		SELECT p.id FROM net_scans cur
		JOIN net_scans p ON COALESCE(p.host_id::text, p.target) = COALESCE(cur.host_id::text, cur.target)
		  AND p.path = cur.path AND p.status='completed' AND p.created_at < cur.created_at AND p.id <> cur.id
		WHERE cur.id=$1
		ORDER BY p.created_at DESC LIMIT 1`, scanID).Scan(&prev)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	rows, err := s.pool.Query(ctx, `SELECT proto, port FROM net_services WHERE scan_id=$1`, prev)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	ports = map[string]bool{}
	for rows.Next() {
		var proto string
		var port int
		if err := rows.Scan(&proto, &port); err != nil {
			return nil, false, err
		}
		ports[fmt.Sprintf("%s/%d", proto, port)] = true
	}
	return ports, true, rows.Err()
}

// ExposedService is one service in the fleet-wide exposure table.
type ExposedService struct {
	ScanID     uuid.UUID  `json:"scanId"`
	HostID     *uuid.UUID `json:"hostId,omitempty"`
	Hostname   string     `json:"hostname,omitempty"`
	Target     string     `json:"target"`
	Path       string     `json:"path"`
	ScannedAt  time.Time  `json:"scannedAt"`
	Port       int        `json:"port"`
	Proto      string     `json:"proto"`
	Service    string     `json:"service,omitempty"`
	Product    string     `json:"product,omitempty"`
	Version    string     `json:"version,omitempty"`
	TLS        bool       `json:"tls"`
	Process    string     `json:"process,omitempty"`
	Unexpected bool       `json:"unexpected"`
	// Findings on this port in the same scan, and the worst of their severities.
	Findings      int    `json:"findings"`
	WorstSeverity string `json:"worstSeverity,omitempty"`
}

// ExposedServices lists every service that answered on the latest scan of each host
// (or range address) -- the same scans the roll-up shows.
func (s *Store) ExposedServices(ctx context.Context) ([]ExposedService, error) {
	rows, err := s.pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (COALESCE(host_id::text, target), path = 'range') id
			-- The same "latest" as the roll-up: a host whose newest scan did not answer
			-- exposes nothing known now, rather than whatever an older scan saw.
			FROM net_scans WHERE status IN ('completed','unreachable')
			ORDER BY COALESCE(host_id::text, target), path = 'range', created_at DESC)
		SELECT ns.id, ns.host_id, COALESCE(h.hostname,''), ns.target, ns.path, ns.created_at,
		       sv.port, sv.proto, sv.service, sv.product, sv.version, sv.tls, sv.process, sv.unexpected,
		       (SELECT count(*) FROM net_findings f WHERE f.scan_id=ns.id AND f.port=sv.port AND f.proto=sv.proto),
		       COALESCE((SELECT f.severity FROM net_findings f WHERE f.scan_id=ns.id AND f.port=sv.port AND f.proto=sv.proto
		         ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
		                  WHEN 'low' THEN 3 ELSE 4 END LIMIT 1), '')
		FROM latest l
		JOIN net_scans ns ON ns.id=l.id
		JOIN net_services sv ON sv.scan_id=ns.id
		LEFT JOIN hosts h ON h.id=ns.host_id
		ORDER BY COALESCE(h.hostname, ns.target), ns.path, sv.proto, sv.port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExposedService{}
	for rows.Next() {
		var e ExposedService
		if err := rows.Scan(&e.ScanID, &e.HostID, &e.Hostname, &e.Target, &e.Path, &e.ScannedAt,
			&e.Port, &e.Proto, &e.Service, &e.Product, &e.Version, &e.TLS, &e.Process, &e.Unexpected,
			&e.Findings, &e.WorstSeverity); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeleteFailedNetScans removes failed scan records. Returns the count removed.
func (s *Store) DeleteFailedNetScans(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM net_scans WHERE status='failed'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// FailStaleNetScans fails any scan left pending or running across a restart.
func (s *Store) FailStaleNetScans(ctx context.Context, lease time.Duration, self uuid.UUID) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE net_scans SET status='failed', error='interrupted (owning instance stopped)', finished_at=now()
		 WHERE status IN ('pending','running') AND `+deadOwnerPredicate("net_scans"), lease.String(), self)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// --- ranges ------------------------------------------------------------------------

const netRangeCols = `r.id, r.name, host(r.cidr) || '/' || masklen(r.cidr), r.note, r.enabled, r.created_at,
	(SELECT max(ns.created_at) FROM net_scans ns WHERE ns.range_id=r.id),
	(SELECT count(*) FROM net_scans ns WHERE ns.range_id=r.id
	   AND ns.run_id = (SELECT n3.run_id FROM net_scans n3 WHERE n3.range_id=r.id ORDER BY n3.created_at DESC LIMIT 1))`

func scanNetRange(row interface{ Scan(...any) error }) (*models.NetScanRange, error) {
	var r models.NetScanRange
	if err := row.Scan(&r.ID, &r.Name, &r.CIDR, &r.Note, &r.Enabled, &r.CreatedAt, &r.LastScan, &r.LastLive); err != nil {
		return nil, err
	}
	return &r, nil
}

// ListNetScanRanges returns the operator-defined ranges.
func (s *Store) ListNetScanRanges(ctx context.Context) ([]models.NetScanRange, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+netRangeCols+` FROM net_scan_ranges r ORDER BY r.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.NetScanRange{}
	for rows.Next() {
		r, err := scanNetRange(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// GetNetScanRange returns one range.
func (s *Store) GetNetScanRange(ctx context.Context, id uuid.UUID) (*models.NetScanRange, error) {
	r, err := scanNetRange(s.pool.QueryRow(ctx, `SELECT `+netRangeCols+` FROM net_scan_ranges r WHERE r.id=$1`, id))
	if err != nil {
		return nil, mapNotFound(err)
	}
	return r, nil
}

// CreateNetScanRange stores a new range. cidr must already be validated.
func (s *Store) CreateNetScanRange(ctx context.Context, name, cidr, note string, enabled bool, by *uuid.UUID) (*models.NetScanRange, error) {
	var id uuid.UUID
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO net_scan_ranges (name, cidr, note, enabled, created_by) VALUES ($1,$2::cidr,$3,$4,$5) RETURNING id`,
		name, cidr, note, enabled, by).Scan(&id); err != nil {
		return nil, err
	}
	return s.GetNetScanRange(ctx, id)
}

// UpdateNetScanRange replaces a range's editable fields.
func (s *Store) UpdateNetScanRange(ctx context.Context, id uuid.UUID, name, cidr, note string, enabled bool) (*models.NetScanRange, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE net_scan_ranges SET name=$2, cidr=$3::cidr, note=$4, enabled=$5 WHERE id=$1`,
		id, name, cidr, note, enabled)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GetNetScanRange(ctx, id)
}

// DeleteNetScanRange removes a range. Its scans are kept, detached.
func (s *Store) DeleteNetScanRange(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM net_scan_ranges WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// HostIDsByAddress maps managed hosts' addresses (LAN and overlay) to their ids, so a
// range scan can attach what it finds to a host it already knows.
func (s *Store) HostIDsByAddress(ctx context.Context) (map[string]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, COALESCE(address,''), COALESCE(host(wg_address),'') FROM hosts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var a, w string
		if err := rows.Scan(&id, &a, &w); err != nil {
			return nil, err
		}
		for _, v := range []string{a, w} {
			if v != "" {
				out[v] = id
			}
		}
	}
	return out, rows.Err()
}

// LatestVulnCVEsForHost returns the CVEs on a host's most recent completed package
// (grype) scan. ok is false when the host has none, which is different from a scan
// that found nothing: a network finding cannot be called "banner-only" against a
// package scan that never ran.
func (s *Store) LatestVulnCVEsForHost(ctx context.Context, hostID uuid.UUID) (cves map[string]bool, ok bool, err error) {
	var scanID uuid.UUID
	err = s.pool.QueryRow(ctx, `
		SELECT id FROM vuln_scans WHERE host_id=$1 AND status='completed'
		ORDER BY created_at DESC LIMIT 1`, hostID).Scan(&scanID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT upper(cve) FROM vuln_findings WHERE scan_id=$1`, scanID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	cves = map[string]bool{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, false, err
		}
		cves[c] = true
	}
	return cves, true, rows.Err()
}

// LatestNetScansForAssistant is LatestNetScans scoped to the caller's hosts. Range
// scans of addresses no host claims are visible to super-admins only: there is no
// host whose access could grant them.
func (s *Store) LatestNetScansForAssistant(ctx context.Context, userID uuid.UUID, isSuperAdmin bool) ([]models.NetScan, error) {
	args := []any{}
	sub := accessibleHostsSubquery("ns.host_id", userID, isSuperAdmin, &args)
	rows, err := s.pool.Query(ctx, `
		SELECT `+netScanCols+netScanFrom+`
		WHERE ns.id IN (
			SELECT DISTINCT ON (COALESCE(n2.host_id::text, n2.target), n2.path = 'range') n2.id
			FROM net_scans n2
			WHERE n2.status IN ('completed','unreachable')
			ORDER BY COALESCE(n2.host_id::text, n2.target), n2.path = 'range', n2.created_at DESC)`+sub+`
		ORDER BY ns.critical DESC, ns.high DESC, ns.medium DESC, ns.unexpected DESC,
		         COALESCE(h.hostname, ns.target), ns.path`, args...)
	if err != nil {
		return nil, err
	}
	return collectNetScans(rows)
}
