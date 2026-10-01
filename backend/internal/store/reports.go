package store

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"time"
)

// ReportTable is a pre-formatted tabular export: fixed column headers and rows of
// string cells, ready to stream as CSV. Building it in the store keeps timestamp
// and type formatting in one place and the handler a generic CSV writer.
type ReportTable struct {
	Columns []string
	Rows    [][]string
}

// CSVBytes renders the table as a CSV document (header row + rows).
func (t *ReportTable) CSVBytes() []byte {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write(t.Columns)
	_ = w.WriteAll(t.Rows)
	w.Flush()
	return b.Bytes()
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }
func rfcPtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return rfc(*t)
}

// ExportSSHSessions returns the access report: every SSH session started in
// [from, to), org-wide, for compliance evidence (who connected to what, when,
// from where, and how it ended).
func (s *Store) ExportSSHSessions(ctx context.Context, from, to time.Time) (*ReportTable, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(username::text,''), COALESCE(hostname,''), COALESCE(host(client_ip),''),
		       status, started_at, ended_at, COALESCE(exit_code::text,''), bytes_in, bytes_out
		FROM ssh_sessions
		WHERE started_at >= $1 AND started_at < $2
		ORDER BY started_at`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	t := &ReportTable{Columns: []string{
		"user", "host", "client_ip", "status", "started_at", "ended_at", "exit_code", "bytes_in", "bytes_out"}}
	for rows.Next() {
		var user, host, ip, status, exit string
		var started time.Time
		var ended *time.Time
		var bin, bout int64
		if err := rows.Scan(&user, &host, &ip, &status, &started, &ended, &exit, &bin, &bout); err != nil {
			return nil, err
		}
		t.Rows = append(t.Rows, []string{user, host, ip, status, rfc(started), rfcPtr(ended), exit,
			fmt.Sprint(bin), fmt.Sprint(bout)})
	}
	return t, rows.Err()
}

// ExportAuditEvents returns audit-trail events in [from, to), newest first, with
// the full (untruncated) detail JSON for evidence.
func (s *Store) ExportAuditEvents(ctx context.Context, from, to time.Time) (*ReportTable, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT created_at, COALESCE(actor_name::text,''), action, target_kind, target_id,
		       COALESCE(host(ip),''), detail::text
		FROM audit_events
		WHERE created_at >= $1 AND created_at < $2
		ORDER BY seq DESC`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	t := &ReportTable{Columns: []string{"time", "actor", "action", "target_kind", "target_id", "ip", "detail"}}
	for rows.Next() {
		var at time.Time
		var actor, action, tk, tid, ip, detail string
		if err := rows.Scan(&at, &actor, &action, &tk, &tid, &ip, &detail); err != nil {
			return nil, err
		}
		if detail == "{}" {
			detail = ""
		}
		t.Rows = append(t.Rows, []string{rfc(at), actor, action, tk, tid, ip, detail})
	}
	return t, rows.Err()
}

// ExportCertificates returns SSH certificates issued in [from, to): the CA's
// issuance record for user and host certificates, with revocation state.
func (s *Store) ExportCertificates(ctx context.Context, from, to time.Time) (*ReportTable, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.serial, c.kind, COALESCE(u.username::text,''), COALESCE(h.hostname,''),
		       c.key_id, array_to_string(c.principals, ';'),
		       c.issued_at, c.expires_at, c.revoked_at, c.revoke_reason
		FROM ssh_certificates c
		LEFT JOIN users u ON u.id = c.user_id
		LEFT JOIN hosts h ON h.id = c.host_id
		WHERE c.issued_at >= $1 AND c.issued_at < $2
		ORDER BY c.issued_at DESC`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	t := &ReportTable{Columns: []string{
		"serial", "kind", "user", "host", "key_id", "principals",
		"issued_at", "expires_at", "revoked_at", "revoke_reason"}}
	for rows.Next() {
		var serial int64
		var kind, user, host, keyID, principals, reason string
		var issued, expires time.Time
		var revoked *time.Time
		if err := rows.Scan(&serial, &kind, &user, &host, &keyID, &principals,
			&issued, &expires, &revoked, &reason); err != nil {
			return nil, err
		}
		t.Rows = append(t.Rows, []string{fmt.Sprint(serial), kind, user, host, keyID, principals,
			rfc(issued), rfc(expires), rfcPtr(revoked), reason})
	}
	return t, rows.Err()
}

// ExportVulnScanFindings returns the vulnerability report: every CVE finding from
// vulnerability scans created in [from, to), one row per host+CVE+package, highest
// CVSS first.
func (s *Store) ExportVulnScanFindings(ctx context.Context, from, to time.Time) (*ReportTable, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT h.hostname, vs.created_at, f.cve, f.package, f.installed_version, f.fixed_version,
		       f.severity, f.cvss_score
		FROM vuln_findings f
		JOIN vuln_scans vs ON vs.id = f.scan_id
		JOIN hosts h ON h.id = vs.host_id
		WHERE vs.created_at >= $1 AND vs.created_at < $2 AND vs.status='completed'
		ORDER BY f.cvss_score DESC, h.hostname, f.cve`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	t := &ReportTable{Columns: []string{
		"host", "scanned_at", "cve", "package", "installed_version", "fixed_version", "severity", "cvss"}}
	for rows.Next() {
		var host, cve, pkg, installed, fixed, severity string
		var scanned time.Time
		var cvss float64
		if err := rows.Scan(&host, &scanned, &cve, &pkg, &installed, &fixed, &severity, &cvss); err != nil {
			return nil, err
		}
		t.Rows = append(t.Rows, []string{host, rfc(scanned), cve, pkg, installed, fixed, severity,
			fmt.Sprintf("%.1f", cvss)})
	}
	return t, rows.Err()
}

// ExportNetScanFindings returns the network-exposure report: every finding from
// network scans created in [from, to), one row per address, path and finding, worst
// first. Unreachable scans are included as rows of their own -- an address nobody
// could assess must appear in an audit export, not vanish from it.
func (s *Store) ExportNetScanFindings(ctx context.Context, from, to time.Time) (*ReportTable, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(h.hostname,''), ns.target, ns.path, ns.status, ns.created_at,
		       COALESCE(f.template_id,''), COALESCE(f.name,''), COALESCE(f.severity,''),
		       COALESCE(f.port,0), COALESCE(f.proto,''), COALESCE(array_to_string(f.cves, ' '),''),
		       COALESCE(f.cvss_score,0), CASE WHEN ns.status='unreachable' THEN ns.reason ELSE '' END
		FROM net_scans ns
		LEFT JOIN hosts h ON h.id = ns.host_id
		LEFT JOIN net_findings f ON f.scan_id = ns.id
		WHERE ns.created_at >= $1 AND ns.created_at < $2 AND ns.status IN ('completed','unreachable')
		  AND (f.id IS NOT NULL OR ns.status='unreachable')
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
		         WHEN 'low' THEN 3 ELSE 4 END, COALESCE(h.hostname, ns.target), ns.path, f.port`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	t := &ReportTable{Columns: []string{
		"host", "address", "path", "status", "scanned_at", "check", "finding", "severity", "port", "proto",
		"cves", "cvss", "not_assessed_reason"}}
	for rows.Next() {
		var host, target, path, status, tid, name, sev, proto, cves, reason string
		var scanned time.Time
		var port int
		var cvss float64
		if err := rows.Scan(&host, &target, &path, &status, &scanned, &tid, &name, &sev, &port, &proto,
			&cves, &cvss, &reason); err != nil {
			return nil, err
		}
		portS := ""
		if port > 0 {
			portS = fmt.Sprint(port)
		}
		t.Rows = append(t.Rows, []string{host, target, path, status, rfc(scanned), tid, name, sev, portS, proto,
			cves, fmt.Sprintf("%.1f", cvss), reason})
	}
	return t, rows.Err()
}

// ExportScans returns the security-posture report: scans created in [from, to)
// with their profile, score, and pass/fail counts.
func (s *Store) ExportScans(ctx context.Context, from, to time.Time) (*ReportTable, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT h.hostname, COALESCE(NULLIF(sc.profile_title,''), sc.profile), sc.status,
		       COALESCE(sc.score::text,''), sc.pass_count, sc.fail_count, sc.other_count,
		       sc.requester, sc.scheduled, sc.created_at, sc.finished_at
		FROM host_scans sc JOIN hosts h ON h.id = sc.host_id
		WHERE sc.created_at >= $1 AND sc.created_at < $2
		ORDER BY sc.created_at DESC`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	t := &ReportTable{Columns: []string{
		"host", "profile", "status", "score", "pass", "fail", "other",
		"requester", "scheduled", "created_at", "finished_at"}}
	for rows.Next() {
		var host, profile, status, score, requester string
		var pass, fail, other int
		var scheduled bool
		var created time.Time
		var finished *time.Time
		if err := rows.Scan(&host, &profile, &status, &score, &pass, &fail, &other,
			&requester, &scheduled, &created, &finished); err != nil {
			return nil, err
		}
		t.Rows = append(t.Rows, []string{host, profile, status, score,
			fmt.Sprint(pass), fmt.Sprint(fail), fmt.Sprint(other),
			requester, fmt.Sprint(scheduled), rfc(created), rfcPtr(finished)})
	}
	return t, rows.Err()
}
