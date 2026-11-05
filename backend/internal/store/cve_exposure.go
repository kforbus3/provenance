package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CVEHostMatch is one package on one host whose latest completed vulnerability
// scan reported one of the requested IDs, either as the finding's own ID or as
// one of its aliases (a GHSA finding names its CVE only as an alias).
type CVEHostMatch struct {
	Hostname         string     `json:"hostname"`
	ID               string     `json:"id"`
	Package          string     `json:"package"`
	InstalledVersion string     `json:"installedVersion"`
	FixedVersion     string     `json:"fixedVersion,omitempty"`
	FixState         string     `json:"fixState,omitempty"`
	Severity         string     `json:"severity"`
	CVSSScore        float64    `json:"cvssScore"`
	ScannedAt        *time.Time `json:"scannedAt,omitempty"`
}

// CVEContainerMatch is a running container whose image's latest scan reported
// one of the requested IDs.
type CVEContainerMatch struct {
	Hostname         string    `json:"hostname"`
	Container        string    `json:"container"`
	Image            string    `json:"image"`
	ID               string    `json:"id"`
	Package          string    `json:"package"`
	InstalledVersion string    `json:"installedVersion"`
	FixedVersion     string    `json:"fixedVersion,omitempty"`
	Severity         string    `json:"severity"`
	CVSSScore        float64   `json:"cvssScore"`
	ScannedAt        time.Time `json:"scannedAt"`
}

// CVENetworkMatch is a network-scan finding (a check run against a listening
// service) that names one of the requested IDs.
type CVENetworkMatch struct {
	Hostname  string     `json:"hostname"`
	Path      string     `json:"path"`
	Port      int        `json:"port"`
	Proto     string     `json:"proto"`
	Name      string     `json:"name"`
	Severity  string     `json:"severity"`
	ScannedAt *time.Time `json:"scannedAt,omitempty"`
}

// CVEExposure answers "which hosts are vulnerable to CVE-X" across every place
// Provenance records CVEs, together with the coverage needed to say what the
// answer does NOT cover. A host with no completed scan is not a host without the
// CVE, and the answer has to be able to tell the two apart.
type CVEExposure struct {
	Hosts      []CVEHostMatch      `json:"hosts"`
	Containers []CVEContainerMatch `json:"containers"`
	Network    []CVENetworkMatch   `json:"network"`
	// AccessibleHosts is every host the caller can see; Scanned is how many of
	// them have a completed package scan; Unscanned names the rest.
	AccessibleHosts int        `json:"accessibleHosts"`
	Scanned         int        `json:"scanned"`
	Unscanned       []string   `json:"unscanned"`
	OldestScan      *time.Time `json:"oldestScan,omitempty"`
}

// CVEExposureForAssistant looks up the given vulnerability IDs (matched
// case-insensitively) in each accessible host's LATEST completed package scan, in the
// latest scan of every container image those hosts are running, and in their
// latest network scans. Older scans are deliberately ignored: a CVE patched since
// is not exposure.
func (s *Store) CVEExposureForAssistant(ctx context.Context, userID uuid.UUID, isSuperAdmin bool, ids []string) (*CVEExposure, error) {
	upper := make([]string, len(ids))
	for i, id := range ids {
		upper[i] = strings.ToUpper(strings.TrimSpace(id))
	}
	ids = upper
	out := &CVEExposure{Hosts: []CVEHostMatch{}, Containers: []CVEContainerMatch{}, Network: []CVENetworkMatch{}, Unscanned: []string{}}

	// Coverage: which accessible hosts have a completed package scan at all.
	args := []any{}
	sub := accessibleHostsSubquery("h.id", userID, isSuperAdmin, &args)
	rows, err := s.pool.Query(ctx, `
		SELECT h.hostname, vs.finished_at, vs.id IS NOT NULL
		FROM hosts h
		LEFT JOIN LATERAL (
			SELECT v2.id, v2.finished_at FROM vuln_scans v2
			WHERE v2.host_id = h.id AND v2.status = 'completed'
			ORDER BY v2.created_at DESC LIMIT 1
		) vs ON true
		WHERE 1=1`+sub+`
		ORDER BY h.hostname`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name string
		var finished *time.Time
		var scanned bool
		if err := rows.Scan(&name, &finished, &scanned); err != nil {
			rows.Close()
			return nil, err
		}
		out.AccessibleHosts++
		if !scanned {
			out.Unscanned = append(out.Unscanned, name)
			continue
		}
		out.Scanned++
		if finished != nil && (out.OldestScan == nil || finished.Before(*out.OldestScan)) {
			t := *finished
			out.OldestScan = &t
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Host packages: latest completed scan per host, matched on the finding's own
	// ID or any alias.
	args = []any{ids}
	sub = accessibleHostsSubquery("h.id", userID, isSuperAdmin, &args)
	rows, err = s.pool.Query(ctx, `
		SELECT h.hostname, f.cve, f.package, f.installed_version, f.fixed_version,
		       COALESCE(f.fix_state,''), f.severity, f.cvss_score, vs.finished_at
		FROM hosts h
		JOIN LATERAL (
			SELECT v2.id, v2.finished_at FROM vuln_scans v2
			WHERE v2.host_id = h.id AND v2.status = 'completed'
			ORDER BY v2.created_at DESC LIMIT 1
		) vs ON true
		JOIN vuln_findings f ON f.scan_id = vs.id
		WHERE (upper(f.cve) = ANY($1)
		       OR EXISTS (SELECT 1 FROM unnest(COALESCE(f.aliases, '{}')) a WHERE upper(a) = ANY($1)))`+sub+`
		ORDER BY h.hostname, f.cvss_score DESC, f.package`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var m CVEHostMatch
		if err := rows.Scan(&m.Hostname, &m.ID, &m.Package, &m.InstalledVersion, &m.FixedVersion,
			&m.FixState, &m.Severity, &m.CVSSScore, &m.ScannedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out.Hosts = append(out.Hosts, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Containers: every running container (by digest) on an accessible host whose
	// image scan lists the ID. Findings are JSONB, keyed as models.VulnFinding.
	args = []any{ids}
	sub = accessibleHostsSubquery("h.id", userID, isSuperAdmin, &args)
	rows, err = s.pool.Query(ctx, `
		SELECT DISTINCT h.hostname, COALESCE(c->>'name',''), COALESCE(NULLIF(c->>'image',''), cis.image),
		       COALESCE(f->>'cve',''), COALESCE(f->>'package',''), COALESCE(f->>'installedVersion',''),
		       COALESCE(f->>'fixedVersion',''), COALESCE(f->>'severity',''),
		       COALESCE((f->>'cvssScore')::double precision, 0), cis.scanned_at
		FROM hosts h
		JOIN host_inventory hi ON hi.host_id = h.id
		CROSS JOIN LATERAL jsonb_array_elements(COALESCE(hi.containers, '[]'::jsonb)) AS c
		JOIN container_image_scans cis ON cis.digest = c->>'digest'
		CROSS JOIN LATERAL jsonb_array_elements(COALESCE(cis.findings, '[]'::jsonb)) AS f
		WHERE (upper(f->>'cve') = ANY($1)
		       OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(
		                    CASE WHEN jsonb_typeof(f->'aliases') = 'array' THEN f->'aliases' ELSE '[]'::jsonb END) a
		                  WHERE upper(a) = ANY($1)))`+sub+`
		ORDER BY 1, 2, 5`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var m CVEContainerMatch
		if err := rows.Scan(&m.Hostname, &m.Container, &m.Image, &m.ID, &m.Package, &m.InstalledVersion,
			&m.FixedVersion, &m.Severity, &m.CVSSScore, &m.ScannedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out.Containers = append(out.Containers, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Network: the latest completed scan per (host, path).
	args = []any{ids}
	sub = accessibleHostsSubquery("ns.host_id", userID, isSuperAdmin, &args)
	rows, err = s.pool.Query(ctx, `
		SELECT DISTINCT h.hostname, ns.path, nf.port, nf.proto, nf.name, nf.severity, ns.finished_at
		FROM net_scans ns
		JOIN hosts h ON h.id = ns.host_id
		JOIN net_findings nf ON nf.scan_id = ns.id
		WHERE ns.id IN (
			SELECT DISTINCT ON (n2.host_id, n2.path) n2.id FROM net_scans n2
			WHERE n2.host_id IS NOT NULL AND n2.status = 'completed'
			ORDER BY n2.host_id, n2.path, n2.created_at DESC)
		  AND EXISTS (SELECT 1 FROM unnest(nf.cves) c WHERE upper(c) = ANY($1))`+sub+`
		ORDER BY 1, 2, 3`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var m CVENetworkMatch
		if err := rows.Scan(&m.Hostname, &m.Path, &m.Port, &m.Proto, &m.Name, &m.Severity, &m.ScannedAt); err != nil {
			return nil, err
		}
		out.Network = append(out.Network, m)
	}
	return out, rows.Err()
}
