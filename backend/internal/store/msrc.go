package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fleet-terminal/backend/internal/models"
)

// UpsertMSRC stores KB→CVE mappings, replacing any existing row for the same
// (kb, cve). Chunked to keep statement size and parameter counts bounded.
func (s *Store) UpsertMSRC(ctx context.Context, rows []models.MSRCEntry) error {
	const chunk = 500
	for start := 0; start < len(rows); start += chunk {
		end := start + chunk
		if end > len(rows) {
			end = len(rows)
		}
		batch := rows[start:end]
		var sb strings.Builder
		sb.WriteString(`INSERT INTO msrc_updates (kb, cve, severity, cvss, vector, title, release, imported_at) VALUES `)
		args := make([]any, 0, len(batch)*7)
		for i, r := range batch {
			if i > 0 {
				sb.WriteString(",")
			}
			n := i * 7
			fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d, now())", n+1, n+2, n+3, n+4, n+5, n+6, n+7)
			args = append(args, r.KB, r.CVE, r.Severity, r.CVSS, r.Vector, r.Title, r.Release)
		}
		sb.WriteString(` ON CONFLICT (kb, cve) DO UPDATE SET severity=EXCLUDED.severity, cvss=EXCLUDED.cvss,
			vector=EXCLUDED.vector, title=EXCLUDED.title, release=EXCLUDED.release, imported_at=now()`)
		if _, err := s.pool.Exec(ctx, sb.String(), args...); err != nil {
			return err
		}
	}
	return nil
}

// MSRCByKBs returns the CVE entries for each of the given KB numbers (digits only).
func (s *Store) MSRCByKBs(ctx context.Context, kbs []string) (map[string][]models.MSRCEntry, error) {
	out := map[string][]models.MSRCEntry{}
	if len(kbs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT kb, cve, severity, cvss, vector, title, release FROM msrc_updates WHERE kb = ANY($1)`, kbs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e models.MSRCEntry
		if err := rows.Scan(&e.KB, &e.CVE, &e.Severity, &e.CVSS, &e.Vector, &e.Title, &e.Release); err != nil {
			return nil, err
		}
		out[e.KB] = append(out[e.KB], e)
	}
	return out, rows.Err()
}

// MSRCStatus summarizes the loaded MSRC data for the settings/scan UI.
type MSRCStatus struct {
	Count         int        `json:"count"`
	Releases      int        `json:"releases"`
	LatestRelease string     `json:"latestRelease,omitempty"`
	ImportedAt    *time.Time `json:"importedAt,omitempty"`
}

func (s *Store) MSRCStatus(ctx context.Context) (MSRCStatus, error) {
	var st MSRCStatus
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*), count(DISTINCT release), max(imported_at) FROM msrc_updates`).
		Scan(&st.Count, &st.Releases, &st.ImportedAt); err != nil {
		return st, err
	}
	// Most-recently-imported release (release ids don't sort lexically by date).
	_ = s.pool.QueryRow(ctx,
		`SELECT release FROM msrc_updates ORDER BY imported_at DESC NULLS LAST LIMIT 1`).Scan(&st.LatestRelease)
	return st, nil
}
