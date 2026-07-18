// Package reports serves compliance evidence exports as CSV: access (SSH
// sessions), the audit trail, certificate issuance, and scan posture, each over a
// date range. Reports are org-wide (auditor evidence, not host-scoped) and gated
// by Audit.View.
package reports

import (
	"context"
	"encoding/csv"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/store"
)

// Mount attaches the report export routes, all gated by Audit.View.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("Audit.View"))
		pr.Get("/reports/access.csv", h.csv("access", func(ctx context.Context, from, to time.Time) (*store.ReportTable, error) {
			return h.d.Store.ExportSSHSessions(ctx, from, to)
		}))
		pr.Get("/reports/audit.csv", h.csv("audit", func(ctx context.Context, from, to time.Time) (*store.ReportTable, error) {
			return h.d.Store.ExportAuditEvents(ctx, from, to)
		}))
		pr.Get("/reports/certificates.csv", h.csv("certificates", func(ctx context.Context, from, to time.Time) (*store.ReportTable, error) {
			return h.d.Store.ExportCertificates(ctx, from, to)
		}))
		pr.Get("/reports/scans.csv", h.csv("scans", func(ctx context.Context, from, to time.Time) (*store.ReportTable, error) {
			return h.d.Store.ExportScans(ctx, from, to)
		}))
		pr.Get("/reports/vulnerabilities.csv", h.csv("vulnerabilities", func(ctx context.Context, from, to time.Time) (*store.ReportTable, error) {
			return h.d.Store.ExportVulnScanFindings(ctx, from, to)
		}))
	})
}

type handler struct{ d *app.Deps }

type queryFn func(ctx context.Context, from, to time.Time) (*store.ReportTable, error)

// csv builds an HTTP handler that runs one export over the requested window and
// streams it as a downloadable CSV file.
func (h *handler) csv(name string, fn queryFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		from, to := dateRange(r)
		table, err := fn(r.Context(), from, to)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not build report")
			return
		}
		filename := "fleet-" + name + "-" + from.Format("20060102") + "-" + to.Format("20060102") + ".csv"
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		cw := csv.NewWriter(w)
		_ = cw.Write(table.Columns)
		_ = cw.WriteAll(table.Rows) // WriteAll flushes
		if err := cw.Error(); err != nil {
			// Header/body already partially written; nothing better to do than log-less return.
			return
		}
	}
}

// dateRange parses ?from=&to= (YYYY-MM-DD or RFC3339), defaulting to the last 30
// days. `to` is treated as exclusive end-of-day when a bare date is given.
func dateRange(r *http.Request) (from, to time.Time) {
	now := time.Now().UTC()
	to = now
	from = now.AddDate(0, 0, -30)
	if v := r.URL.Query().Get("from"); v != "" {
		if t, ok := parseDate(v, false); ok {
			from = t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, ok := parseDate(v, true); ok {
			to = t
		}
	}
	return from, to
}

func parseDate(v string, endOfDay bool) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		if endOfDay {
			t = t.AddDate(0, 0, 1) // exclusive upper bound covering the whole day
		}
		return t.UTC(), true
	}
	return time.Time{}, false
}
