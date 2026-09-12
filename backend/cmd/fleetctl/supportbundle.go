package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/provenance/backend/internal/appsupport"
	"github.com/kforbus3/provenance/backend/internal/config"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// The same support bundle the web interface offers, produced from the command
// line.
//
// Which is the point: a bundle is wanted when something is wrong, and "something
// is wrong" sometimes means the interface will not load. A diagnostic tool that
// requires the thing being diagnosed to be healthy is not much of one.
//
// This path needs only the database and, if it is up, the updater. It does not
// need the backend at all.
type cliSource struct {
	pool    *pgxpool.Pool
	cfg     *config.Config
	st      *store.Store
	version string
}

func (c cliSource) Version() string { return c.version }

func (c cliSource) Instances(ctx context.Context) ([]appsupport.InstanceInfo, error) {
	rows, err := c.st.ListClusterInstances(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]appsupport.InstanceInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, appsupport.InstanceInfo{
			ID: r.ID.String(), Hostname: r.Hostname, Version: r.Version,
			LastSeen: r.LastHeartbeat, Leader: r.IsLeader,
		})
	}
	return out, nil
}

// Jobs are held in the running backend's memory, so a command-line bundle cannot
// see them. Reported as absent rather than omitted: a reader should be able to
// tell the difference between "no jobs have run" and "this bundle could not ask".
func (c cliSource) Jobs() []appsupport.JobInfo {
	return []appsupport.JobInfo{{
		Name:  "(not available from the command line — job history lives in the running backend)",
		Error: "",
	}}
}

func (c cliSource) Migrations(ctx context.Context) ([]string, error) {
	rows, err := c.pool.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (c cliSource) Settings() []appsupport.Setting {
	set := appsupport.Set
	return []appsupport.Setting{
		{Name: "environment", Value: c.cfg.Environment},
		{Name: "multi-tenancy", Value: fmt.Sprint(c.cfg.MultiTenancy)},
		{Name: "FIPS mode", Value: fmt.Sprint(c.cfg.FIPSMode)},
		{Name: "updater URL", Value: c.cfg.UpdaterURL},
		{Name: "updater token", Value: set(c.cfg.UpdaterToken)},
		{Name: "audit HMAC key", Value: set(string(c.cfg.AuditHMACKey))},
		{Name: "collected from", Value: "fleetctl"},
	}
}

func (c cliSource) Health(ctx context.Context) []appsupport.Check {
	out := []appsupport.Check{}
	add := func(name string, err error) {
		ck := appsupport.Check{Name: name, OK: err == nil}
		if err != nil {
			ck.Detail = err.Error()
		}
		out = append(out, ck)
	}
	add("database", c.pool.Ping(ctx))
	_, derr := c.Diagnostics(ctx)
	add("updater", derr)
	return out
}

func (c cliSource) FleetSummary(ctx context.Context) (appsupport.FleetSummary, error) {
	fs := appsupport.FleetSummary{ByStatus: map[string]int{}}
	rows, err := c.pool.Query(ctx, `SELECT COALESCE(status,'unknown'), count(*) FROM hosts GROUP BY 1`)
	if err != nil {
		return fs, err
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return fs, err
		}
		fs.ByStatus[st] = n
		fs.Hosts += n
	}
	_ = c.pool.QueryRow(ctx, `SELECT count(*) FROM container_stacks`).Scan(&fs.Stacks)
	_ = c.pool.QueryRow(ctx, `SELECT count(*) FROM container_update_rollouts WHERE state='running'`).Scan(&fs.OpenRollout)
	return fs, rows.Err()
}

// UpgradeStatus comes from the updater, which holds it on disk — so it survives
// the backend being down, which is when this path is used.
func (c cliSource) Hostnames(ctx context.Context) ([]string, error) {
	rows, err := c.pool.Query(ctx, `SELECT hostname FROM hosts WHERE COALESCE(hostname,'') <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (c cliSource) UpgradeStatus(ctx context.Context) (any, error) {
	d, err := c.Diagnostics(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"note": "from the updater", "containers": d.Containers}, nil
}

func (c cliSource) Diagnostics(ctx context.Context) (appsupport.Diagnostics, error) {
	return appsupport.FetchDiagnostics(ctx, &http.Client{Timeout: 3 * time.Minute},
		c.cfg.UpdaterURL, c.cfg.UpdaterToken, 2000)
}

// supportBundleCmd writes a bundle to a file.
func supportBundleCmd(ctx context.Context, pool *pgxpool.Pool, st *store.Store, cfg *config.Config, version, out string, anonymise bool) error {
	if out == "" {
		out = fmt.Sprintf("provenance-support-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	}
	// 0600: it holds this instance's logs and configuration until somebody
	// decides where to send it.
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	src := cliSource{pool: pool, cfg: cfg, st: st, version: version}
	if err := appsupport.New(src).Collect(ctx, f, "fleetctl",
		appsupport.Options{Anonymise: anonymise}); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", out)
	if anonymise {
		fmt.Println("Hostnames are masked and IP addresses replaced with consistent placeholders.")
	} else {
		fmt.Println("Hostnames and IP addresses are AS THEY ARE. Pass --anonymise to mask them.")
	}
	fmt.Println("See manifest.json inside the bundle for exactly what was collected and redacted.")
	return nil
}
