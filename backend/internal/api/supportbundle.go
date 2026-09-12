package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/kforbus3/provenance/backend/internal/appsupport"
	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// The application's own support bundle.
//
// internal/support collects one about a managed HOST. This collects one about
// Provenance, for when the application is what is misbehaving — so an operator
// does not have to know which container to exec into, which log to tail, or which
// table to query, to send somebody enough to work from.
//
// This type is the seam between the collector, which knows what a bundle should
// contain, and the server, which knows where each piece lives. Keeping them apart
// is what lets the collector be tested without a database, a Docker socket or a
// running updater — the three things most likely to be broken when a bundle is
// wanted.
type bundleSource struct{ s *Server }

func (b bundleSource) Version() string { return b.s.Version }

func (b bundleSource) Instances(ctx context.Context) ([]appsupport.InstanceInfo, error) {
	rows, err := b.s.Store.ListClusterInstances(ctx)
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

func (b bundleSource) Jobs() []appsupport.JobInfo {
	out := []appsupport.JobInfo{}
	for _, j := range b.s.Jobs.Snapshot() {
		info := appsupport.JobInfo{Name: j.Name}
		if j.LastRunAt != nil {
			info.LastRun = *j.LastRunAt
		}
		info.Error = j.LastError
		out = append(out, info)
	}
	return out
}

func (b bundleSource) Migrations(ctx context.Context) ([]string, error) {
	rows, err := b.s.Store.Pool().Query(ctx,
		`SELECT version FROM schema_migrations ORDER BY version`)
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

// Settings is an explicit allowlist. Deny by default: a new configuration value
// is absent from a bundle until somebody decides it is safe to include, which is
// the only arrangement that survives people adding settings.
func (b bundleSource) Settings() []appsupport.Setting {
	c := b.s.Cfg
	set := appsupport.Set
	return []appsupport.Setting{
		{Name: "environment", Value: c.Environment},
		{Name: "version", Value: b.s.Version},
		{Name: "multi-tenancy", Value: fmt.Sprint(c.MultiTenancy)},
		{Name: "FIPS mode", Value: fmt.Sprint(c.FIPSMode)},
		{Name: "monitor concurrency", Value: fmt.Sprint(c.MonitorConcurrency)},
		{Name: "updater URL", Value: c.UpdaterURL},
		{Name: "updater token", Value: set(c.UpdaterToken)},
		{Name: "audit HMAC key", Value: set(string(c.AuditHMACKey))},
		{Name: "ansible runner token", Value: set(c.AnsibleRunnerToken)},
		{Name: "release trust keys", Value: set(c.ReleaseTrustKeys)},
		{Name: "host-scoped principals only", Value: fmt.Sprint(c.HostScopedOnly)},
	}
}

func (b bundleSource) Health(ctx context.Context) []appsupport.Check {
	out := []appsupport.Check{}
	check := func(name string, err error) {
		c := appsupport.Check{Name: name, OK: err == nil}
		if err != nil {
			c.Detail = err.Error()
		}
		out = append(out, c)
	}
	check("database", b.s.Store.Pool().Ping(ctx))
	// The updater's own diagnostics endpoint doubles as its reachability check:
	// asking one question rather than two avoids a health line that disagrees
	// with the section below it.
	_, derr := b.Diagnostics(ctx)
	check("updater", derr)
	return out
}

func (b bundleSource) FleetSummary(ctx context.Context) (appsupport.FleetSummary, error) {
	var fs appsupport.FleetSummary
	fs.ByStatus = map[string]int{}
	rows, err := b.s.Store.Pool().Query(ctx,
		`SELECT COALESCE(status,'unknown'), count(*) FROM hosts GROUP BY 1`)
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
	_ = b.s.Store.Pool().QueryRow(ctx, `SELECT count(*) FROM container_stacks`).Scan(&fs.Stacks)
	_ = b.s.Store.Pool().QueryRow(ctx,
		`SELECT count(*) FROM container_update_rollouts WHERE state='running'`).Scan(&fs.OpenRollout)
	_ = b.s.Store.Pool().QueryRow(ctx, `
		SELECT COALESCE(sum(jsonb_array_length(COALESCE(containers,'[]'::jsonb))),0)
		FROM host_inventory`).Scan(&fs.Containers)
	return fs, rows.Err()
}

func (b bundleSource) UpgradeStatus(ctx context.Context) (any, error) {
	return b.s.upgradeSvc.Status(ctx), nil
}

func (b bundleSource) Diagnostics(ctx context.Context) (appsupport.Diagnostics, error) {
	return appsupport.FetchDiagnostics(ctx, &http.Client{Timeout: 3 * time.Minute},
		b.s.Cfg.UpdaterURL, b.s.Cfg.UpdaterToken, 2000)
}

// supportBundle streams the application's own bundle to the caller.
//
// System.Configure, not Host.View: this carries configuration, cluster identity
// and the application's logs. It is the same class of thing as the settings
// screen, and narrower than the host bundle only because there is one instance.
//
// Streamed, never stored. A file on disk holding an instance's logs and
// configuration is a thing to protect for as long as it exists; a download is
// over when it is over.
func (s *Server) supportBundle(w http.ResponseWriter, r *http.Request) {
	by := ""
	if p := auth.MustPrincipal(r); p != nil {
		by = p.Username
	}
	// Detached from the request deadline: collecting logs from several containers
	// takes longer than the router's timeout, and half a bundle is not useful.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Minute)
	defer cancel()

	if p := auth.MustPrincipal(r); p != nil {
		_, _ = s.Store.AppendAudit(r.Context(), models.AuditEvent{
			ActorID: &p.UserID, ActorName: p.Username,
			Action: "system.support_bundle",
			// Recorded because a bundle leaves the instance carrying its
			// configuration and logs. Who generated one, and when, is exactly the
			// kind of thing an audit log exists to answer afterwards.
			Detail: map[string]any{"version": s.Version},
		})
	}

	name := fmt.Sprintf("provenance-support-%s-%s.tar.gz",
		s.Version, time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	// No Content-Length: the bundle is built as it streams, and guessing a length
	// would mean buffering the whole thing to be able to say it.
	if err := appsupport.New(bundleSource{s}).Collect(ctx, w, by); err != nil {
		// The body has already started; the only honest signal left is to stop.
		s.Log.Error("support bundle", "err", err)
	}
}
