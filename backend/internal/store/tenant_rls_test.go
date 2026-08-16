package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/Moorgate/backend/internal/db"
)

// providerTenant is the seeded default tenant every pre-existing row backfills into
// (migration 0051). It is "tenant A" for these tests.
const providerTenant = "00000000-0000-0000-0000-000000000001"

// rlsTable describes how to seed and probe one tenant-scoped table generically. cols are
// the non-tenant NOT NULL columns (filled with a label string); tenant_id is appended.
type rlsTable struct {
	name string
	cols []string
}

func (r rlsTable) placeholders(n int) string {
	ph := make([]string, n)
	for i := range ph {
		ph[i] = fmt.Sprintf("$%d", i+1)
	}
	return strings.Join(ph, ",")
}

// seedFor inserts a row owned by tenant tid and returns its id. Run as the superuser
// (RLS bypassed) so we can plant rows in either tenant regardless of the GUC.
func (r rlsTable) seedFor(ctx context.Context, t *testing.T, q *pgxpool.Pool, label, tid string) uuid.UUID {
	t.Helper()
	args := make([]any, 0, len(r.cols)+1)
	for range r.cols {
		args = append(args, label)
	}
	args = append(args, tid)
	sql := fmt.Sprintf("INSERT INTO %s (%s, tenant_id) VALUES (%s) RETURNING id",
		r.name, strings.Join(r.cols, ","), r.placeholders(len(r.cols)+1))
	var id uuid.UUID
	if err := q.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
		t.Fatalf("%s: seed for tenant %s: %v", r.name, tid, err)
	}
	return id
}

// insertDefaultSQL inserts WITHOUT tenant_id (relying on the fleet_current_tenant()
// column default) — exactly how the store CRUD (CreateDatabase / CreateAccessPolicy /
// CreateK8sCluster) inserts. Returns the SQL + args for the given label.
func (r rlsTable) insertDefaultSQL(label string) (string, []any) {
	args := make([]any, 0, len(r.cols))
	for range r.cols {
		args = append(args, label)
	}
	sql := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) RETURNING id, tenant_id::text",
		r.name, strings.Join(r.cols, ","), r.placeholders(len(r.cols)))
	return sql, args
}

// insertForTenantSQL inserts WITH an explicit tenant_id (the cross-tenant write RLS must
// reject via WITH CHECK). Returns SQL + args.
func (r rlsTable) insertForTenantSQL(label, tid string) (string, []any) {
	args := make([]any, 0, len(r.cols)+1)
	for range r.cols {
		args = append(args, label)
	}
	args = append(args, tid)
	sql := fmt.Sprintf("INSERT INTO %s (%s, tenant_id) VALUES (%s)",
		r.name, strings.Join(r.cols, ","), r.placeholders(len(r.cols)+1))
	return sql, args
}

// TestTenantRLSIsolation proves the row-level-security added by migration 0074 (plus the
// pre-existing 0051 scoping of vault_secrets, which carries the "external secrets"
// material) actually isolates tenants: a NON-superuser app role scoped to tenant A can
// see A's rows and not B's, its inserts land in A, and it cannot write a row for tenant B
// (WITH CHECK denies it). An unscoped connection is denied entirely (fail closed).
//
// Gated on FLEET_RLS_TEST_DB (a DSN to a throwaway Postgres). The DSN normally connects
// as a superuser; the test drops into a freshly-created NOSUPERUSER/NOBYPASSRLS role via
// SET ROLE, because Postgres only enforces RLS (even FORCE'd) against a non-superuser,
// non-BYPASSRLS role — this is the same requirement db.verifyRLSCapableRole enforces at
// boot.
func TestTenantRLSIsolation(t *testing.T) {
	dsn := os.Getenv("FLEET_RLS_TEST_DB")
	if dsn == "" {
		t.Skip("set FLEET_RLS_TEST_DB to a throwaway Postgres DSN to run tenant-isolation tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	// Bring the schema (including migration 0074) up to date.
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// A non-superuser, NOBYPASSRLS role we can SET ROLE into so RLS is enforced.
	const role = "fleet_rls_tester"
	mustExec(ctx, t, pool, fmt.Sprintf(`DO $$ BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN
			CREATE ROLE %s NOSUPERUSER NOBYPASSRLS NOLOGIN;
		END IF;
	END $$;`, role, role))
	mustExec(ctx, t, pool, fmt.Sprintf(`GRANT USAGE ON SCHEMA public TO %s`, role))
	mustExec(ctx, t, pool, fmt.Sprintf(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %s`, role))
	mustExec(ctx, t, pool, fmt.Sprintf(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %s`, role))

	// Tenant A = provider (seeded by 0051). Tenant B = a fresh customer tenant.
	tenantA := providerTenant
	tenantB := uuid.NewString()
	mustExec(ctx, t, pool,
		`INSERT INTO tenants (id, name, slug, kind) VALUES ($1, 'RLS Test B', $2, 'customer')
		 ON CONFLICT (id) DO NOTHING`, tenantB, "rls-test-b-"+tenantB[:8])

	tables := []rlsTable{
		{name: "databases", cols: []string{"name", "address"}},
		{name: "access_policies", cols: []string{"name"}},
		{name: "k8s_clusters", cols: []string{"name", "api_server"}},
		// vault_secrets is scoped by 0051; it carries external-secret material
		// (external_provider/external_ref from 0058), so this stands in for the
		// "external_secrets" coverage the plan asks for.
		{name: "vault_secrets", cols: []string{"name"}},
	}
	// vuln_sboms is scoped by 0074 too, but only exists once migration 0071 has run
	// (this branch may predate it). Include it only if present + scoped.
	if hasTenantColumn(ctx, t, pool, "vuln_sboms") {
		tables = append(tables, rlsTable{name: "vuln_sboms", cols: sbomCols(ctx, t, pool)})
	}

	label := "rls-" + tenantB[:8]
	// Seed one row per tenant per table (as superuser; RLS bypassed).
	seededA := map[string]uuid.UUID{}
	seededB := map[string]uuid.UUID{}
	for _, tbl := range tables {
		seededA[tbl.name] = tbl.seedFor(ctx, t, pool, label+"-A", tenantA)
		seededB[tbl.name] = tbl.seedFor(ctx, t, pool, label+"-B", tenantB)
	}
	t.Cleanup(func() {
		// Best-effort: remove the rows we planted (superuser). Reset role first in case a
		// sub-test left the connection scoped.
		_, _ = pool.Exec(context.Background(), "RESET ROLE")
		for _, tbl := range tables {
			_, _ = pool.Exec(context.Background(),
				fmt.Sprintf("DELETE FROM %s WHERE id = ANY($1)", tbl.name),
				[]uuid.UUID{seededA[tbl.name], seededB[tbl.name]})
		}
	})

	// Pin one connection for the whole scoped-role phase: SET ROLE + set_config are
	// connection-local, so all probes must run on the same conn.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	setScope := func(t *testing.T, tid string) {
		t.Helper()
		if _, err := conn.Exec(ctx, "SET ROLE "+role); err != nil {
			t.Fatalf("SET ROLE: %v", err)
		}
		if _, err := conn.Exec(ctx, "SELECT set_config('app.tenant_id', $1, false)", tid); err != nil {
			t.Fatalf("set app.tenant_id=%q: %v", tid, err)
		}
	}
	resetScope := func() { _, _ = conn.Exec(ctx, "RESET ROLE") }

	rowVisible := func(t *testing.T, table string, id uuid.UUID) bool {
		t.Helper()
		var n int
		if err := conn.QueryRow(ctx,
			fmt.Sprintf("SELECT count(*) FROM %s WHERE id=$1", table), id).Scan(&n); err != nil {
			t.Fatalf("%s: visibility query: %v", table, err)
		}
		return n == 1
	}

	for _, tbl := range tables {
		t.Run(tbl.name, func(t *testing.T) {
			// --- Scoped to tenant A: sees A, not B. ---
			setScope(t, tenantA)
			defer resetScope()

			if !rowVisible(t, tbl.name, seededA[tbl.name]) {
				t.Errorf("%s: tenant A cannot see its OWN row %s", tbl.name, seededA[tbl.name])
			}
			if rowVisible(t, tbl.name, seededB[tbl.name]) {
				t.Errorf("%s: LEAK — tenant A can see tenant B's row %s", tbl.name, seededB[tbl.name])
			}

			// --- Cross-tenant write is denied by WITH CHECK. ---
			fSQL, fArgs := tbl.insertForTenantSQL(label+"-x", tenantB)
			if _, err := conn.Exec(ctx, fSQL, fArgs...); err == nil {
				t.Errorf("%s: tenant A was ALLOWED to INSERT a row owned by tenant B (WITH CHECK not enforced)", tbl.name)
			} else if !isRLSViolation(err) {
				t.Errorf("%s: cross-tenant insert failed with an unexpected error: %v", tbl.name, err)
			}

			// --- Default-tenant insert (no tenant_id, like the store CRUD) lands in A
			//     and is visible. ---
			dSQL, dArgs := tbl.insertDefaultSQL(label + "-own")
			var newID uuid.UUID
			var gotTenant string
			if err := conn.QueryRow(ctx, dSQL, dArgs...).Scan(&newID, &gotTenant); err != nil {
				t.Fatalf("%s: default-tenant insert (store CRUD path) was rejected under RLS: %v", tbl.name, err)
			}
			if gotTenant != tenantA {
				t.Errorf("%s: default insert landed in tenant %s, want A=%s", tbl.name, gotTenant, tenantA)
			}
			if !rowVisible(t, tbl.name, newID) {
				t.Errorf("%s: tenant A cannot see the row it just inserted", tbl.name)
			}
			resetScope()

			// --- Symmetry: scoped to tenant B, sees B, not A. ---
			setScope(t, tenantB)
			if !rowVisible(t, tbl.name, seededB[tbl.name]) {
				t.Errorf("%s: tenant B cannot see its OWN row", tbl.name)
			}
			if rowVisible(t, tbl.name, seededA[tbl.name]) {
				t.Errorf("%s: LEAK — tenant B can see tenant A's row", tbl.name)
			}
			resetScope()

			// --- Fail closed: an unscoped (empty GUC) connection sees nothing and cannot
			//     insert. ---
			if _, err := conn.Exec(ctx, "SET ROLE "+role); err != nil {
				t.Fatalf("SET ROLE: %v", err)
			}
			if _, err := conn.Exec(ctx, "SELECT set_config('app.tenant_id', '', false)"); err != nil {
				t.Fatalf("clear app.tenant_id: %v", err)
			}
			if rowVisible(t, tbl.name, seededA[tbl.name]) || rowVisible(t, tbl.name, seededB[tbl.name]) {
				t.Errorf("%s: an UNSCOPED connection can see tenant rows (should fail closed)", tbl.name)
			}
			dSQL2, dArgs2 := tbl.insertDefaultSQL(label + "-noscope")
			if _, err := conn.Exec(ctx, dSQL2, dArgs2...); err == nil {
				t.Errorf("%s: an UNSCOPED connection was allowed to insert (should fail closed)", tbl.name)
			}
			resetScope()
		})
	}
}

// mustExec runs an admin statement or fails the test.
func mustExec(ctx context.Context, t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// isRLSViolation reports whether err is a WITH CHECK / RLS policy rejection (SQLSTATE
// 42501 insufficient_privilege), as opposed to some other failure.
func isRLSViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "42501"
	}
	// Fall back to message matching if the concrete type isn't available.
	return strings.Contains(strings.ToLower(err.Error()), "row-level security") ||
		strings.Contains(strings.ToLower(err.Error()), "row level security")
}

// hasTenantColumn reports whether table exists AND already has a tenant_id column (i.e.
// migration 0074 scoped it in this schema).
func hasTenantColumn(ctx context.Context, t *testing.T, pool *pgxpool.Pool, table string) bool {
	t.Helper()
	var ok bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = $1 AND column_name = 'tenant_id'
		)`, table).Scan(&ok); err != nil {
		t.Fatalf("hasTenantColumn(%s): %v", table, err)
	}
	return ok
}

// sbomCols returns a minimal set of NOT NULL text columns (without defaults) for
// vuln_sboms so a seed insert satisfies its schema regardless of the exact 0071 shape.
func sbomCols(ctx context.Context, t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT column_name FROM information_schema.columns
		WHERE table_name = 'vuln_sboms'
		  AND is_nullable = 'NO'
		  AND column_default IS NULL
		  AND data_type IN ('text','character varying')
		ORDER BY ordinal_position`)
	if err != nil {
		t.Fatalf("sbomCols: %v", err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatalf("sbomCols scan: %v", err)
		}
		if c == "tenant_id" {
			continue
		}
		cols = append(cols, c)
	}
	return cols
}
