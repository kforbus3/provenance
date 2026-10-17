package db

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 0118 purges the indexed commands that recording deletion and retention left behind
// (session_commands cascaded from ssh_sessions, never from session_recordings).
//
// It has to reach EVERY tenant's rows. session_commands has FORCE ROW LEVEL SECURITY,
// so on a connection that is not a superuser and not in bypass, a plain DELETE skips
// other tenants' rows without an error. This runs the migration body the way that
// connection would -- as a non-superuser role scoped to one customer tenant -- and
// checks that orphans in both tenants go and a command whose recording still exists
// stays. The control case runs the same body without its set_config line and must
// leave the other tenant's orphan behind, or this test could not tell the difference.
func TestPurgeMigrationRemovesOrphanedCommandsInEveryTenant(t *testing.T) {
	url := os.Getenv("PROV_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("no test database offered; run via `make test-db`")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("migrations/0118_purge_orphaned_session_commands.sql")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	const bypass = "SELECT set_config('app.tenant_id', 'bypass', true);"
	if !strings.Contains(body, bypass) {
		t.Fatal("0118 no longer sets the RLS bypass; update this test with it")
	}

	const provider = "00000000-0000-0000-0000-000000000001"
	const customer = "00000000-0000-0000-0000-0000000000c1"
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`DO $$ BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'purge_probe') THEN
			CREATE ROLE purge_probe NOSUPERUSER NOBYPASSRLS;
		END IF; END $$`)
	exec(`GRANT SELECT, DELETE ON session_commands, session_recordings TO purge_probe`)

	// seed returns (orphan in provider, orphan in customer, recorded command in provider).
	seed := func() [3]string {
		exec(`DELETE FROM session_commands`)
		var ids [3]string
		for i, tenant := range []string{provider, customer, provider} {
			var sess string
			if err := pool.QueryRow(ctx,
				`INSERT INTO ssh_sessions (tenant_id) VALUES ($1) RETURNING id`, tenant).Scan(&sess); err != nil {
				t.Fatal(err)
			}
			if i == 2 {
				exec(`INSERT INTO session_recordings (ssh_session_id, format, path, tenant_id)
				      VALUES ($1, 'asciicast-v2', 'kept.cast', $2)`, sess, tenant)
			}
			exec(`INSERT INTO session_commands (ssh_session_id, ts, command_text, tenant_id)
			      VALUES ($1, now(), 'sudo su', $2)`, sess, tenant)
			ids[i] = sess
		}
		return ids
	}
	runAsScopedRole := func(sql string) {
		t.Helper()
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE purge_probe`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, provider); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, sql)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	left := func(sess string) bool {
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM session_commands WHERE ssh_session_id = $1`, sess).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}

	// Control: without the bypass, RLS hides the customer's orphan from the DELETE.
	ids := seed()
	runAsScopedRole(strings.Replace(body, bypass, "", 1))
	if !left(ids[1]) {
		t.Fatal("control: the customer orphan was deleted without the bypass, so RLS is not in effect and this test proves nothing")
	}

	ids = seed()
	runAsScopedRole(body)
	if left(ids[0]) {
		t.Error("an orphaned command in the provider tenant survived the purge")
	}
	if left(ids[1]) {
		t.Error("an orphaned command in another tenant survived the purge")
	}
	if !left(ids[2]) {
		t.Error("the purge deleted a command whose recording still exists")
	}
}
