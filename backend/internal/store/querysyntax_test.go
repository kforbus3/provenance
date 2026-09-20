package store

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Every SQL statement in this package, put to a real PostgreSQL.
//
// This exists because a query shipped that could not run at all:
//
//	ERROR: subquery uses ungrouped column "c.value" from outer query
//
// It compiled. `go test ./...` passed. Nothing in this package's tests executes SQL,
// so the entire suite was green while TrackedImages returned an error on every call —
// the update checker received no images and the Updates page went quietly empty, which
// looks exactly like "nothing needs updating". It reached production.
//
// PREPARE is the check, not EXPLAIN: it parses, resolves every name, and type-checks
// the whole statement against the live schema without executing it or touching a row.
// That is enough to catch a bad column, a dropped table, a GROUP BY violation, and a
// type mismatch — the things that make a query invalid rather than slow.
//
// Gated on a database because it needs the real schema. The same convention as the
// Docker e2e test beside it: set PROV_TEST_DATABASE_URL to a Provenance database that
// has had migrations applied. `make test-db` does this against a throwaway container.
func TestEverySQLStatementParsesAgainstTheRealSchema(t *testing.T) {
	dsn := os.Getenv("PROV_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set PROV_TEST_DATABASE_URL to a migrated Provenance database (see `make test-db`)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	stmts := statementsInPackage(t)
	if len(stmts) < 20 {
		t.Fatalf("only found %d statements to check — the extraction is broken, and a "+
			"test that checks nothing is worse than no test", len(stmts))
	}
	t.Logf("checking %d statements", len(stmts))

	checked := 0
	for _, st := range stmts {
		sql := st.sql
		// Placeholders are typed by context; PREPARE needs no help for these, but a
		// statement built by string concatenation is not whole here and is skipped
		// rather than reported as broken.
		if strings.Contains(sql, "` + ") || strings.Contains(sql, "%s") {
			continue
		}
		checked++
		name := "s" + strings.ReplaceAll(st.where, ":", "_")
		if _, err := pool.Exec(ctx, "PREPARE "+sanitise(name)+" AS "+sql); err != nil {
			t.Errorf("%s: this statement cannot run against the schema:\n%v\n\n%s",
				st.where, err, sql)
			continue
		}
		_, _ = pool.Exec(ctx, "DEALLOCATE "+sanitise(name))
	}
	if checked == 0 {
		t.Fatal("no statements were actually checked")
	}
	t.Logf("%d statements prepared successfully", checked)
}

type statement struct {
	where string
	sql   string
}

var sqlLiteral = regexp.MustCompile("(?s)`\\s*(SELECT|INSERT|UPDATE|DELETE|WITH)\\s.*?`")

// directQueryArg matches the tail of a Query/QueryRow/Exec call up to its SQL argument.
var directQueryArg = regexp.MustCompile(`(?s)(Query|QueryRow|Exec)\s*\([^()]*,\s*$`)

// statementsInPackage pulls every backtick SQL literal out of the package's source.
func statementsInPackage(t *testing.T) []statement {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var out []statement
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			continue
		}
		body := string(src)
		for i, loc := range sqlLiteral.FindAllStringIndex(body, -1) {
			// A literal joined to something else with + is only PART of a statement —
			// `... RETURNING ` + cols — and preparing the fragment would report a
			// syntax error that is this test's fault, not the code's. Whether it is a
			// fragment is visible right after the closing backtick, and nowhere else.
			rest := strings.TrimLeft(body[loc[1]:], " \t\n\r")
			if strings.HasPrefix(rest, "+") {
				continue
			}
			// Only literals handed STRAIGHT to a query call are whole statements.
			//
			// A package constant is often a base that call sites extend --
			// serviceAccountSelect carries no GROUP BY because each caller appends its
			// own -- and preparing that fragment reports an error that belongs to this
			// test, not to the code. Those compose at run time out of pieces this
			// cannot see, so they are honestly out of reach here rather than quietly
			// counted as checked.
			from := loc[0] - 80
			if from < 0 {
				from = 0
			}
			if !directQueryArg.MatchString(body[from:loc[0]]) {
				continue
			}
			sql := strings.TrimSpace(strings.Trim(body[loc[0]:loc[1]], "`"))
			out = append(out, statement{
				where: fmt.Sprintf("%s:%d", e.Name(), i),
				sql:   sql,
			})
		}
	}
	return out
}

func sanitise(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
