package db

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

var migNameRe = regexp.MustCompile(`^(\d{4})_[a-z0-9]+(_[a-z0-9]+)*\.sql$`)

// knownDupOrdinals are migration number prefixes that historically ship two files.
// They are harmless — the migrator applies each unique filename exactly once, in
// lexical order (see Migrate) — but the set must NOT grow. Renumbering an
// already-applied migration would change its schema_migrations key, so every
// existing database would re-run it (and orphan the old record); a new migration
// must instead take a fresh, unused ordinal. This test enforces that without forcing
// a risky renumber of the historical collisions.
var knownDupOrdinals = map[string]int{"0010": 2, "0011": 2, "0049": 2, "0050": 2}

// TestMigrationsNamingAndOrdinals guards the migration set: every file follows the
// NNNN_snake_case.sql convention, no two files collapse to the same schema_migrations
// key, and no NEW ordinal collision is introduced beyond the grandfathered set.
func TestMigrationsNamingAndOrdinals(t *testing.T) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}

	versions := map[string]bool{}
	ordinals := map[string][]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		m := migNameRe.FindStringSubmatch(name)
		if m == nil {
			t.Errorf("migration %q does not match the NNNN_snake_case.sql convention", name)
			continue
		}
		version := strings.TrimSuffix(name, ".sql")
		if versions[version] {
			t.Errorf("duplicate migration version %q: two files map to one schema_migrations key", version)
		}
		versions[version] = true
		ordinals[m[1]] = append(ordinals[m[1]], name)
	}

	for ord, files := range ordinals {
		if len(files) > 1 && knownDupOrdinals[ord] == 0 {
			t.Errorf("new migration ordinal collision on %s: %v\n"+
				"use the next unused ordinal — never renumber an applied migration, it changes "+
				"its schema_migrations key and re-runs on every existing database", ord, files)
		}
	}
	// Catch the dangerous inverse too: a grandfathered ordinal losing/gaining a file
	// means someone renamed a historical migration (the operation to avoid).
	for ord, want := range knownDupOrdinals {
		if got := len(ordinals[ord]); got != want {
			t.Errorf("historical ordinal %s now has %d files (expected %d): renaming an applied "+
				"migration breaks schema_migrations tracking", ord, got, want)
		}
	}
}
