package db

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestRLSCoverage is a regression guard against multi-tenancy row-level-security (RLS)
// gaps. The H1 audit finding was that seven tenant-data tables shipped with NO tenant_id
// column and NO RLS policy, so in a FLEET_MULTI_TENANCY deployment one customer tenant
// could read/edit/delete every other tenant's rows in those tables (fixed by migration
// 0074). This test forces every FUTURE table to make an explicit, reviewed choice: it
// must either be RLS-protected, or be listed in rlsGlobalAllowlist below with a one-line
// reason explaining why it is intentionally fleet-global / not tenant-scoped.
//
// A brand-new table that is neither RLS-enabled nor allowlisted fails this test with a
// message telling the developer to add RLS (the tenant_id + FORCE ROW LEVEL SECURITY
// envelope used throughout the migrations) or justify a global allowlist entry.
//
// How RLS is detected: the migrations enable RLS two ways — a literal
// `ALTER TABLE <name> ENABLE ROW LEVEL SECURITY` (0063), and (the common case) a
// `DO $$ ... FOREACH t IN ARRAY ARRAY['a','b',...] LOOP ... EXECUTE 'ALTER TABLE %I
// ENABLE ROW LEVEL SECURITY' ... END $$` loop over a list of table names (0051, 0062,
// 0074). This test recognizes both: literal ALTER-TABLE targets, plus every quoted
// table name inside an ARRAY[...] that lives in a migration whose body enables RLS.
//
// rlsGlobalAllowlist is the documented "intentionally NOT tenant-scoped" set. It was
// produced by computing (tables created) minus (tables with RLS) against the current
// migrations and classifying each remainder as genuinely global/operational. Adding a
// table here is a deliberate security decision — it asserts the table holds no
// per-tenant data (or is isolated some other way). Keep the reason accurate.
var rlsGlobalAllowlist = map[string]string{
	// --- tenancy + RBAC catalog (global by design; the per-user *assignment* is scoped) ---
	"tenants":          "the tenant registry itself — the root of the tenancy model, administered by the provider tenant; not tenant-scoped (0051).",
	"permissions":      "global RBAC capability catalog (static permission keys) shared by all tenants (0001).",
	"roles":            "global RBAC role catalog shared by all tenants; the per-user assignment (user_roles) is the tenant-scoped table (0001).",
	"role_permissions": "global role->permission mapping (part of the shared RBAC catalog) (0001).",
	"settings":         "fleet-wide key/value instance configuration (branding, toggles); not per-tenant data (0001).",

	// --- SSH certificate authority (one fleet-wide CA) ---
	"ca_keys":          "the fleet-wide SSH certificate-authority keypair(s); single shared CA, not tenant data (0001).",
	"cert_revocations": "revocation list (by serial) for the single fleet-wide SSH CA; one global CRL (0001).",

	// --- overlay (WireGuard/OpenVPN) PKI — one fleet-wide CA/CRL, not in the 0051 scoped set ---
	"overlay_ca":          "fleet-wide overlay PKI certificate authority (FIPS/OpenVPN overlay mode); single global CA (0049).",
	"overlay_clients":     "overlay PKI issued-client registry; fleet-wide overlay infrastructure state (0049).",
	"overlay_revocations": "overlay PKI CRL — one global revocation list consumed by the overlay server; documented global in 0074 (0073).",

	// --- host / infrastructure identity shared across tenants ---
	"ssh_host_keys":     "TOFU host-key pins are a physical host's cryptographic identity (PK host), shared gateway infra; documented intentionally-global in 0068/0074.",
	"cluster_instances": "HA instance registry (identity/liveness/leadership) — operational infra state per backend process, not tenant data (0036).",
	"msrc_updates":      "global Microsoft KB->CVE reference cache; shared vulnerability reference data, not per-tenant (0041).",

	// --- federation control plane (hub-global, or the site's own single-tenant DB) ---
	"federation_hub":          "the local instance's singleton (id=1) hub-join config; site-side control, not a tenant entity (0060).",
	"federation_hub_keys":     "hub federation identity keypairs (Ed25519); hub-global, not tenant-scoped (0060).",
	"federation_seen_nonces":  "site-side replay-defense nonce set; lives in the site's own single-tenant DB (0060).",
	"federation_shadow_users": "site-side shadow-user map for hub SSO; lives in the site's own single-tenant DB (0060).",

	// --- per-user (not per-tenant) ---
	"user_preferences": "per-user UI prefs keyed by user_id, always scoped to the authenticated user; carries no tenant_id by design (0055).",
	// NOTE: assistant_feedback (0069) was the gap this guard first surfaced; it is now
	// tenant-scoped by migration 0077, so it is RLS-protected rather than allowlisted.
}

var (
	reCreateTable = regexp.MustCompile(`(?is)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?("?)([A-Za-z0-9_.]+)"?`)
	// Literal RLS toggles. The dynamic-loop form uses `ALTER TABLE %I ...`; `%I` is not a
	// valid identifier here so it is naturally excluded and handled via the ARRAY parsing.
	reAlterRLS = regexp.MustCompile(`(?is)\bALTER\s+TABLE\s+(?:ONLY\s+)?("?)([A-Za-z0-9_.]+)"?\s+(?:ENABLE|FORCE)\s+ROW\s+LEVEL\s+SECURITY`)
	reArray    = regexp.MustCompile(`(?is)\bARRAY\s*\[(.*?)\]`)
	reQuoted   = regexp.MustCompile(`'([^']+)'`)
)

// normTable strips a schema qualifier and quotes and lower-cases, so "public"."Hosts"
// and hosts collapse to the same key.
func normTable(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, `"`)
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	return strings.ToLower(strings.Trim(s, `"`))
}

func loadMigrationSQL(t *testing.T) map[string]string {
	t.Helper()
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("read embedded migrations dir: %v", err)
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := fs.ReadFile(migrationsFS, "migrations/"+e.Name())
		if err != nil {
			t.Fatalf("read embedded migration %s: %v", e.Name(), err)
		}
		out[e.Name()] = string(b)
	}
	if len(out) == 0 {
		t.Fatal("no embedded migrations found — embed.FS wiring changed?")
	}
	return out
}

func TestRLSCoverage(t *testing.T) {
	files := loadMigrationSQL(t)

	created := map[string]bool{}
	rls := map[string]bool{}

	for _, sql := range files {
		for _, m := range reCreateTable.FindAllStringSubmatch(sql, -1) {
			created[normTable(m[2])] = true
		}
		for _, m := range reAlterRLS.FindAllStringSubmatch(sql, -1) {
			rls[normTable(m[2])] = true
		}
		// Dynamic loop form: only trust ARRAY contents when the migration actually
		// enables RLS, so an unrelated ARRAY[] elsewhere can't mark a table protected.
		if strings.Contains(strings.ToUpper(sql), "ROW LEVEL SECURITY") {
			for _, a := range reArray.FindAllStringSubmatch(sql, -1) {
				for _, q := range reQuoted.FindAllStringSubmatch(a[1], -1) {
					rls[normTable(q[1])] = true
				}
			}
		}
	}

	if len(created) == 0 {
		t.Fatal("parsed zero CREATE TABLE statements — the parser or migrations changed")
	}

	// Every created table must be RLS-protected OR explicitly allowlisted as global.
	var gaps []string
	for tbl := range created {
		if rls[tbl] {
			continue
		}
		if _, ok := rlsGlobalAllowlist[tbl]; ok {
			continue
		}
		gaps = append(gaps, tbl)
	}
	sort.Strings(gaps)

	if len(gaps) > 0 {
		t.Fatalf("multi-tenancy RLS coverage gap: %d table(s) are created by a migration but "+
			"are neither RLS-enabled nor on the intentionally-global allowlist: %s\n\n"+
			"For each, make an explicit choice:\n"+
			"  * tenant data  -> add the tenancy envelope (tenant_id column + ENABLE/FORCE ROW "+
			"LEVEL SECURITY + tenant_isolation policy), e.g. add it to a scoped ARRAY[] like 0074.\n"+
			"  * genuinely fleet-global -> add it to rlsGlobalAllowlist in %s with a one-line reason.",
			len(gaps), strings.Join(gaps, ", "), "internal/db/rls_coverage_test.go")
	}

	// Keep the allowlist honest: an entry for a table that no longer exists (or is now
	// RLS-protected) is stale and should be removed so the allowlist keeps meaning.
	for tbl := range rlsGlobalAllowlist {
		if !created[tbl] {
			t.Errorf("rlsGlobalAllowlist has %q but no migration creates that table — remove the stale entry", tbl)
		}
		if rls[tbl] {
			t.Errorf("rlsGlobalAllowlist has %q but it is now RLS-protected — remove it from the allowlist", tbl)
		}
	}

	t.Logf("RLS coverage: %d tables created, %d RLS-protected, %d intentionally-global (allowlisted)",
		len(created), countRLSCreated(created, rls), len(rlsGlobalAllowlist))
}

// countRLSCreated counts created tables that are RLS-protected (rls may also contain
// names like external_secrets that no migration creates in this schema).
func countRLSCreated(created, rls map[string]bool) int {
	n := 0
	for tbl := range created {
		if rls[tbl] {
			n++
		}
	}
	return n
}
