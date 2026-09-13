package config

import "testing"

// The rename moved every setting from FLEET_ to PROV_. An operator's .env is not
// rewritten by deploying new code, so the old names have to keep being read —
// otherwise the first restart after an upgrade boots a backend with no JWT secret,
// no CA passphrase and no database URL, and fails closed.
func TestLegacyPrefixIsStillRead(t *testing.T) {
	resetLegacyEnv()
	t.Setenv("FLEET_THING", "from-legacy")
	if got := env("PROV_THING", "fallback"); got != "from-legacy" {
		t.Fatalf("env = %q, want the value from FLEET_THING", got)
	}
}

// The new name always wins. An operator who has migrated their .env but left the
// old variable behind must not be silently served the stale value.
func TestCurrentPrefixWinsOverLegacy(t *testing.T) {
	resetLegacyEnv()
	t.Setenv("FLEET_THING", "stale")
	t.Setenv("PROV_THING", "current")
	if got := env("PROV_THING", "fallback"); got != "current" {
		t.Fatalf("env = %q, want the PROV_ value", got)
	}
}

// An empty value counts as unset in both spellings. Compose writes optional
// settings as `PROV_FOO: ${PROV_FOO:-}`, so an unset variable arrives as an empty
// string rather than being absent; treating that as "set" would override a
// default with nothing and, for the required secrets, fail closed at boot.
func TestEmptyValueFallsThrough(t *testing.T) {
	resetLegacyEnv()
	t.Setenv("PROV_THING", "")
	t.Setenv("FLEET_THING", "")
	if got := env("PROV_THING", "fallback"); got != "fallback" {
		t.Fatalf("env = %q, want the default", got)
	}
	resetLegacyEnv()
	t.Setenv("PROV_THING", "")
	t.Setenv("FLEET_THING", "from-legacy")
	if got := env("PROV_THING", "fallback"); got != "from-legacy" {
		t.Fatalf("an empty PROV_ must not shadow a set FLEET_; got %q", got)
	}
}

// The typed readers go through the same fallback. Routing only the string helper
// would leave every bool, int and duration setting silently on its default —
// which is how PROV_COOKIE_SECURE or PROV_FIPS_MODE would quietly flip.
func TestTypedHelpersUseTheFallback(t *testing.T) {
	resetLegacyEnv()
	t.Setenv("FLEET_A_BOOL", "false")
	t.Setenv("FLEET_AN_INT", "7")
	t.Setenv("FLEET_A_DUR", "90s")
	if envBool("PROV_A_BOOL", true) {
		t.Error("envBool ignored the legacy name")
	}
	if got := envInt("PROV_AN_INT", 1); got != 7 {
		t.Errorf("envInt = %d, want 7", got)
	}
	if got := envDuration("PROV_A_DUR", 0).Seconds(); got != 90 {
		t.Errorf("envDuration = %v, want 90s", got)
	}
}

// Reading a legacy name has to be recorded, or the deprecation warning names
// nothing and the operator never learns which variables to rename.
func TestLegacyReadsAreRecordedForTheWarning(t *testing.T) {
	resetLegacyEnv()
	t.Setenv("FLEET_THING", "x")
	_ = env("PROV_THING", "")
	used := LegacyEnvInUse()
	if used["FLEET_THING"] != "PROV_THING" {
		t.Fatalf("LegacyEnvInUse = %v, want FLEET_THING -> PROV_THING", used)
	}
	// A setting read under its current name is not a deprecation.
	resetLegacyEnv()
	t.Setenv("PROV_OTHER", "y")
	_ = env("PROV_OTHER", "")
	if len(LegacyEnvInUse()) != 0 {
		t.Fatalf("LegacyEnvInUse = %v, want empty", LegacyEnvInUse())
	}
}

// A name that never carried the prefix has no legacy spelling to fall back to.
func TestNonPrefixedNamesHaveNoLegacyFallback(t *testing.T) {
	resetLegacyEnv()
	t.Setenv("POSTGRES_PASSWORD", "")
	if _, ok := LookupEnv("POSTGRES_PASSWORD"); ok {
		t.Fatal("an unprefixed empty setting must read as unset")
	}
	if _, ok := legacyName("POSTGRES_PASSWORD"); ok {
		t.Fatal("POSTGRES_PASSWORD must have no legacy name")
	}
}

func resetLegacyEnv() {
	legacyEnvMu.Lock()
	defer legacyEnvMu.Unlock()
	legacyEnvSeen = map[string]string{}
}
