package config

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
)

// Deprecated settings.
//
// docs/compatibility.md promises that a deprecated setting keeps working for at
// least two minor releases and warns, naming what replaces it, so an operator
// learns from their own logs rather than from an upgrade that stops working.
// This is the half of that promise the code has to keep.
//
// The list is empty, and that is the point: it exists before the first
// deprecation rather than after, so nothing has to be remembered at the moment
// it matters. Add an entry in the release that deprecates the setting.

// deprecation is one setting that still works but should not be used.
type deprecation struct {
	// Env is the old variable name.
	Env string
	// Replacement is the variable to use instead. Empty means the setting is
	// going away with nothing taking its place.
	Replacement string
	// Since is the release that deprecated it, so an operator can tell how long
	// they have.
	Since string
	// RemoveIn is the release it is scheduled to be removed in — always a major.
	RemoveIn string
}

// deprecations is the live list. Keep entries until the major that removes
// them, then delete the entry and the code that reads the old variable.
var deprecations = []deprecation{}

// warnDeprecated logs a warning for every deprecated setting that is actually
// set. A setting nobody uses is not worth a line in anyone's logs.
//
// It runs on every start rather than once, because a warning seen only at the
// moment of upgrade is a warning seen by nobody.
func warnDeprecated() {
	warnLegacyEnvPrefix()
	for _, d := range deprecations {
		if _, ok := os.LookupEnv(d.Env); !ok {
			continue
		}
		slog.Warn(d.message(), "setting", d.Env, "replacement", d.Replacement,
			"deprecated_since", d.Since, "removed_in", d.RemoveIn)
	}
}

func (d deprecation) message() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s is deprecated since %s and will be removed in %s", d.Env, d.Since, d.RemoveIn)
	if d.Replacement != "" {
		fmt.Fprintf(&b, "; use %s instead", d.Replacement)
	} else {
		b.WriteString("; it has no replacement and can be removed")
	}
	return b.String()
}

// warnLegacyEnvPrefix warns about settings still spelled with the pre-Provenance
// FLEET_ prefix. It runs after the config has been read, so it reports the ones
// that were actually consulted rather than everything in the environment — a
// variable left in a .env that nothing reads any more is not the operator's
// problem to fix.
//
// This is a whole-prefix deprecation rather than ~187 entries in `deprecations`,
// because the mapping is mechanical: only the prefix moved.
func warnLegacyEnvPrefix() {
	used := LegacyEnvInUse()
	if len(used) == 0 {
		return
	}
	old := make([]string, 0, len(used))
	for k := range used {
		old = append(old, k)
	}
	sort.Strings(old)
	pairs := make([]string, 0, len(old))
	for _, k := range old {
		pairs = append(pairs, k+" -> "+used[k])
	}
	slog.Warn("settings are using the pre-Provenance FLEET_ prefix and will stop being read in a future major; rename them to PROV_",
		"count", len(old), "settings", strings.Join(pairs, ", "))
}
