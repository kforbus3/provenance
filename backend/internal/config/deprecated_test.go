package config

import (
	"strings"
	"testing"
)

// The list is empty today. These tests are what make it safe to add to: an
// entry with a missing field, or one that outlives the release meant to remove
// it, would otherwise be found by an operator rather than by CI.
func TestDeprecationsAreWellFormed(t *testing.T) {
	for _, d := range deprecations {
		if d.Env == "" {
			t.Error("a deprecation with no setting name")
			continue
		}
		if !strings.HasPrefix(d.Env, "FLEET_") {
			t.Errorf("%s: not a Fleet setting", d.Env)
		}
		if d.Since == "" || d.RemoveIn == "" {
			t.Errorf("%s: needs both the release that deprecated it and the one that removes it — "+
				"without them an operator cannot tell how long they have", d.Env)
		}
		// Removal is a breaking change, so it happens in a major. An entry
		// scheduled into a minor is a promise the compatibility policy forbids.
		if d.RemoveIn != "" && !strings.HasSuffix(d.RemoveIn, ".0.0") {
			t.Errorf("%s: scheduled for removal in %s, but a setting may only be removed in a major release",
				d.Env, d.RemoveIn)
		}
	}
}

func TestDeprecationMessageNamesTheReplacement(t *testing.T) {
	d := deprecation{Env: "FLEET_OLD", Replacement: "FLEET_NEW", Since: "1.1.0", RemoveIn: "2.0.0"}
	msg := d.message()
	for _, want := range []string{"FLEET_OLD", "FLEET_NEW", "1.1.0", "2.0.0", "deprecated"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not mention %q", msg, want)
		}
	}

	// A setting with nothing replacing it should say so rather than trail off.
	bare := deprecation{Env: "FLEET_GONE", Since: "1.1.0", RemoveIn: "2.0.0"}
	if !strings.Contains(bare.message(), "no replacement") {
		t.Errorf("message %q should say there is no replacement", bare.message())
	}
}
