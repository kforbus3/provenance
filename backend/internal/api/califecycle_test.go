package api

import "testing"

// The gate a pending CA key passes before it signs. Promoting early is the bug this
// replaces: the new key signed before the jump host trusted it, and new logins failed.
func TestAPendingKeySignsOnlyOnceEverythingTrustsIt(t *testing.T) {
	for _, c := range []struct {
		name      string
		jump      bool
		outOfSync int
		force     bool
		want      bool
	}{
		{"jump host has not fetched it yet", false, 0, false, false},
		{"force never skips the jump host", false, 0, true, false},
		{"a host has not confirmed it", true, 2, false, false},
		{"forced past hosts that are gone", true, 2, true, true},
		{"everything trusts it", true, 0, false, true},
	} {
		got, why := promotionAllowed(c.jump, c.outOfSync, c.force)
		if got != c.want {
			t.Errorf("%s: promote=%v, want %v (%s)", c.name, got, c.want, why)
		}
		if !got && why == "" {
			t.Errorf("%s: a refusal must say why", c.name)
		}
	}
}
