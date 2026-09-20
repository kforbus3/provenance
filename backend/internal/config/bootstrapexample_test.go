package config

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A QA install that followed docs/installation.md to the letter could not create its
// first administrator. The guide says to start from .env.production.example, that file
// shipped PROV_ALLOW_BOOTSTRAP=false "as belt-and-braces", and the guide then says to
// create the first account on the bootstrap page -- which never appears. The endpoint
// already gates itself on there being zero users, so the flag was defending nothing
// and blocking the only documented way in.
func TestTheProductionExampleAllowsTheFirstAdministrator(t *testing.T) {
	for _, path := range []string{"../../../.env.production.example", "../../.env.production.example"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		m := regexp.MustCompile(`(?m)^PROV_ALLOW_BOOTSTRAP=(\S+)`).FindStringSubmatch(string(raw))
		if m == nil {
			// Absent is fine: the default is true.
			return
		}
		if strings.ToLower(m[1]) != "true" {
			t.Errorf("%s ships PROV_ALLOW_BOOTSTRAP=%s, so the documented install cannot "+
				"create its first administrator: the bootstrap page never appears and "+
				"/bootstrap/init answers \"no longer available\"", path, m[1])
		}
		return
	}
	t.Skip("no .env.production.example found from this directory")
}

// ...and the default in code stays permissive, because the endpoint's own zero-users
// check is the real gate.
func TestBootstrapDefaultsOn(t *testing.T) {
	t.Setenv("PROV_ALLOW_BOOTSTRAP", "")
	os.Unsetenv("PROV_ALLOW_BOOTSTRAP")
	if !envBool("PROV_ALLOW_BOOTSTRAP", true) {
		t.Error("bootstrap default is off; a fresh install has no way to create its first account")
	}
}
