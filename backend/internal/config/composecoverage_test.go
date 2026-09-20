package config

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every setting config.go reads must have a way in from the shipped deployment.
//
// A QA install found twenty-two that did not: PROV_FIPS_MODE, PROV_OVERLAY and
// PROV_DR_STANDBY_TOKEN among them -- so the FIPS profile, the overlay choice and
// disaster-recovery standby could not be enabled at all with the compose stack this
// project ships, however carefully an operator edited .env. The setting existed, the
// documentation described it, and nothing carried it to the process.
//
// This is drift that happens silently: a new setting is added to config.go and the
// compose file is not touched, and nothing fails. So the test is the guard.
func TestEveryConfigSettingIsReachableFromCompose(t *testing.T) {
	cfg, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatal(err)
	}
	read := regexp.MustCompile(`env(?:Bool|Int|Duration|Float|List)?\("(PROV_[A-Z0-9_]+)"`).
		FindAllStringSubmatch(string(cfg), -1)

	var compose strings.Builder
	for _, p := range []string{
		"../../../deploy/compose/docker-compose.yml",
		"../../../deploy/compose/docker-compose.jumphost.yml",
		"../../../deploy/compose/docker-compose.testfabric.yml",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		compose.Write(b)
	}
	if compose.Len() == 0 {
		t.Skip("compose files not found from this directory")
	}
	// Matched as an actual env ASSIGNMENT, not as a substring. The first version used
	// strings.Contains, and the comment introducing these lines names three of the
	// settings in prose -- so deleting PROV_FIPS_MODE's line left the test passing on
	// the strength of the comment explaining why it should be there.
	assigned := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(PROV_[A-Z0-9_]+):\s`).
		FindAllStringSubmatch(compose.String(), -1) {
		assigned[m[1]] = true
	}

	// Settings that genuinely belong somewhere else, with the reason. Keep this list
	// short and specific: an entry here is a claim that the compose stack should not
	// be able to set it.
	exempt := map[string]string{
		"PROV_DATABASE_URL": "composed from POSTGRES_* by the compose file itself",
	}

	var missing []string
	for _, m := range read {
		name := m[1]
		if _, ok := exempt[name]; ok {
			continue
		}
		if !assigned[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d setting(s) config.go reads cannot be set from the shipped compose stack:\n  %s\n"+
			"Add each as `NAME: ${NAME:-}` to the backend service, or exempt it here with a reason.",
			len(missing), strings.Join(missing, "\n  "))
	}
}
