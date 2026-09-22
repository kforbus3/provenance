package release

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A bundle must carry every setting the backend it installs refuses to start without.
//
// Config additions are applied PER BUNDLE: the updater merges the manifest of the
// release being installed and nothing else. PROV_RECORDING_KEY became required in
// 2.0.1, whose bundle generated one — but minFromVersion is 0.0.0, so a 2.0.0 or
// 1.9.x deployment may upgrade straight to a later release. Had that release not
// re-declared the key, the upgrade would have installed a backend that refuses to
// boot, on a deployment that was working a minute earlier.
func TestBaselineCarriesTheRecordingKey(t *testing.T) {
	var found bool
	for _, a := range BaselineConfigAdditions {
		if a.Key == "PROV_RECORDING_KEY" {
			found = true
			if a.Generate != "secret" {
				t.Errorf("the recording key is declared with generate=%q; it must be generated, "+
					"since there is no sensible literal default for a secret", a.Generate)
			}
		}
	}
	if !found {
		t.Error("PROV_RECORDING_KEY is not in the baseline, so a bundle would install a " +
			"backend that requires it without providing one")
	}
	for _, a := range BaselineConfigAdditions {
		if err := a.Validate(); err != nil {
			t.Errorf("baseline addition %q is not well-formed: %v", a.Key, err)
		}
	}
}

// An explicit --config-secret for the same key must not produce a duplicate.
func TestMergeDoesNotDuplicateAnExplicitDeclaration(t *testing.T) {
	got := MergeBaselineConfigAdditions([]ConfigAddition{
		{Key: "PROV_RECORDING_KEY", Generate: "secret"},
		{Key: "PROV_SOMETHING_ELSE", Default: "1"},
	})
	seen := map[string]int{}
	for _, a := range got {
		seen[a.Key]++
	}
	if seen["PROV_RECORDING_KEY"] != 1 {
		t.Errorf("PROV_RECORDING_KEY appears %d times", seen["PROV_RECORDING_KEY"])
	}
	if seen["PROV_SOMETHING_ELSE"] != 1 {
		t.Error("an explicit addition was dropped")
	}
}

// And a bundle that declares nothing still gets the baseline.
func TestABundleThatDeclaresNothingStillCarriesTheBaseline(t *testing.T) {
	if got := MergeBaselineConfigAdditions(nil); len(got) != len(BaselineConfigAdditions) {
		t.Errorf("declared %d addition(s), want the %d baseline", len(got), len(BaselineConfigAdditions))
	}
}

// The baseline must keep up with what the backend actually demands.
//
// Config.validate() is the list of truth for what production refuses to start
// without. Most of those are operator-supplied (a JWT secret is not something a
// release can invent for you) — but a GENERATED secret, one the release could create
// and the operator has no reason to choose, must be in the baseline or an upgrade
// hands somebody a backend that will not boot.
func TestGeneratedRequirementsAreInTheBaseline(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "config", "config.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	i := strings.Index(body, "func (c *Config) validate() error {")
	if i < 0 {
		t.Fatal("Config.validate not found — this test no longer guards what it claims")
	}
	end := strings.Index(body[i:], "\n}\n")
	required := regexp.MustCompile(`missing = append\(missing, "(PROV_[A-Z0-9_]+)`).
		FindAllStringSubmatch(body[i:i+end], -1)
	if len(required) == 0 {
		t.Fatal("no production-required settings parsed out of config.go")
	}

	inBaseline := map[string]bool{}
	for _, a := range BaselineConfigAdditions {
		inBaseline[a.Key] = true
	}
	// Settings a release cannot invent on the operator's behalf: identities and trust
	// anchors, not conveniences. Silently generating one would be worse than refusing
	// to start, and every existing deployment already has these, so no upgrade meets
	// them for the first time.
	operatorSupplied := map[string]bool{
		"PROV_JWT_SECRET": true, "PROV_CSRF_SECRET": true, "PROV_CA_PASSPHRASE": true,
		"PROV_AUDIT_HMAC_KEY": true, "PROV_ANSIBLE_RUNNER_TOKEN": true,
	}
	// Required only when the operator has opted into a subsystem, so no bundle needs
	// to provide them: a deployment without the subsystem never meets the check, and
	// one with it had to configure the subsystem by hand anyway. This list is why the
	// guard does not flag them, and it is not the same as "operator supplied" — the
	// distinction is whether the requirement applies at all.
	//
	// The regex below reads requirements out of validate() without seeing the `if`
	// they sit inside, which is exactly how PROV_BUILDER_RUNNER_TOKEN first appeared
	// here: unconditional to this test, conditional in fact.
	conditional := map[string]bool{
		"PROV_BUILDER_RUNNER_TOKEN": true,
	}
	for _, m := range required {
		key := m[1]
		if operatorSupplied[key] || conditional[key] || inBaseline[key] {
			continue
		}
		t.Errorf("production requires %s, and nothing here accounts for it. Classify it: "+
			"BaselineConfigAdditions if a release can generate it, operatorSupplied if a "+
			"human must choose it, conditional if the requirement only applies once the "+
			"operator opts into a subsystem. Otherwise an upgrade installs a backend that "+
			"refuses to start on a deployment that was working a minute earlier.", key)
	}
}
