// Package release defines Provenance's signed upgrade bundle (`.provup`): its
// manifest, Ed25519 detached-signature signing/verification, and streaming
// read/write of the bundle tar (a manifest + detached signature + one saved Docker
// image tar per changed component). It is the trust foundation for the in-UI
// upgrade system — an uploaded bundle is remote code execution by design, so nothing
// is applied until its signature verifies against a trusted release key and every
// image's content hash matches the signed manifest.
package release

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ManifestSchema is the current manifest schema version.
const ManifestSchema = 1

// Lineage names the product line these releases belong to. It is compared against a
// bundle's own declared lineage before the version numbers are even looked at.
//
// Version numbers alone cannot answer "is this bundle the same product?". This
// repository carries tags from two earlier product lines it was forked from, and
// their numbering runs AHEAD of the current one — a Moorgate-era v2.0.2 bundle
// outranks a running v1.3.0 by semver, so a gate that only asks "is it newer?"
// accepts it and installs a different, older codebase over the running one. Applying
// a bundle is remote code execution by design; "newer" is not identity.
const Lineage = "provenance"

// Migration-compatibility values. They drive rolling-upgrade ordering: an "additive"
// release (only new tables / nullable columns) is safe to run with older peers still
// live, so a cluster can roll one instance at a time; a "breaking" release requires a
// quiesced maintenance window.
const (
	CompatAdditive = "additive"
	CompatBreaking = "breaking"
)

// Manifest describes what a bundle installs. It is the signed document; because it
// pins each image's content digest, a valid signature over the manifest transitively
// authenticates the image payloads.
type Manifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	Version       string `json:"version"` // app version this bundle installs, e.g. "v0.61.0"
	// Lineage is the product line this bundle belongs to; it must equal the running
	// build's Lineage. Omitted by bundles built before the field existed, which is
	// why an absent value is refused rather than assumed compatible — the bundles
	// that predate it are exactly the ones from the other product lines.
	Lineage                string     `json:"lineage,omitempty"`
	BuildDate              string     `json:"buildDate"`              // RFC3339
	MinFromVersion         string     `json:"minFromVersion"`         // lowest running version this may upgrade from
	Components             []string   `json:"components"`             // e.g. ["backend","frontend","grype-scanner"]
	Images                 []ImageRef `json:"images"`                 // one per changed component
	Migrations             []string   `json:"migrations,omitempty"`   // migration filenames introduced (informational)
	MigrationCompatibility string     `json:"migrationCompatibility"` // additive | breaking
	Notes                  string     `json:"notes,omitempty"`
	// ConfigAdditions declares NEW environment keys this release needs. The updater
	// merges them into the deployment's .env before recreating containers — additive
	// only (an existing key is never touched), so operator-set values are preserved.
	// This is what lets a release that introduces a new setting (or a generated secret
	// like PROV_UPDATER_TOKEN) install from a bundle without hand-editing .env.
	ConfigAdditions []ConfigAddition `json:"configAdditions,omitempty"`
}

// ConfigAddition is one env key a bundle adds to the deployment's .env if absent.
type ConfigAddition struct {
	Key      string `json:"key"`                // e.g. PROV_UPDATER_TOKEN; must match ^[A-Z][A-Z0-9_]*$
	Default  string `json:"default,omitempty"`  // literal value written when the key is absent
	Generate string `json:"generate,omitempty"` // "" (use Default) or "secret" (generate 32 random bytes, hex)
	Comment  string `json:"comment,omitempty"`  // written as a # comment line above the key
}

// configKeyRE bounds an env key to a safe shell/dotenv identifier.
var configKeyRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// Validate checks a config addition is well-formed.
func (c ConfigAddition) Validate() error {
	if !configKeyRE.MatchString(c.Key) {
		return fmt.Errorf("config addition key %q is not a valid env identifier", c.Key)
	}
	switch c.Generate {
	case "", "secret":
	default:
		return fmt.Errorf("config addition %q: generate must be empty or \"secret\", got %q", c.Key, c.Generate)
	}
	// A newline in a value would corrupt the .env; reject it.
	if strings.ContainsAny(c.Default, "\n\r") {
		return fmt.Errorf("config addition %q: default value must not contain newlines", c.Key)
	}
	return nil
}

// ImageRef pins one component's saved Docker image inside the bundle.
type ImageRef struct {
	Component string `json:"component"` // backend | frontend | grype-scanner
	Image     string `json:"image"`     // repository, e.g. "provenance-backend"
	Tag       string `json:"tag"`       // version tag loaded on the host
	File      string `json:"file"`      // path within the bundle tar, e.g. "images/backend.tar"
	Digest    string `json:"digest"`    // "sha256:<hex>" over the image tar file
	Bytes     int64  `json:"bytes"`
}

// Validate checks the manifest is internally well-formed (before trusting versions).
func (m *Manifest) Validate() error {
	if m.SchemaVersion != ManifestSchema {
		return fmt.Errorf("unsupported manifest schema %d (want %d)", m.SchemaVersion, ManifestSchema)
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("manifest has no version")
	}
	if len(m.Images) == 0 {
		return fmt.Errorf("manifest lists no images")
	}
	switch m.MigrationCompatibility {
	case CompatAdditive, CompatBreaking:
	default:
		return fmt.Errorf("manifest migrationCompatibility must be %q or %q, got %q", CompatAdditive, CompatBreaking, m.MigrationCompatibility)
	}
	for i, im := range m.Images {
		if im.Component == "" || im.Image == "" || im.Tag == "" || im.File == "" {
			return fmt.Errorf("image[%d] is missing a required field", i)
		}
		if !strings.HasPrefix(im.Digest, "sha256:") || len(im.Digest) != len("sha256:")+64 {
			return fmt.Errorf("image[%d] (%s) has an invalid digest", i, im.Component)
		}
	}
	for _, c := range m.ConfigAdditions {
		if err := c.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// CheckUpgradeable verifies this bundle may be applied to a host running
// currentVersion: the bundle must be strictly newer, and currentVersion must be at
// or above minFromVersion. A non-semver currentVersion (e.g. "dev" or a git-describe
// build) is treated as a development build and allowed to install anything — real
// releases carry a "vX.Y.Z" version.
func (m *Manifest) CheckUpgradeable(currentVersion string) error {
	// Identity before ordering. A bundle from another product line can carry a
	// higher version number than anything this line has released, so checking
	// "newer" first would accept it and then never reach this test.
	if err := m.checkLineage(); err != nil {
		return err
	}
	cur, curOK := parseVersion(currentVersion)
	newV, newOK := parseVersion(m.Version)
	if !newOK {
		return fmt.Errorf("bundle version %q is not a valid release version", m.Version)
	}
	if !curOK {
		return nil // dev/unknown current build: allow (developer machine)
	}
	if compare(newV, cur) <= 0 {
		return fmt.Errorf("bundle version %s is not newer than the running version %s", m.Version, currentVersion)
	}
	if minV, ok := parseVersion(m.MinFromVersion); ok && compare(cur, minV) < 0 {
		return fmt.Errorf("running version %s is older than this bundle's minimum upgradable-from version %s — upgrade to %s first", currentVersion, m.MinFromVersion, m.MinFromVersion)
	}
	return nil
}

// NewerVersion reports whether release version a is strictly newer than b (both
// "vX.Y.Z"). A non-semver value sorts as older.
func NewerVersion(a, b string) bool {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok {
		return false
	}
	if !bok {
		return true
	}
	return compare(av, bv) > 0
}

// semver is a parsed major.minor.patch (pre-release/build metadata ignored).
type semver struct{ major, minor, patch int }

// checkLineage refuses a bundle that does not declare this product line.
//
// An absent lineage is refused rather than tolerated. The rule reads harshly for a
// legitimately old bundle, but the bundles that predate the field are precisely the
// dangerous ones — the earlier product lines this repository was forked from, whose
// version numbers run ahead of the current line. A bundle that cannot say what it is
// cannot be shown to be the same product, and the cost of being wrong is the whole
// stack replaced by an older, different codebase.
//
// The remedy is to rebuild it: `provctl release build` stamps the lineage.
func (m *Manifest) checkLineage() error {
	got := strings.TrimSpace(m.Lineage)
	switch {
	case got == "":
		return fmt.Errorf("bundle %s does not declare a product lineage, so it cannot be shown to be a %s release — "+
			"bundles built before lineage tagging include the earlier product lines this one was forked from, whose "+
			"version numbers run ahead of it. Rebuild the bundle with a current provctl if it is genuinely a %s release",
			m.Version, Lineage, Lineage)
	case !strings.EqualFold(got, Lineage):
		return fmt.Errorf("bundle %s belongs to the %q product line, but this deployment runs %q — "+
			"installing it would replace the running stack with a different product",
			m.Version, got, Lineage)
	}
	return nil
}

// parseVersion parses "vX.Y.Z" (optionally with a -prerelease/+build suffix, which is
// ignored). ok=false for anything that isn't a clean numeric triple.
func parseVersion(s string) (semver, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	// Drop any -prerelease or +build metadata.
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	var v semver
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		switch i {
		case 0:
			v.major = n
		case 1:
			v.minor = n
		case 2:
			v.patch = n
		}
	}
	return v, true
}

func compare(a, b semver) int {
	switch {
	case a.major != b.major:
		return sign(a.major - b.major)
	case a.minor != b.minor:
		return sign(a.minor - b.minor)
	default:
		return sign(a.patch - b.patch)
	}
}

func sign(n int) int {
	switch {
	case n > 0:
		return 1
	case n < 0:
		return -1
	default:
		return 0
	}
}

// BaselineConfigAdditions are the settings every bundle must carry, because the
// backend it installs refuses to start without them.
//
// Config additions are applied PER BUNDLE, not cumulatively: the updater merges the
// manifest of the release being installed and nothing else. So a setting introduced
// as a requirement in one release has to be re-declared by every release after it,
// or a deployment that skips the intervening version never receives it.
//
// That is not hypothetical. PROV_RECORDING_KEY became required in 2.0.1, whose bundle
// generated one. minFromVersion is 0.0.0, so a 2.0.0 or 1.9.x deployment may upgrade
// straight to a later release — and if that release had not re-declared the key, the
// upgrade would have installed a backend that refuses to boot, on a deployment that
// was working a minute earlier.
//
// Keeping the list here rather than in each release command means the next person to
// cut a release cannot omit it by not knowing about it. Anything added to
// Config.validate()'s production requirements belongs here too.
var BaselineConfigAdditions = []ConfigAddition{
	{
		Key:      "PROV_RECORDING_KEY",
		Generate: "secret",
		Comment:  "encrypts session recordings at rest; required since 2.0.1",
	},
}

// MergeBaselineConfigAdditions returns extra plus every baseline addition it does not
// already declare, so an explicit --config-secret for the same key wins and is not
// duplicated.
func MergeBaselineConfigAdditions(extra []ConfigAddition) []ConfigAddition {
	seen := map[string]bool{}
	for _, a := range extra {
		seen[a.Key] = true
	}
	out := append([]ConfigAddition(nil), extra...)
	for _, a := range BaselineConfigAdditions {
		if !seen[a.Key] {
			out = append(out, a)
		}
	}
	return out
}
