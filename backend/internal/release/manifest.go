// Package release defines Moorgate's signed upgrade bundle (`.fleetup`): its
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
	SchemaVersion          int        `json:"schemaVersion"`
	Version                string     `json:"version"`                // app version this bundle installs, e.g. "v0.61.0"
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
	// like FLEET_UPDATER_TOKEN) install from a bundle without hand-editing .env.
	ConfigAdditions []ConfigAddition `json:"configAdditions,omitempty"`
}

// ConfigAddition is one env key a bundle adds to the deployment's .env if absent.
type ConfigAddition struct {
	Key      string `json:"key"`                // e.g. FLEET_UPDATER_TOKEN; must match ^[A-Z][A-Z0-9_]*$
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
	Image     string `json:"image"`     // repository, e.g. "fleet-terminal-backend"
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
