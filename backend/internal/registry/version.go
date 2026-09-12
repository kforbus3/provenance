// Package registry asks container registries what is available for the images a
// fleet is running.
//
// This is the job a renovate bot did, and the part of it that goes wrong is not
// the HTTP: it is deciding that one tag is newer than another. Tags are not
// versions. A repository may carry semver, dates, build numbers, channel names,
// and several of those at once, and "newer" is only meaningful within one of
// those schemes.
//
// So this refuses to guess. A comparison is offered only when two tags are the
// same SHAPE -- same prefix, same number of numeric components, same suffix --
// and otherwise the answer is "these cannot be ordered confidently", recorded as
// such. An update proposal nobody can trust is worse than none: it trains an
// operator to click through, which is exactly how a bad bump reaches production.
package registry

import (
	"regexp"
	"strconv"
	"strings"
)

// semverish splits a tag into an optional prefix, numeric components, and an
// optional suffix: v1.25.3, 1.25.3, 15-alpine, v2.1.0-rc1.
var semverish = regexp.MustCompile(`^([A-Za-z._-]*?)(\d+(?:\.\d+)*)(.*)$`)

// Version is a tag parsed into something comparable.
type Version struct {
	Prefix string // "v", "release-", ""
	Parts  []int  // 1.25.3 -> [1 25 3]
	Suffix string // "-alpine", "-rc1", ""
	Raw    string
}

// ParseVersion reads a tag. ok is false when the tag carries no number at all --
// "latest", "stable", "edge" -- which are not versions and must never be ordered.
func ParseVersion(tag string) (Version, bool) {
	m := semverish.FindStringSubmatch(tag)
	if m == nil {
		return Version{Raw: tag}, false
	}
	var parts []int
	for _, p := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return Version{Raw: tag}, false
		}
		parts = append(parts, n)
	}
	return Version{Prefix: m[1], Parts: parts, Suffix: m[3], Raw: tag}, true
}

// Comparable reports whether two tags are the same shape, and so can be ordered.
//
// Same prefix, same suffix, same number of components. All three matter:
//
//   - prefix: "v2" and "release-2" are different schemes that happen to contain
//     numbers.
//   - suffix: "15-alpine" and "16-bookworm" are different base images, and
//     calling one an upgrade of the other would propose changing the operating
//     system inside the container as if it were a patch bump.
//   - length: "1.25" and "1.25.3" may well be the same image, and may not; a
//     rule that guessed would be right often enough to be trusted and wrong
//     often enough to matter.
//
// A prerelease suffix compares equal in shape to another prerelease, but that is
// as far as it goes -- IsNewer refuses to move between prerelease and release.
func Comparable(a, b Version) bool {
	return a.Prefix == b.Prefix && a.Suffix == b.Suffix && len(a.Parts) == len(b.Parts)
}

// IsNewer reports whether b is a later version of the same thing as a.
func IsNewer(a, b Version) bool {
	if !Comparable(a, b) {
		return false
	}
	for i := range a.Parts {
		switch {
		case b.Parts[i] > a.Parts[i]:
			return true
		case b.Parts[i] < a.Parts[i]:
			return false
		}
	}
	return false
}

// Newest returns the newest tag comparable to current, and why it stopped if it
// did not.
//
// The reason is returned rather than discarded because "nothing newer exists" and
// "nothing here could be compared" are different facts with different responses:
// the first is fine, the second means this image will never be reported as
// out of date and somebody should know that.
func Newest(current string, tags []string) (newest string, reason string) {
	cur, ok := ParseVersion(current)
	if !ok {
		// "latest", "stable", "edge". Not a version, and a registry that moves
		// such a tag is already delivering updates by a different route.
		return "", "the running tag is not a version, so nothing can be newer than it"
	}
	best := cur
	comparable, skipped := 0, 0
	for _, t := range tags {
		v, ok := ParseVersion(t)
		if !ok {
			continue // not a version at all: "latest", "stable"
		}
		if !Comparable(cur, v) {
			// A version, but of a different shape. Counted rather than ignored:
			// see below.
			skipped++
			continue
		}
		comparable++
		if IsNewer(best, v) {
			best = v
		}
	}
	if comparable == 0 {
		return "", "no tag in this repository has the same shape as " + current +
			", so none can be ordered against it"
	}
	if best.Raw != current {
		return best.Raw, ""
	}
	// Nothing newer of the same shape -- but if the repository carries versions
	// of a DIFFERENT shape, saying only "up to date" would be misleading. There
	// may well be a newer image; what is true is that this cannot tell. An
	// operator who is not told that will believe the image is current, which is
	// the quiet half of the same failure a wrong proposal causes loudly.
	if skipped > 0 {
		return "", "nothing newer with the same shape as " + current +
			"; the repository carries other version tags that cannot be ordered against it"
	}
	return "", ""
}
