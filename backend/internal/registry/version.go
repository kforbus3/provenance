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

// buildCounter splits a suffix into a stem and a trailing build number:
// "-ls356" -> ("-ls", 356). No trailing digits gives a counter of -1.
var buildCounter = regexp.MustCompile(`^(.*?[^0-9])([0-9]+)$`)

// suffixParts separates a variant from a build number.
//
// linuxserver.io publishes v1.6.0-ls356, and the NEXT build of the same image is
// v1.6.0-ls372. The suffix rule -- which exists so 15-alpine is never offered as
// an upgrade to 16-bookworm -- read those as two different variants, so every
// linuxserver image on a fleet was permanently unupdatable: seven of them here,
// each reported as "no tag has the same shape", each in fact a plain version
// behind.
//
// A build counter is not a variant. It is the same stem with a number after it,
// which is exactly what this splits out, and every refusal that matters survives
// it because the STEM still has to match exactly:
//
//   - "-alpine" against "-bookworm": different distributions, different stems.
//   - "-alpine3.21" against "-alpine4.0": stems "-alpine3." and "-alpine4.", so
//     an OS major is never crossed. What DOES compare is "-alpine3.21" against
//     "-alpine3.22", a patch of the same base image, which is the same kind of
//     move a build counter is.
//   - "1.0.0" against "1.0.0-rc1": stems "" and "-rc", so a prerelease and a
//     release stay separate.
//
// The stem may contain digits, because in practice it does: qbittorrent is
// tagged 5.2.3_v2.0.13-ls469, where the digits are the bundled libtorrent
// version. Refusing those left it unorderable against 5.2.3_v2.0.13-ls470, the
// very next build -- while "_v2.0.14-ls471" is still refused, since bumping
// libtorrent changes the stem.
func suffixParts(suffix string) (stem string, counter int) {
	m := buildCounter.FindStringSubmatch(suffix)
	if m == nil {
		return suffix, -1
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return suffix, -1
	}
	return m[1], n
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
	if a.Prefix != b.Prefix || len(a.Parts) != len(b.Parts) {
		return false
	}
	// Suffixes match on their VARIANT, not on their build number. See
	// suffixParts: "-ls356" and "-ls372" are the same image, counted; "-alpine"
	// and "-bookworm" are not, and still compare unequal here.
	as, ac := suffixParts(a.Suffix)
	bs, bc := suffixParts(b.Suffix)
	if as != bs {
		return false
	}
	// One side numbered and the other not is not a build counter at all -- it is
	// a suffix that happens to end in a digit next to one that does not.
	if (ac < 0) != (bc < 0) {
		return false
	}
	// A calendar version and a semantic one are different schemes wearing the same
	// punctuation.
	//
	// linuxserver/heimdall publishes both: 2.8.3 and 2021.11.28. Every other rule
	// here passes — same prefix, same suffix, three components each — and then
	// 2021 > 2, so a four-year-old image is offered as an upgrade over a current
	// one. It was, on a live fleet, and the rollout would have written that tag
	// into the compose file where it would have stayed.
	//
	// This is the same refusal as v2 against release-3, which the prefix rule
	// already catches. It only needed catching here too because a year is spelled
	// with digits and so hides inside a rule about digits.
	return looksCalendar(a) == looksCalendar(b)
}

// looksCalendar reports a leading component that can only be a year.
//
// Bounded deliberately. A major version of 2021 is not a thing anybody ships, and
// a year outside this range is not one anybody is running — so the window is wide
// enough to be safe and narrow enough that an ordinary major version cannot fall
// into it.
func looksCalendar(v Version) bool {
	if len(v.Parts) == 0 {
		return false
	}
	return v.Parts[0] >= 1990 && v.Parts[0] <= 2200
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
	// Same version, later build. A rebuild with a higher counter is genuinely
	// newer -- that is what the counter is for -- and it is the only thing left
	// to order on once every numeric component is equal.
	_, ac := suffixParts(a.Suffix)
	_, bc := suffixParts(b.Suffix)
	return ac >= 0 && bc > ac
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
