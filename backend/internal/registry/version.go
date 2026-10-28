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
//
// A commit hash is not a variant either. searxng tags every release
// 2026.10.27-b5ed73fcb: the date is the version and the hash names the commit it
// was built from. Read as a stem, every release had a different one, so no two
// searxng tags were ever comparable and both hosts running it sat on September
// builds reading "nothing newer". All hashes share one stem, and carry no counter:
// a hash orders nothing, so two builds of the same date stay unordered here and
// the checker asks the registry which of them :latest is (see sameVersionBuilds).
func suffixParts(suffix string) (stem string, counter int) {
	if isCommitHash(suffix) {
		return "#commit", -1
	}
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

// commitHash is an abbreviated or full git hash after a separator.
var commitHash = regexp.MustCompile(`^[-_.+][0-9a-f]{7,40}$`)

// isCommitHash reports a suffix that is a commit hash: hex, and with both digits
// and letters in it, which a word ("-deadbeef") or a counter ("-1234567") lacks.
func isCommitHash(suffix string) bool {
	return commitHash.MatchString(suffix) &&
		strings.ContainsAny(suffix, "0123456789") && strings.ContainsAny(suffix, "abcdef")
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
//
// A date stamp counts too: jellyfin publishes nightly builds as 2026102610, one
// component that is a date and an hour. Its leading four digits are the year, and a
// major version of two billion is no more a thing anybody ships than one of 2021.
func looksCalendar(v Version) bool {
	if len(v.Parts) == 0 {
		return false
	}
	n := v.Parts[0]
	if n >= 1990_01_01 { // yyyymmdd at the shortest
		for n >= 10000 {
			n /= 10
		}
	}
	return n >= 1990 && n <= 2200
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

// NewerElsewhere returns the newest release that Newest could not order against
// current but that is plainly later than it, or "" when there is none.
//
// Newest refuses to compare across shapes, and the refusal is right for an
// automatic update: it is what keeps 16-bookworm from being rolled out over
// 15-alpine. But a refusal that also stays silent leaves the image on the
// version it runs forever, and on this fleet Provenance is how images get
// upgraded at all. Three ways that happened, each answered here:
//
//  0. The project changed how it numbers releases. jellyfin went from 10.11.11 to
//     12.0 and tags 12.4, so no tag of the running shape will ever be newer.
//  1. A version inside the suffix moved. qbittorrent 5.2.3_v2.0.13-ls470 became
//     5.3.0_v2.1.2-ls485 when the bundled libtorrent did; apache/tika
//     4.1.0-1-full became 4.1.0-2-full; nginx 1.31-alpine3.24 will become
//     1.32-alpine4.0. Same suffix with its digits taken out.
//  2. The variant changed outright, within the same major: 1.26-bookworm to
//     1.28-trixie once a base image stops being built.
//
// Earlier tiers win: a candidate closer to the running line is the better answer.
// Every candidate shares the prefix and calendar-ness (the refusals that guard
// against a different scheme entirely), has at least two components (a lone
// number is as often a build counter -- linuxserver/mariadb still carries a bare
// 158), and is strictly later. In tier 2 it must also not be a prerelease, since
// its suffix is no longer the running one's and cannot vouch for it.
//
// The answer is reported and offered one row at a time, never swept into Update
// all: crossing any of these is a decision about which line to be on.
func NewerElsewhere(current string, tags []string) string {
	cur, ok := ParseVersion(current)
	if !ok {
		return ""
	}
	var best [3]*Version
	for _, t := range tags {
		v, ok := ParseVersion(t)
		if !ok || v.Prefix != cur.Prefix || looksCalendar(v) != looksCalendar(cur) ||
			len(v.Parts) < 2 {
			continue
		}
		same := sameVariant(cur, v)
		tier := -1
		switch {
		case len(v.Parts) != len(cur.Parts):
			if same {
				tier = 0
			}
		case same:
			// Newest's own shape; it already ordered these.
		case skeleton(v.Suffix) == skeleton(cur.Suffix):
			tier = 1
		case !prerelease.MatchString(v.Suffix) && v.Parts[0] == cur.Parts[0]:
			// A different variant AND a different major is two changes at once,
			// and in practice a malformed tag: linuxserver/mariadb carries
			// 110.4.21mariabionic-ls30 beside 11.8.9.
			tier = 2
		}
		if tier < 0 || later(cur, v, tier == 1) <= 0 {
			continue
		}
		b := best[tier]
		if b == nil || later(*b, v, tier == 1) > 0 ||
			(later(*b, v, tier == 1) == 0 && len(v.Parts) > len(b.Parts)) {
			v := v
			best[tier] = &v
		}
	}
	for _, b := range best {
		if b != nil {
			return b.Raw
		}
	}
	return ""
}

// sameVariant is Comparable's suffix rule on its own.
func sameVariant(a, b Version) bool {
	as, ac := suffixParts(a.Suffix)
	bs, bc := suffixParts(b.Suffix)
	return as == bs && (ac < 0) == (bc < 0)
}

var digitRun = regexp.MustCompile(`[0-9]+`)

// skeleton is a suffix with its numbers taken out: "_v2.0.13-ls470" -> "_v.-ls".
func skeleton(suffix string) string { return digitRun.ReplaceAllString(suffix, "") }

// prerelease matches a suffix naming something that is not a release.
var prerelease = regexp.MustCompile(`(?i)(^|[^a-z])(rc|alpha|beta|snapshot|dev|develop|development|` +
	`nightly|preview|pre|test|testing|pr|deprecated|unstable|canary|edge|experimental)([^a-z]|$)`)

// later is leading, then -- when the versions tie and withSuffix is set -- the
// numbers in the suffix: 4.1.0-2-full is later than 4.1.0-1-full.
func later(a, b Version, withSuffix bool) int {
	if c := leading(a, b); c != 0 || !withSuffix {
		return c
	}
	an, bn := digitRun.FindAllString(a.Suffix, -1), digitRun.FindAllString(b.Suffix, -1)
	for i := 0; i < len(an) && i < len(bn); i++ {
		x, _ := strconv.Atoi(an[i])
		y, _ := strconv.Atoi(bn[i])
		switch {
		case y > x:
			return 1
		case y < x:
			return -1
		}
	}
	return 0
}

// leading compares a and b over the components they share: 1 when b is later, -1
// when it is earlier, 0 when neither can be told from the other.
func leading(a, b Version) int {
	for i := 0; i < len(a.Parts) && i < len(b.Parts); i++ {
		switch {
		case b.Parts[i] > a.Parts[i]:
			return 1
		case b.Parts[i] < a.Parts[i]:
			return -1
		}
	}
	return 0
}

// sameVersionBuilds returns the other tags at newest's version that differ from it
// only by commit hash -- searxng pushes several builds a day as 2026.10.27-<hash>.
// Their names cannot say which is the latest (registries list tags lexically, not
// in push order), so the checker resolves them against :latest.
func sameVersionBuilds(newest string, tags []string) []string {
	n, ok := ParseVersion(newest)
	if !ok || !isCommitHash(n.Suffix) {
		return nil
	}
	var out []string
	for _, t := range tags {
		v, ok := ParseVersion(t)
		if ok && t != newest && isCommitHash(v.Suffix) && v.Prefix == n.Prefix &&
			len(v.Parts) == len(n.Parts) && leading(n, v) == 0 {
			out = append(out, t)
		}
	}
	return out
}
