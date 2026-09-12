package registry

import "testing"

// Deciding one tag is newer than another is where an update bot does damage.
//
// The failure is not a crash: it is a plausible-looking proposal to move from
// 15-alpine to 16-bookworm, or from v2 to release-3, which an operator approves
// because the tool said so. An update proposal nobody can trust is worse than
// none, because it trains people to click through.
func TestNewestRefusesToGuess(t *testing.T) {
	cases := []struct {
		name, current string
		tags          []string
		want          string
		wantNoReason  bool
	}{
		{
			name: "an ordinary patch bump", current: "1.25.1",
			tags: []string{"1.25.0", "1.25.1", "1.25.3", "1.24.9"}, want: "1.25.3", wantNoReason: true,
		},
		{
			name: "a v-prefix is kept", current: "v2.1.0",
			tags: []string{"v2.0.9", "v2.1.0", "v2.3.1"}, want: "v2.3.1", wantNoReason: true,
		},
		{
			// Genuinely up to date, and nothing ambiguous in the repository, so
			// this one really does say nothing at all.
			name: "already newest", current: "1.25.3",
			tags: []string{"1.25.0", "1.25.3"}, want: "", wantNoReason: true,
		},
		{
			// The base image is part of the identity. Proposing 16-bookworm as an
			// upgrade of 15-alpine would change the operating system inside the
			// container and present it as a version bump.
			name: "a different base image is not an upgrade", current: "15-alpine",
			tags: []string{"15-alpine", "16-bookworm", "16-alpine"}, want: "16-alpine", wantNoReason: true,
		},
		{
			// Not silently "up to date": release-3 might well be newer, and what
			// is true is that this cannot tell. An operator who is not told will
			// believe the image is current.
			name: "a different prefix is a different scheme", current: "v2",
			tags: []string{"v2", "release-3"}, want: "",
		},
		{
			// 1.25 and 1.25.3 may be the same image or may not. A rule that
			// guessed would be right often enough to be trusted.
			name: "different component counts are not compared", current: "1.25",
			tags: []string{"1.25", "1.25.3"}, want: "",
		},
		{
			name: "a moving tag is not a version", current: "latest",
			tags: []string{"latest", "1.2.3"}, want: "",
		},
		{
			name: "nothing comparable in the repository", current: "1.0.0",
			tags: []string{"latest", "stable", "edge"}, want: "",
		},
		{
			// A date tag is a version by this parser's reckoning, and ordering
			// them numerically happens to be right.
			name: "date tags order numerically", current: "2026.01.05",
			tags: []string{"2026.01.05", "2026.09.12"}, want: "2026.09.12", wantNoReason: true,
		},
	}
	for _, c := range cases {
		got, reason := Newest(c.current, c.tags)
		if got != c.want {
			t.Errorf("%s: Newest(%q) = %q, want %q (reason: %s)", c.name, c.current, got, c.want, reason)
		}
		if c.wantNoReason && reason != "" {
			t.Errorf("%s: unexpected reason %q", c.name, reason)
		}
		if !c.wantNoReason && c.want == "" && reason == "" {
			t.Errorf("%s: refused to order but gave no reason — an operator cannot "+
				"tell 'nothing newer' from 'I could not compare these'", c.name)
		}
	}
}

func TestIsNewer(t *testing.T) {
	n := func(s string) Version { v, _ := ParseVersion(s); return v }

	if !IsNewer(n("1.2.3"), n("1.2.4")) {
		t.Error("1.2.4 should be newer than 1.2.3")
	}
	if !IsNewer(n("1.2.3"), n("1.10.0")) {
		t.Error("1.10.0 should be newer than 1.2.3 — numeric, not lexical")
	}
	if IsNewer(n("1.2.3"), n("1.2.3")) {
		t.Error("a version is not newer than itself")
	}
	if IsNewer(n("1.2.4"), n("1.2.3")) {
		t.Error("older is not newer")
	}
	// Shape mismatches never compare, whichever direction.
	if IsNewer(n("1.2.3"), n("v1.2.4")) || IsNewer(n("v1.2.3"), n("1.2.4")) {
		t.Error("tags with different prefixes were ordered against each other")
	}
	if IsNewer(n("15-alpine"), n("16-bookworm")) {
		t.Error("tags with different suffixes were ordered against each other")
	}
}

func TestParseVersion(t *testing.T) {
	for _, tag := range []string{"latest", "stable", "edge", "main", ""} {
		if _, ok := ParseVersion(tag); ok {
			t.Errorf("%q carries no number and must not parse as a version", tag)
		}
	}
	v, ok := ParseVersion("v2.1.0-rc1")
	if !ok || v.Prefix != "v" || len(v.Parts) != 3 || v.Suffix != "-rc1" {
		t.Errorf("v2.1.0-rc1 parsed as %+v", v)
	}
}
