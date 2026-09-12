package composefile

import "testing"

// One parser serves the rollout rewriter and the registry checker, so what it
// finds has to be exactly what the rewriter would edit. A reference the checker
// sees and the rewriter cannot change becomes an update offer that fails on the
// host; one the rewriter changes and the checker never saw is an edit nobody
// asked for.
func TestImages(t *testing.T) {
	compose := `services:
  gluetun:
    image: qmcgaw/gluetun:v3.41.3
  bazarr:
    image: "lscr.io/linuxserver/bazarr:v1.6.0-ls356"   # pinned 2026-09-12
  private:
    image: 'registry.example.com:5000/team/app:2.1.0'
  pinned:
    image: nginx:1.27-alpine@sha256:abc123
  dupe:
    image: qmcgaw/gluetun:v3.41.3
  untagged:
    image: alpine
  notanimage:
    image_pull_policy: always
  environment:
    - IMAGE=nginx:9.9.9
`
	want := []Ref{
		{"qmcgaw/gluetun", "v3.41.3"},
		{"lscr.io/linuxserver/bazarr", "v1.6.0-ls356"},
		{"registry.example.com:5000/team/app", "2.1.0"},
		{"nginx", "1.27-alpine"},
	}
	got := Images(compose)
	if len(got) != len(want) {
		t.Fatalf("found %d image(s), want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("image %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSplitRefKeepsARegistryPort(t *testing.T) {
	// Splitting on the FIRST colon yields a repository of
	// "registry.example.com" and a tag of "5000/app", which is wrong in a way
	// nobody notices until it is their registry.
	repo, tag, ok := SplitRef("registry.example.com:5000/team/app:2.1.0")
	if !ok || repo != "registry.example.com:5000/team/app" || tag != "2.1.0" {
		t.Errorf("SplitRef = (%q, %q, %v)", repo, tag, ok)
	}
	if _, _, ok := SplitRef("registry.example.com:5000/team/app"); ok {
		t.Error("a reference with no tag must not report one")
	}
}

func TestSplitImageLineRejectsNearMisses(t *testing.T) {
	for _, line := range []string{"    image_pull_policy: always", "    imagex: a:b", "    images:", "    myimage: a:b"} {
		if _, _, ok := SplitImageLine(line); ok {
			t.Errorf("%q is not a compose image key", line)
		}
	}
	if _, v, ok := SplitImageLine("    image: nginx:1.27"); !ok || v != "nginx:1.27" {
		t.Errorf("value = %q, ok = %v", v, ok)
	}
}

func TestATrailingCommentIsNotPartOfTheReference(t *testing.T) {
	ref, trailer := SplitTrailingComment("nginx:1.27  # keep until Q3")
	if ref != "nginx:1.27  " || trailer != "# keep until Q3" {
		t.Errorf("ref = %q, trailer = %q", ref, trailer)
	}
	// A '#' not preceded by whitespace is part of the value, which is what keeps
	// a digest pin from being cut in half.
	ref, trailer = SplitTrailingComment("nginx:1.27@sha256:a#b")
	if trailer != "" || ref != "nginx:1.27@sha256:a#b" {
		t.Errorf("ref = %q, trailer = %q", ref, trailer)
	}
}
