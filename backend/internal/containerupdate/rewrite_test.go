package containerupdate

import (
	"strings"
	"testing"
)

func TestRewritesOnlyTheMatchingImage(t *testing.T) {
	// Every one of these near-misses is a real compose file's worth of damage if
	// the match is loosened: a different image, a different registry, or a
	// different variant of the same version silently swapped under an operator
	// who approved an nginx upgrade.
	compose := `services:
  web:
    image: nginx:1.24
  extras:
    image: nginx-extras:1.24
  mirror:
    image: ghcr.io/nginx:1.24
  alpine:
    image: nginx:1.24-alpine
  db:
    image: postgres:15
`
	out, n := RewriteImageTag(compose, "nginx", "1.24", "1.27")
	if n != 1 {
		t.Fatalf("changed %d lines, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "image: nginx:1.27") {
		t.Error("the matching image was not rewritten")
	}
	for _, untouched := range []string{
		"image: nginx-extras:1.24",
		"image: ghcr.io/nginx:1.24",
		"image: nginx:1.24-alpine",
		"image: postgres:15",
	} {
		if !strings.Contains(out, untouched) {
			t.Errorf("rewrote something it should not have: %q is gone\n%s", untouched, out)
		}
	}
}

func TestEverythingElseIsBytewiseUnchanged(t *testing.T) {
	// The diff an operator reviews before approving an update must contain only
	// the change they approved. A YAML round-trip would drop the comments,
	// renormalise the quoting and reorder the keys, and bury one tag bump in a
	// hundred-line diff nobody can read.
	compose := `# production web stack -- do not edit by hand
services:
  web:
    image: nginx:1.24   # pinned deliberately, see RFD-14
    environment:
      - "GREETING=${GREETING:-hello}"
    ports: [ "80:80" ]
`
	out, n := RewriteImageTag(compose, "nginx", "1.24", "1.27")
	if n != 1 {
		t.Fatalf("changed %d", n)
	}
	want := strings.Replace(compose, "nginx:1.24", "nginx:1.27", 1)
	if out != want {
		t.Errorf("the file changed beyond the image tag:\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

func TestQuotingAndSpacingAreKept(t *testing.T) {
	cases := []struct{ in, want string }{
		{`    image: "nginx:1.24"`, `    image: "nginx:1.27"`},
		{`    image: 'nginx:1.24'`, `    image: 'nginx:1.27'`},
		{`    image:    nginx:1.24`, `    image:    nginx:1.27`},
		{"\timage: nginx:1.24", "\timage: nginx:1.27"},
		{`    image: nginx:1.24 # note`, `    image: nginx:1.27 # note`},
	}
	for _, c := range cases {
		out, n := RewriteImageTag(c.in, "nginx", "1.24", "1.27")
		if n != 1 || out != c.want {
			t.Errorf("RewriteImageTag(%q) = %q (%d), want %q", c.in, out, n, c.want)
		}
	}
}

func TestADigestPinIsDroppedNotCarried(t *testing.T) {
	// The pin names the OLD bytes. Carrying it forward produces
	// nginx:1.27@sha256:<1.24's digest>, which either refuses to pull or pulls
	// 1.24 while calling it 1.27 -- the second being the one that ships.
	in := "    image: nginx:1.24@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	out, n := RewriteImageTag(in, "nginx", "1.24", "1.27")
	if n != 1 {
		t.Fatalf("changed %d", n)
	}
	if strings.Contains(out, "@sha256:") {
		t.Errorf("the old digest pin was carried onto the new tag: %q", out)
	}
	if strings.TrimSpace(out) != "image: nginx:1.27" {
		t.Errorf("got %q", out)
	}
}

func TestARegistryPortIsNotMistakenForATag(t *testing.T) {
	// Splitting on the FIRST colon makes the repository "registry.example.com"
	// and the tag "5000/tools/aptly", so nothing ever matches and an internal
	// registry's images are silently never updatable.
	in := "    image: registry.example.com:5000/tools/aptly:1.4"
	out, n := RewriteImageTag(in, "registry.example.com:5000/tools/aptly", "1.4", "1.5")
	if n != 1 {
		t.Fatalf("changed %d: %q", n, out)
	}
	if !strings.Contains(out, "registry.example.com:5000/tools/aptly:1.5") {
		t.Errorf("got %q", out)
	}
}

func TestSeveralServicesOnTheSameImageAllMove(t *testing.T) {
	// A worker and a web container on one image must not be left on two
	// different versions by an update that stopped after the first.
	compose := `services:
  web:
    image: myapp:2.0
  worker:
    image: myapp:2.0
`
	out, n := RewriteImageTag(compose, "myapp", "2.0", "2.1")
	if n != 2 {
		t.Fatalf("changed %d lines, want 2:\n%s", n, out)
	}
	if strings.Contains(out, "myapp:2.0") {
		t.Errorf("one service was left behind:\n%s", out)
	}
}

func TestNonImageKeysAreNotTouched(t *testing.T) {
	compose := `services:
  web:
    x-base-image: nginx:1.24
    command: ["sh", "-c", "echo image: nginx:1.24"]
    labels:
      my.image: nginx:1.24
`
	out, n := RewriteImageTag(compose, "nginx", "1.24", "1.27")
	if n != 0 {
		t.Errorf("rewrote %d non-image lines:\n%s", n, out)
	}
	if out != compose {
		t.Error("the file changed when nothing should have")
	}
}

func TestNoMatchIsReportedAsZero(t *testing.T) {
	// The caller must be able to tell "this stack does not contain what I thought"
	// from "I updated it". Returning the unchanged file with no count would let a
	// rollout deploy an identical file and record an update that never happened.
	compose := "services:\n  web:\n    image: caddy:2\n"
	out, n := RewriteImageTag(compose, "nginx", "1.24", "1.27")
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
	if out != compose {
		t.Error("an unmatched file was modified")
	}
}

func TestEmptyArgumentsChangeNothing(t *testing.T) {
	compose := "services:\n  web:\n    image: nginx:1.24\n"
	for _, c := range [][3]string{{"", "1.24", "1.27"}, {"nginx", "", "1.27"}, {"nginx", "1.24", ""}} {
		out, n := RewriteImageTag(compose, c[0], c[1], c[2])
		if n != 0 || out != compose {
			t.Errorf("RewriteImageTag with %v changed the file", c)
		}
	}
}

func TestAnUntaggedImageIsNotMatched(t *testing.T) {
	// "image: nginx" means nginx:latest to docker, but this function is given an
	// explicit from-tag and must not infer that an untagged reference is it.
	in := "    image: nginx"
	out, n := RewriteImageTag(in, "nginx", "latest", "1.27")
	if n != 0 || out != in {
		t.Errorf("an untagged image was rewritten: %q", out)
	}
}
