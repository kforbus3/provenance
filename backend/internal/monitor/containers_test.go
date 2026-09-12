package monitor

import "testing"

// "Nothing is running" and "we were not allowed to look" must never render the
// same.
//
// Docker's socket is root-owned and every monitor probe runs WITHOUT sudo, so on
// a host whose monitor account is not in the docker group `docker ps` fails with
// a permission error. An empty list there would report a clean host — on exactly
// the machines carrying the most software, and in a product whose entire job is
// telling you what is on your fleet.
//
// This is the same failure that has cost this project real time in other forms: a
// silent empty result that looks like a good answer.
func TestParseContainersDistinguishesEmptyFromUnasked(t *testing.T) {
	cases := []struct {
		name, out, wantStatus string
		wantN                 int
	}{
		{"no runtime installed", "::NORUNTIME::\n", ContainersNoDocker, 0},
		{"installed but not permitted", "::NOACCESS::\n", ContainersNoAccess, 0},
		{"asked, and genuinely nothing running", "::OK::\n::IMAGES::\n", ContainersOK, 0},
		{"script did not run at all", "", ContainersUnreachable, 0},
		{"garbage with no marker", "bash: docker: command not found\n", ContainersUnreachable, 0},
	}
	for _, c := range cases {
		got, status := parseContainers(c.out)
		if status != c.wantStatus {
			t.Errorf("%s: status = %q, want %q", c.name, status, c.wantStatus)
		}
		if len(got) != c.wantN {
			t.Errorf("%s: %d containers, want %d", c.name, len(got), c.wantN)
		}
	}
}

func TestParseContainers(t *testing.T) {
	out := "::OK::\n" +
		"abc123def456789\tnextcloud\tnextcloud:29-apache\trunning\tUp 3 days\t0.0.0.0:8080->80/tcp\n" +
		"beef00112233445\tgluetun\tqmcgaw/gluetun:latest\trunning\tUp 2 weeks\t\n" +
		"::IMAGES::\n" +
		"nextcloud:29-apache\tnextcloud@sha256:aaaa\n" +
		"qmcgaw/gluetun:latest\tqmcgaw/gluetun@sha256:bbbb\n"

	got, status := parseContainers(out)
	if status != ContainersOK {
		t.Fatalf("status = %q", status)
	}
	if len(got) != 2 {
		t.Fatalf("got %d containers, want 2", len(got))
	}

	// The id is trimmed to what an operator sees in their own `docker ps`.
	if got[0].ID != "abc123def456" {
		t.Errorf("id = %q, want the 12-char form", got[0].ID)
	}
	if got[0].Name != "nextcloud" || got[0].State != "running" {
		t.Errorf("unexpected: %+v", got[0])
	}
	// The digest is the point of collecting this at all: a tag moves, so
	// "nextcloud:29-apache" does not say which one is running.
	if got[0].Digest != "sha256:aaaa" {
		t.Errorf("digest = %q, want the resolved digest", got[0].Digest)
	}
	if got[1].Digest != "sha256:bbbb" {
		t.Errorf("digest = %q", got[1].Digest)
	}
}

// A registry with a port is the case that breaks the obvious implementation.
func TestSplitImageRef(t *testing.T) {
	for _, c := range []struct{ ref, repo, tag string }{
		{"nginx", "nginx", "latest"},
		{"nginx:1.25", "nginx", "1.25"},
		{"qmcgaw/gluetun:latest", "qmcgaw/gluetun", "latest"},
		{"ghcr.io/owner/app:v2", "ghcr.io/owner/app", "v2"},
		// Splitting on the FIRST colon gives repo "registry.example.com" and tag
		// "5000/app" — wrong, and nobody notices until it is their registry.
		{"registry.example.com:5000/app", "registry.example.com:5000/app", "latest"},
		{"registry.example.com:5000/app:1.4", "registry.example.com:5000/app", "1.4"},
		// A digest-pinned reference carries no tag.
		{"nginx@sha256:abcd", "nginx", "latest"},
	} {
		repo, tag := splitImageRef(c.ref)
		if repo != c.repo || tag != c.tag {
			t.Errorf("splitImageRef(%q) = (%q, %q), want (%q, %q)", c.ref, repo, tag, c.repo, c.tag)
		}
	}
}
