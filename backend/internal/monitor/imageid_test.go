package monitor

import "testing"

// An image with no repository tags must not become a repository called "sha256".
//
// Seen in production at the top of the Updates page:
//
//	repository            tag
//	sha256                60b1fa07833c70ab67b7f8c0289bbaf780e7bcbf51f0ce1072be69ab1994d76b
//
// A permanent, unanswerable row: nothing can ask a registry whether there is a
// newer sha256:60b1fa07… than sha256:60b1fa07…. It appears whenever an image's
// tag is removed or reused, which rebuilding a local image does routinely.
func TestABareImageIDIsNotARepository(t *testing.T) {
	const id = "sha256:60b1fa07833c70ab67b7f8c0289bbaf780e7bcbf51f0ce1072be69ab1994d76b"
	repo, tag := splitImageRef(id)
	if repo != "" || tag != "" {
		t.Errorf("splitImageRef(%q) = (%q, %q), want empty/empty so registry checks "+
			"and rollouts skip it", id, repo, tag)
	}
	// The digest without the algorithm prefix, which some runtimes report.
	repo, tag = splitImageRef(id[len("sha256:"):])
	if repo != "" || tag != "" {
		t.Errorf("a bare digest parsed as (%q, %q)", repo, tag)
	}
}

// And the ordinary cases still work, including the ones the ID check must not
// swallow.
func TestRealReferencesStillParse(t *testing.T) {
	cases := []struct{ ref, repo, tag string }{
		{"nginx:1.31-alpine", "nginx", "1.31-alpine"},
		{"nginx", "nginx", "latest"},
		{"registry.example.com:5000/app:v2", "registry.example.com:5000/app", "v2"},
		{"ghcr.io/linuxserver/faster-whisper:gpu-v3.8.1-ls66",
			"ghcr.io/linuxserver/faster-whisper", "gpu-v3.8.1-ls66"},
		{"postgres@sha256:60b1fa07833c70ab67b7f8c0289bbaf780e7bcbf51f0ce1072be69ab1994d76b",
			"postgres", "latest"},
		// A repository that merely LOOKS hexadecimal, and a tag of the right
		// length: neither is an image ID.
		{"abcdef/beef:cafe", "abcdef/beef", "cafe"},
	}
	for _, c := range cases {
		repo, tag := splitImageRef(c.ref)
		if repo != c.repo || tag != c.tag {
			t.Errorf("splitImageRef(%q) = (%q, %q), want (%q, %q)", c.ref, repo, tag, c.repo, c.tag)
		}
	}
}
