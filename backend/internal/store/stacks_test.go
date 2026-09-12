package store

import "testing"

// A stack name becomes a directory on a host, interpolated into a path that a
// privileged shell then writes to.
//
// So this is not a naming-convention check. A name containing a slash, a null, or
// "…/.." is a write to somewhere the operator did not choose, and the validation
// running here — before it ever reaches the database — is what keeps the path
// construction downstream honest.
func TestValidStackName(t *testing.T) {
	good := []string{"nextcloud", "media-stack", "app_1", "a", "grafana.prod", repeat("a", 64)}
	for _, n := range good {
		if !ValidStackName(n) {
			t.Errorf("should accept %q", n)
		}
	}

	bad := map[string]string{
		"":              "empty",
		".":             "the current directory",
		"..":            "the parent directory",
		"../etc":        "escapes the stack root",
		"a/b":           "a separator makes it a different directory",
		`a\b`:           "a Windows separator, for a host that may honour it",
		".hidden":       "a leading dot hides it from the operator looking for it",
		"a:b":           "a colon is a path separator in some tools and a drive in others",
		"a b":           "a space survives quoting but reads as two arguments everywhere else",
		"a;rm -rf /":    "shell metacharacters",
		"a$(id)":        "command substitution",
		"a\x00b":        "a null truncates the path in anything written in C",
		repeat("a", 65): "longer than a sensible directory name",
	}
	for n, why := range bad {
		if ValidStackName(n) {
			t.Errorf("should reject %q — %s", n, why)
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = s[0]
	}
	return string(out)
}

// A stack's path is where a privileged deploy WRITES. Getting it wrong does not
// fail loudly — it creates a new directory, writes the compose file into it, and
// leaves behind every file the project needs that Provenance does not manage.
//
// That is not hypothetical. The compose editor sends the text and no path; the
// server read that silence as a choice and moved media-stack from
// /home/keith/media-stack to /opt/stacks/media-stack. The next rollout wrote
// there, found no .env, and told the operator their compose file was invalid
// when the file on the host was fine.
func TestResolveStackPath(t *testing.T) {
	cases := []struct {
		name           string
		in, prev, want string
		why            string
	}{
		{
			name: "editor save keeps the adopted path",
			in:   "", prev: "/home/keith/media-stack", want: "/home/keith/media-stack",
			why: "the editor sends no path; that is silence, not a request to relocate",
		},
		{
			name: "blank-padded input is still silence",
			in:   "   ", prev: "/home/keith/media-stack", want: "/home/keith/media-stack",
			why: "whitespace from a text field must not read as a new location",
		},
		{
			name: "a new stack gets the default",
			in:   "", prev: "", want: stackRoot + "/media-stack",
			why: "creation has no stored path to keep, so something has to be chosen",
		},
		{
			name: "an explicit path wins",
			in:   "/srv/media-stack", prev: "/home/keith/media-stack", want: "/srv/media-stack",
			why: "an operator who names a directory means it",
		},
		{
			name: "an explicit path wins on create too",
			in:   "/srv/media-stack", prev: "", want: "/srv/media-stack",
			why: "adoption passes the discovered directory on the first save",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveStackPath(c.in, c.prev, "media-stack"); got != c.want {
				t.Errorf("resolveStackPath(%q, %q) = %q, want %q — %s",
					c.in, c.prev, got, c.want, c.why)
			}
		})
	}
}
