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
