package appsupport

import (
	"strings"
	"testing"
)

// A support bundle exists to be SENT somewhere — a ticket, an email, a chat.
// Whatever it contains has left the building, and nobody reads one closely
// enough to notice a password in it. These are the shapes that must not survive.
func TestScrubRemovesCredentialShapedText(t *testing.T) {
	cases := []struct {
		name, in, mustNotContain string
		mustContain              string
	}{
		{
			"an env-style secret",
			`FLEET_AUDIT_HMAC_KEY=9f8a7b6c5d4e3f2a1b0c`,
			"9f8a7b6c5d4e3f2a1b0c",
			// The KEY survives: "which setting is set" is the diagnostic half.
			"FLEET_AUDIT_HMAC_KEY",
		},
		{
			"a logged password field",
			`level=info msg="login" password: hunter2 user=alice`,
			"hunter2",
			"user=alice",
		},
		{
			"a database URL with inline credentials",
			`postgres://fleet:s3cr3t@db:5432/fleet`,
			"s3cr3t",
			// Scheme, user and host survive — which database it is, is the point.
			"postgres://fleet:",
		},
		{
			"an updater token header",
			`X-Updater-Token: abcdef123456`,
			"abcdef123456",
			"X-Updater-Token",
		},
		{
			"a bearer JWT",
			`Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
			"dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			"Authorization",
		},
		{
			"a private key block",
			"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
			"b3BlbnNzaC1rZXktdjEAAAAA",
			"PRIVATE KEY",
		},
		{
			"an api key with a dashed name",
			`grype-api-key = "sk-live-9999"`,
			"sk-live-9999",
			"grype-api-key",
		},
	}
	for _, c := range cases {
		got := Scrub(c.in)
		if strings.Contains(got, c.mustNotContain) {
			t.Errorf("%s: the secret survived scrubbing\n  in:  %s\n  out: %s",
				c.name, c.in, got)
		}
		if c.mustContain != "" && !strings.Contains(got, c.mustContain) {
			t.Errorf("%s: scrubbing removed the diagnostic part too\n  out: %s\n  want it to contain %q",
				c.name, got, c.mustContain)
		}
		if !strings.Contains(got, redacted) {
			t.Errorf("%s: nothing was marked as redacted, so a reader cannot tell "+
				"something was removed:\n  %s", c.name, got)
		}
	}
}

func TestScrubLeavesOrdinaryDiagnosticsAlone(t *testing.T) {
	// Over-redaction has a cost too: a bundle where every line says [REDACTED]
	// is one nobody can troubleshoot from.
	lines := []string{
		`level=error msg="container image check" checked=3 failed=10`,
		`upgrade to 1.2.14 completed in 58s`,
		`host docker: containers_status=no_access`,
		`GET /api/v1/hosts 200 in 14ms`,
		`postgres: connection pool 8/20 in use`,
	}
	for _, l := range lines {
		if got := Scrub(l); got != l {
			t.Errorf("an ordinary log line was altered:\n  in:  %s\n  out: %s", l, got)
		}
	}
}

func TestSetReportsPresenceNotValue(t *testing.T) {
	// The diagnostic question about a secret is almost always "is it set" — an
	// audit key that is EMPTY explains a class of symptom; its bytes explain
	// nothing.
	if got := Set("a-real-secret-value"); got != "set" {
		t.Errorf("got %q", got)
	}
	if strings.Contains(Set("a-real-secret-value"), "a-real-secret") {
		t.Error("Set leaked the value it was asked about")
	}
	if got := Set("   "); got != "not set" {
		t.Errorf("whitespace should read as not set, got %q", got)
	}
}
