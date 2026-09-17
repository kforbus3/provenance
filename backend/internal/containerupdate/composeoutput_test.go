package containerupdate

import (
	"strings"
	"testing"
)

// The real output keith was shown, verbatim, for the Keycloak rollout that took
// its database down. Everything that matters is the last clause and it is the
// least visible part of the message.
const keycloakFailure = `quay.io/keycloak/keycloak:26.7.3 → 26.7.4: …6.3MB
 b021fe485c81 Pull complete
 dcee140b22ee Extracting [==================================================>]     546B/546B
 dcee140b22ee Extracting [==================================================>]     546B/546B
 dcee140b22ee Pull complete
 keycloak Pulled
 Container keycloak-db  Recreate
 Container keycloak-db  Recreated
 Container keycloak  Recreate
 Container keycloak  Recreated
 Container keycloak-db  Starting
 Container keycloak-db  Started
 Container keycloak-db  Waiting
 Container keycloak-db  Error
dependency failed to start: container keycloak-db is unhealthy

[exit code 1]`

func TestTheCauseIsReportedNotThePullTranscript(t *testing.T) {
	got := explainCompose(keycloakFailure)

	// The first line must be the diagnosis.
	first := strings.SplitN(got, "\n", 2)[0]
	if !strings.Contains(first, "dependency failed to start") ||
		!strings.Contains(first, "keycloak-db") {
		t.Errorf("the message does not lead with the cause; it leads with:\n%s", first)
	}
	// And not with a progress bar, which is what it used to lead with.
	for _, noise := range []string{"Extracting", "Pull complete", "[=", "546B"} {
		if strings.Contains(first, noise) {
			t.Errorf("the first line still carries pull noise (%q):\n%s", noise, first)
		}
	}
	// The transcript is kept, because the cause is not always enough.
	if !strings.Contains(got, "full output:") {
		t.Error("the transcript was dropped entirely")
	}
}

// "Container keycloak-db Error" also matches a marker, and reporting THAT
// instead sends the operator to look at a container without saying what about
// it was wrong. The specific phrase has to win over the generic one.
func TestTheMostSpecificCauseWins(t *testing.T) {
	cause := composeCause(keycloakFailure)
	if cause != "dependency failed to start: container keycloak-db is unhealthy" {
		t.Errorf("cause = %q, want the dependency line", cause)
	}
}

func TestCausesAreFoundAcrossTheCommonFailures(t *testing.T) {
	cases := []struct{ out, want string }{
		{"foo Pulling\nError response from daemon: no such image: x\n", "Error response from daemon"},
		{"web Pulling\n b1 Pull complete\nno such service: wibble\n", "no such service"},
		{" x Extracting [===>]\nunauthorized: authentication required\n", "unauthorized:"},
		{"a Pulling\nmanifest unknown: manifest unknown\n", "manifest unknown"},
		{"db Waiting\nport is already allocated\n", "port is already allocated"},
	}
	for _, c := range cases {
		got := composeCause(c.out)
		if !strings.Contains(got, c.want) {
			t.Errorf("composeCause(%q) = %q, want it to contain %q", c.out, got, c.want)
		}
	}
}

// A pull line IS the cause when the pull is what failed, so the noise filter
// must not swallow it.
func TestAFailedPullIsNotTreatedAsNoise(t *testing.T) {
	out := "nextcloud Pulling\nnextcloud Error manifest for nextcloud:99 not found\n"
	if got := composeCause(out); !strings.Contains(got, "manifest for") {
		t.Errorf("a failed pull was filtered out as progress noise: %q", got)
	}
}

// Output with nothing recognisable must still be reported, not swallowed.
func TestUnrecognisedOutputIsStillShown(t *testing.T) {
	out := "something went sideways in a way nobody anticipated"
	if got := explainCompose(out); !strings.Contains(got, "sideways") {
		t.Errorf("unrecognised output was dropped: %q", got)
	}
}

// Success-shaped output has no cause to report.
func TestCleanOutputHasNoCause(t *testing.T) {
	out := " web Pulling\n b1 Pull complete\n web Pulled\n Container web  Recreated\n Container web  Started\n"
	if got := composeCause(out); got != "" {
		t.Errorf("composeCause found a cause in a successful deploy: %q", got)
	}
}
