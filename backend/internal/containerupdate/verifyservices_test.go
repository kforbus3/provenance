package containerupdate

import (
	"strings"
	"testing"
)

// The exact readback the Nextcloud host produced, and which was recorded as
// verified.
//
// `nextcloud-cron` moved to 35 and reports the tag. The APP stayed on 34 and
// reports a bare digest, because it had been recreated from an untagged image.
// Every repository-matched check drops that line before looking at it, so the
// only container the old verification saw was the one that HAD moved.
const nextcloudReadback = "::OK::\n" +
	"nextcloud:35.0.0-apache\tnextcloud-nextcloud-cron-1\trunning\tnextcloud@sha256:new\n" +
	"::SVC::nextcloud\tsha256:94abf59f8e799025ee10b315b8419270f09e73cf410a54c0812debfc4aefefa7\trunning\n" +
	"::SVC::nextcloud-cron\tnextcloud:35.0.0-apache\trunning\n"

func TestAnUntaggedContainerNoLongerPassesVerification(t *testing.T) {
	why := checkServices(nextcloudReadback, "nextcloud", "34.0.4-apache", "35.0.0-apache")
	if why == "" {
		t.Fatal("the app service still passes verification while running the old image — " +
			"this is the exact state that was recorded as verified")
	}
	if !strings.Contains(why, "nextcloud") {
		t.Errorf("the failure does not name the service: %s", why)
	}
	// It must say WHY the image is unreadable, or an operator goes looking for a
	// tag the container does not report.
	if !strings.Contains(why, "untagged") {
		t.Errorf("the failure does not explain that the image is untagged, which is the "+
			"whole reason it was skipped: %s", why)
	}
	if !strings.Contains(why, "35.0.0-apache") {
		t.Errorf("the failure does not say what was wanted: %s", why)
	}
}

// The good case has to pass, or every rollout stops.
func TestServicesOnTheTargetPass(t *testing.T) {
	out := "::OK::\n" +
		"::SVC::nextcloud\tnextcloud:35.0.0-apache\trunning\n" +
		"::SVC::nextcloud-cron\tnextcloud:35.0.0-apache\trunning\n"
	if why := checkServices(out, "nextcloud", "34.0.4-apache", "35.0.0-apache"); why != "" {
		t.Errorf("a correct deploy was failed: %s", why)
	}
}

// A service the deploy named and that has no container is a failure: the deploy
// claimed to bring it up.
func TestAnAbsentServiceFails(t *testing.T) {
	out := "::OK::\n::SVC::nextcloud\t\tabsent\n"
	why := checkServices(out, "nextcloud", "34.0.4-apache", "35.0.0-apache")
	if why == "" || !strings.Contains(why, "no container") {
		t.Errorf("an absent service passed verification: %q", why)
	}
}

// Running the right image is not the same as running.
func TestAServiceOnTheTargetButNotRunningFails(t *testing.T) {
	out := "::OK::\n::SVC::nextcloud\tnextcloud:35.0.0-apache\trestarting\n"
	why := checkServices(out, "nextcloud", "34.0.4-apache", "35.0.0-apache")
	if why == "" || !strings.Contains(why, "restarting") {
		t.Errorf("a crash-looping service passed verification: %q", why)
	}
}

// A rebuild republishes the same tag, so every service legitimately reports it;
// the digest comparison elsewhere is what separates old bytes from new. This
// check must stay out of the way there.
func TestARebuildIsNotJudgedByTag(t *testing.T) {
	out := "::OK::\n::SVC::web\tnginx:1.27\trunning\n"
	if why := checkServices(out, "nginx", "1.27", "1.27"); why != "" {
		t.Errorf("a rebuild was failed by the tag check: %s", why)
	}
}

// Nothing named means nothing to assert -- a whole-project deploy must behave as
// it did before.
func TestNoNamedServicesIsNotAFailure(t *testing.T) {
	if why := checkServices("::OK::\n", "nginx", "1.24", "1.27"); why != "" {
		t.Errorf("a deploy that named no services was failed: %s", why)
	}
	if got := serviceReadback("", nil); got != "" {
		t.Errorf("a script fragment was emitted for no services: %q", got)
	}
	if got := serviceReadback("/opt/x", nil); got != "" {
		t.Errorf("a script fragment was emitted for no services: %q", got)
	}
}

// The script has to ask by compose label, and quote what it interpolates.
func TestTheServiceReadbackAsksByLabelAndQuotes(t *testing.T) {
	got := serviceReadback("/opt/stacks/nextcloud", []string{"nextcloud", "nextcloud-cron"})
	for _, want := range []string{
		"com.docker.compose.project.working_dir=/opt/stacks/nextcloud",
		"com.docker.compose.service=nextcloud",
		"com.docker.compose.service=nextcloud-cron",
		"::SVC::",
		"{{.Config.Image}}",
		"{{.State.Status}}",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the readback script is missing %q:\n%s", want, got)
		}
	}
	// A hostile service name must not break out of the command.
	hostile := serviceReadback("/opt/x", []string{"web'; rm -rf /; '"})
	if strings.Contains(hostile, "rm -rf /;") && !strings.Contains(hostile, `'\''`) {
		t.Errorf("a service name was interpolated unquoted:\n%s", hostile)
	}
}
