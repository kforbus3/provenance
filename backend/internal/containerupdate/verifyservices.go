package containerupdate

import (
	"fmt"
	"strings"
)

// Verifying by SERVICE, because verifying by repository cannot see the case that
// matters most.
//
// verifyScript reads `docker ps` and keeps the lines whose IMAGE STRING matches
// the rollout's repository. A container recreated from an image referenced by
// digest reports its image as a bare `sha256:...`, which matches no repository,
// so it is dropped before a single check runs. It is invisible to every
// assertion that follows -- including "is anything still on the old tag".
//
// That is how a partial update was recorded as verified. `nextcloud-cron` moved
// to 35 and reported `nextcloud:35.0.0-apache`; `nextcloud-nextcloud-1` stayed
// on 34 and reported `sha256:94abf59...`. The check saw one container, found it
// on the target, and passed the host -- with the app and its cron job on
// different major versions of Nextcloud against one data directory.
//
// A deploy knows which services it named. Those are exactly the things that had
// to change, and a compose service can be found by its labels whatever its image
// string says. So ask for them by name.

// serviceReadback appends, to the repository readback, one line per service this
// deploy named.
//
// `ps -q --filter label=` plus `inspect` is the portable subset: both docker and
// podman support them, where a `{{.Label "..."}}` format string is not portable
// between the two.
func serviceReadback(dir string, services []string) string {
	if dir == "" || len(services) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n")
	for _, svc := range services {
		fmt.Fprintf(&b, "_cid=$($_rt ps -aq --filter %s --filter %s 2>/dev/null | head -1)\n",
			shellQuote("label=com.docker.compose.project.working_dir="+dir),
			shellQuote("label=com.docker.compose.service="+svc))
		// A service with no container at all is a failure, not an absence of
		// information: the deploy claimed to bring it up.
		fmt.Fprintf(&b, "if [ -z \"$_cid\" ]; then printf '::SVC::%%s\\t%%s\\t%%s\\n' %s '' absent; else\n",
			shellQuote(svc))
		b.WriteString("  _si=$($_rt inspect --format '{{.Config.Image}}' \"$_cid\" 2>/dev/null)\n")
		b.WriteString("  _ss=$($_rt inspect --format '{{.State.Status}}' \"$_cid\" 2>/dev/null)\n")
		fmt.Fprintf(&b, "  printf '::SVC::%%s\\t%%s\\t%%s\\n' %s \"$_si\" \"$_ss\"\n", shellQuote(svc))
		b.WriteString("fi\n")
	}
	return b.String()
}

// verifiedService is one named service, read back off the host.
type verifiedService struct {
	name  string
	image string
	state string
}

// parseServiceReadback pulls the ::SVC:: lines out of the verify output.
func parseServiceReadback(out string) []verifiedService {
	var got []verifiedService
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "::SVC::")
		if !ok {
			continue
		}
		parts := strings.Split(rest, "\t")
		if len(parts) < 3 {
			continue
		}
		got = append(got, verifiedService{
			name:  strings.TrimSpace(parts[0]),
			image: strings.TrimSpace(parts[1]),
			state: strings.ToLower(strings.TrimSpace(parts[2])),
		})
	}
	return got
}

// checkServices reports the first named service that is not running the target,
// or "" when they all are.
//
// Only meaningful when the tag actually changes. A rebuild republishes the same
// tag, so every service legitimately reports it and the digest comparison
// elsewhere is what separates old bytes from new.
func checkServices(out, repo, fromTag, toTag string) string {
	if fromTag == toTag {
		return ""
	}
	want := repo + ":" + toTag
	for _, s := range parseServiceReadback(out) {
		switch {
		case s.state == "absent" || s.image == "":
			return fmt.Sprintf(
				"deployed, but the service %q has no container on this host — the deploy "+
					"named it and it is not there", s.name)
		case s.image != want:
			// Said in full, because the reason this was ever missed is that the
			// image does not name the repository: an operator reading
			// "still on nextcloud:34" would go looking for a tag that is not
			// what the container reports.
			shown := s.image
			if strings.HasPrefix(shown, "sha256:") {
				shown = shortDigest(shown) + " (an untagged image, so it names no " +
					"repository and every repository-matched check skips it)"
			}
			return fmt.Sprintf(
				"deployed, but the service %q is running %s rather than %s",
				s.name, shown, want)
		case s.state != "running" && s.state != "":
			return fmt.Sprintf(
				"deployed %s to the service %q, but its container is %s rather than "+
					"running — the update did not come up", want, s.name, s.state)
		}
	}
	return ""
}
