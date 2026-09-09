package playbook

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Working out which hosts a failed run actually failed on.
//
// The failure notification used to name every host the run TARGETED and give
// ansible's exit code as the reason:
//
//	A playbook run against ai, coder, containers, debian, docker, gitlab,
//	grafana, imager, mcp, prometheus, python, repo, tvadblocker failed:
//	ansible-playbook exited 2
//
// Thirteen hosts named, twelve of them fine, and nothing to say which one was
// the problem — so the only way to learn anything from the alert was to open
// the run and read to the bottom of several hundred lines of output. An alert
// that cannot be acted on without opening something else is barely an alert.
//
// Ansible already computes exactly what is wanted, in the PLAY RECAP it prints
// at the end of every run:
//
//	imager    : ok=0  changed=0  unreachable=1  failed=0  skipped=0 ...
//	repo      : ok=2  changed=1  unreachable=0  failed=0  skipped=0 ...
//
// So parse that rather than inferring anything. The recap is per-host and
// authoritative — it is ansible's own account of what happened, and it
// distinguishes a host that could not be reached from one whose tasks failed,
// which are different problems with different fixes.

// hostOutcome is one host's line from the PLAY RECAP.
type hostOutcome struct {
	Host        string
	OK          int
	Changed     int
	Unreachable int
	Failed      int
}

// bad reports whether this host is a reason the run failed.
//
// Only unreachable and failed count. A host with rescued>0 had a task fail and
// a rescue block handle it, which is the playbook working as written; ignored
// likewise. Counting either would report failures the author deliberately
// handled.
func (h hostOutcome) bad() bool { return h.Unreachable > 0 || h.Failed > 0 }

// reason says what went wrong in a few words, keeping "could not be reached"
// distinct from "ran and failed". They look the same in a summary count and
// they are not: one is usually a host that is off or moved, the other is
// usually the playbook or the machine's state.
func (h hostOutcome) reason() string {
	switch {
	case h.Unreachable > 0 && h.Failed > 0:
		return "unreachable, and failed tasks"
	case h.Unreachable > 0:
		return "unreachable"
	case h.Failed == 1:
		return "1 task failed"
	default:
		return fmt.Sprintf("%d tasks failed", h.Failed)
	}
}

// ansiRE strips terminal colour codes. The runner is not asked for colour, but
// ansible turns it on by itself in some configurations, and a stray escape
// sequence would otherwise become part of a hostname and of an email subject.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// recapLineRE matches one host line of a PLAY RECAP. The counts after failed=
// vary by ansible version (skipped/rescued/ignored arrived at different times),
// so only the four that have always been there are required.
var recapLineRE = regexp.MustCompile(
	`^(\S+)\s*:\s*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)`)

// parseRecap returns the per-host outcomes from a run's output.
//
// Returns nil when there is no recap, which is a real and different case: a run
// that failed before ansible got as far as printing one — a syntax error, an
// unreachable runner, a timeout that killed it mid-play. Callers must not read
// "no bad hosts" as "no hosts had problems"; nil means "unknown", and saying so
// is more useful than a confident wrong summary.
func parseRecap(output string) []hostOutcome {
	clean := ansiRE.ReplaceAllString(output, "")
	lines := strings.Split(clean, "\n")

	// Scan from the last PLAY RECAP header. A run of several plays prints one
	// recap at the end, but a run that was retried, or output that has been
	// concatenated, can contain more than one — and the last is the current one.
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "PLAY RECAP") {
			start = i + 1
		}
	}
	if start < 0 {
		return nil
	}

	var out []hostOutcome
	for _, l := range lines[start:] {
		m := recapLineRE.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		n := func(s string) int { v, _ := strconv.Atoi(s); return v }
		out = append(out, hostOutcome{
			Host: m[1], OK: n(m[2]), Changed: n(m[3]),
			Unreachable: n(m[4]), Failed: n(m[5]),
		})
	}
	return out
}

// maxNamedHosts bounds how many hosts are named in one alert. A rollout of a
// broken change can fail on every host in a large fleet, and an email listing
// six hundred names is the same unreadable wall this is meant to replace.
const maxNamedHosts = 8

// failureSummary describes a failed run in one line: which hosts failed, why,
// and how many were fine.
//
// targets is the list the run was aimed at, used only when there is no recap to
// read — in which case the honest answer is that nothing is known about
// individual hosts, not a guess dressed up as a finding.
func failureSummary(output string, targets []string, errMsg string) string {
	recap := parseRecap(output)
	if recap == nil {
		if len(targets) == 0 {
			return errMsg
		}
		return fmt.Sprintf("%s. The run produced no play recap, so it failed before "+
			"reaching individual hosts; it was aimed at %s.",
			errMsg, joinCapped(targets, maxNamedHosts))
	}

	var bad []hostOutcome
	for _, h := range recap {
		if h.bad() {
			bad = append(bad, h)
		}
	}

	// Failed with a recap in which every host is clean. Rare but real: a task
	// failed on the controller, a handler failed after the recap, or ansible
	// exited non-zero for a reason that is not per-host. Say that, rather than
	// reporting "0 hosts failed" and leaving it looking like a false alarm.
	if len(bad) == 0 {
		return fmt.Sprintf("%s, but every host in the play recap succeeded (%d "+
			"host%s). The failure was not specific to a host.",
			errMsg, len(recap), plural(len(recap)))
	}

	parts := make([]string, 0, len(bad))
	for _, h := range bad {
		parts = append(parts, fmt.Sprintf("%s (%s)", h.Host, h.reason()))
	}

	okCount := len(recap) - len(bad)
	summary := fmt.Sprintf("Failed on %s", joinCapped(parts, maxNamedHosts))
	if okCount > 0 {
		summary += fmt.Sprintf(". The other %d host%s succeeded", okCount, plural(okCount))
	}
	return summary + "."
}

// failureTitle is the alert's subject line, so it carries the single most
// useful fact: which playbook, and which host. The old title was "Playbook run
// failed" for every failure of every playbook, which made a mailbox of them
// indistinguishable from each other.
func failureTitle(playbookName, output string) string {
	name := playbookName
	if name == "" {
		name = "Playbook run"
	} else {
		name = fmt.Sprintf("Playbook %q", name)
	}

	var bad []string
	for _, h := range parseRecap(output) {
		if h.bad() {
			bad = append(bad, h.Host)
		}
	}
	switch {
	case len(bad) == 0:
		return name + " failed"
	case len(bad) <= 3:
		return fmt.Sprintf("%s failed on %s", name, strings.Join(bad, ", "))
	default:
		return fmt.Sprintf("%s failed on %d hosts", name, len(bad))
	}
}

func joinCapped(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:max], ", "), len(items)-max)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
