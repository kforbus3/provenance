package containerupdate

import "strings"

// Reading a compose failure back to an operator.
//
// A failed deploy's output is mostly a pull transcript: layer ids, percentages,
// "Extracting", "Pull complete". The operative line -- the one naming what
// actually went wrong -- is a single sentence somewhere in it, and keeping the
// last 600 characters is as likely to catch progress bars as the cause. What an
// operator got for a Keycloak rollout that took its database down was:
//
//	…6.3MB b021fe485c81 Pull complete dcee140b22ee Extracting [====>] 546B/546B
//	dcee140b22ee Pull complete keycloak Pulled Container keycloak-db Recreate
//	Container keycloak-db Recreated … dependency failed to start: container
//	keycloak-db is unhealthy [exit code 1]
//
// Everything that matters is the last clause, and it is the least visible part.
// So: say the cause first, and keep the transcript after it for anyone who wants
// it.

// causeMarkers are the phrases that name a real failure, most specific first.
//
// Ordered because more than one can appear: "dependency failed to start" is
// worth more than the generic "Error" that accompanies it, and reporting the
// generic one sends the operator looking at the wrong container.
var causeMarkers = []string{
	"dependency failed to start",
	"Error response from daemon",
	"no such service",
	"unknown flag",
	"manifest unknown",
	"manifest for",
	"pull access denied",
	"unauthorized:",
	"network not found",
	"port is already allocated",
	"no space left on device",
	"failed to solve",
	"exited with code",
	"unhealthy",
	"cannot start service",
	"invalid compose",
	"yaml:",
	"permission denied",
}

// progressPrefixes mark a line as pull-transcript noise.
var progressWords = []string{
	"Pulling", "Pull complete", "Extracting", "Downloading", "Download complete",
	"Already exists", "Verifying Checksum", "Waiting", "Pulled", "Pulling fs layer",
}

// composeCause returns the line that names the failure, or "" when nothing in
// the output looks like one.
//
// Scanned from the END: a deploy can survive one complaint and fail on a later
// one, and the last thing that went wrong is the thing that stopped it.
func composeCause(out string) string {
	lines := strings.Split(out, "\n")
	best, bestRank := "", len(causeMarkers)
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" || isProgressNoise(line) {
			continue
		}
		for rank, marker := range causeMarkers {
			if rank > bestRank {
				break // a worse marker than one already found
			}
			if strings.Contains(line, marker) {
				// A later line wins only if its marker is at least as specific.
				if rank <= bestRank {
					best, bestRank = line, rank
				}
				break
			}
		}
	}
	return best
}

// isProgressNoise reports a line that carries no diagnosis.
//
// Progress lines are recognised by their WORDS rather than by a bar or a
// percentage: compose collapses them when not on a terminal, so the bar is often
// absent and the words are not.
func isProgressNoise(line string) bool {
	if strings.Contains(line, "[=") || strings.Contains(line, "[>") {
		return true
	}
	for _, w := range progressWords {
		if strings.Contains(line, w) {
			// "manifest unknown" arrives on a Pulling line, and that IS a cause.
			for _, marker := range causeMarkers {
				if strings.Contains(line, marker) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// explainCompose puts the cause first and the transcript second.
//
// Both, not just the cause: the cause is what an operator acts on, and the
// transcript is what they need when the cause is not enough. Dropping the
// transcript would trade one kind of unreadable message for another.
func explainCompose(out string) string {
	cause := composeCause(out)
	rest := trimOutput(out)
	if cause == "" {
		return rest
	}
	if strings.TrimSpace(rest) == cause {
		return cause
	}
	return cause + "\n\nfull output: " + rest
}
