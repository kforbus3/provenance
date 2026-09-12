package containerupdate

import (
	"fmt"
	"strings"
)

// Adopting a host's existing compose file so a version bump can be applied.
//
// A rebuild needs no file changed, so it goes through inplace.go. A version bump
// is written INTO the compose file, and something has to edit it. Requiring an
// operator to copy that file into Provenance by hand first is the kind of chore
// that leaves the feature unused -- which is precisely how the bot-and-merge-
// request arrangement this replaces came to be ignored.
//
// So it is read off the host and adopted, and from then on it is a stack like
// any other: the edit is a revision with an author and a note, it is visible in
// the history, and it can be rolled back.
//
// The file is left where it is. Adoption records what is already there; it does
// not move anything or change what the host is running.

// composeFilename is the only name that can be adopted.
//
// The stack deploy writes <dir>/docker-compose.yml. Adopting a project whose
// file is called something else would leave the original in place AND write a
// second one beside it, and compose would then pick up whichever its own rules
// prefer -- which may not be the one just edited. Refusing is the honest answer;
// silently creating a second compose file in somebody's directory is not.
const composeFilename = "docker-compose.yml"

// adoptScript prints the compose file to adopt, or says why it cannot.
func adoptScript(dir string) string {
	var b strings.Builder
	b.WriteString("set -eu\n")
	// Missing and unreadable are asked about SEPARATELY. A failed `cd` is
	// indistinguishable from a missing directory, and reporting "that directory is
	// not there" about one that plainly is sends an operator looking for the wrong
	// problem — which it did, for a compose file sitting exactly where it was
	// expected under a home directory this account could not traverse.
	fmt.Fprintf(&b, "[ -d %s ] || { echo '::NODIR::'; exit 0; }\n", shellQuote(dir))
	fmt.Fprintf(&b, "cd %s 2>/dev/null || { echo '::NOACCESS::'; exit 0; }\n", shellQuote(dir))
	// Report what IS there when the expected name is missing, so the message can
	// name the file rather than say "not found" about a directory full of them.
	b.WriteString("if [ ! -f " + shellQuote(composeFilename) + " ]; then\n")
	b.WriteString("  echo '::NOFILE::'\n")
	b.WriteString("  ls -1 2>/dev/null | grep -iE '^(docker-)?compose\\.ya?ml$' || true\n")
	b.WriteString("  exit 0\n")
	b.WriteString("fi\n")
	// Markers on BOTH sides, and the file verbatim between them. Not base64: the
	// content has to be reviewable in the revision history, and an encoding step
	// is one more place for it to arrive subtly different from what is on disk.
	//
	// The closing marker is not decoration. Everything this runs through appends
	// its own trailing line -- the command runner ends every result with
	// "[exit code N]" -- and taking "everything after the opening marker" as the
	// file swallowed that into the compose content. It was then written to the
	// host, where it is not YAML:
	//
	//	qdrant_data:
	//
	//	[exit code 0]
	//	  go-yaml: could not find expected ':'
	//
	// Bounded on both sides, anything appended afterwards is ignored by
	// construction rather than by remembering to strip it.
	b.WriteString("echo '::COMPOSE::'\n")
	b.WriteString("cat " + shellQuote(composeFilename) + "\n")
	b.WriteString("echo '::ENDCOMPOSE::'\n")
	return b.String()
}

// parseAdopt returns the compose text, or the reason there is none.
func parseAdopt(dir, out string) (string, error) {
	if i := strings.Index(out, "::COMPOSE::"); i >= 0 {
		body := out[i+len("::COMPOSE::"):]
		body = strings.TrimPrefix(body, "\r\n")
		body = strings.TrimPrefix(body, "\n")
		// Everything up to the closing marker, verbatim. `cat` emits the file's
		// bytes and the closing `echo` starts wherever cat left off, so the text
		// before the marker IS the file -- whether or not it ended with a newline.
		end := strings.Index(body, "::ENDCOMPOSE::")
		if end < 0 {
			return "", fmt.Errorf(
				"the compose file at %s/%s was read but not completely — the output "+
					"was truncated", dir, composeFilename)
		}
		body = body[:end]
		if strings.TrimSpace(body) == "" {
			return "", fmt.Errorf("the compose file at %s/%s is empty", dir, composeFilename)
		}
		return body, nil
	}
	if strings.Contains(out, "::NODIR::") {
		return "", fmt.Errorf(
			"this container's compose project is recorded at %s, but that directory is "+
				"not there — it was probably deployed from somewhere else", dir)
	}
	if strings.Contains(out, "::NOACCESS::") {
		return "", fmt.Errorf(
			"%s exists but could not be read, even with sudo. Check that this host's "+
				"Provenance account has passwordless sudo, or that the directory is "+
				"reachable by it", dir)
	}
	if strings.Contains(out, "::NOFILE::") {
		others := []string{}
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "::") && line != composeFilename {
				others = append(others, line)
			}
		}
		if len(others) > 0 {
			return "", fmt.Errorf(
				"the compose project at %s is called %s, not %s. Provenance writes %s when "+
					"it deploys, so adopting this one would leave two compose files in that "+
					"directory — rename it, or add it as a stack yourself",
				dir, strings.Join(others, " and "), composeFilename, composeFilename)
		}
		return "", fmt.Errorf("no %s in %s", composeFilename, dir)
	}
	return "", fmt.Errorf("could not read the compose file at %s: %s", dir, trimOutput(out))
}
