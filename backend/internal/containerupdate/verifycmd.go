package containerupdate

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/composefile"
	"github.com/kforbus3/provenance/backend/internal/hostexec"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// A stack's verify command.
//
// Everything else a rollout reads describes the container: its state, its
// healthcheck, its restart count, since 0116 its logs. None of it exercises the
// service. The 2026-10-04 whisper container was running, healthy, unrestarted
// and failing every request, and the only check that would have caught it
// inside the soak is one that sends a request. The operator knows how to do
// that for their service; Provenance does not. So they can say, per stack, and
// the rollout runs it where it already looks: at the soak re-check and on every
// read of the post-rollout watch.

// verifyCommandTimeoutSeconds bounds one run of a verify command. A command that
// hangs -- a request to a service that accepts connections and never answers,
// which is exactly the failure this exists to find -- must come back as a
// failure, not stall the engine's tick.
const verifyCommandTimeoutSeconds = 120

// verifyCommandScript wraps an operator's command so it runs in the stack's
// directory under a timeout, and reports its exit code on a marker line the
// runner's own exit status cannot be trusted to carry.
func verifyCommandScript(dir, command string) string {
	return "cd " + shellQuote(dir) + " 2>/dev/null || true\n" +
		"timeout " + fmt.Sprint(verifyCommandTimeoutSeconds) + " sh -c " + shellQuote(command) + " 2>&1\n" +
		"echo \"::EXIT::$?\"\n"
}

// verifyCommandExit reads the exit code off the marker line, -1 when the script
// never reached it.
func verifyCommandExit(out string) int {
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "::EXIT::"); ok {
			var n int
			if _, err := fmt.Sscanf(rest, "%d", &n); err == nil {
				return n
			}
		}
	}
	return -1
}

// runVerifyCommands runs the verify command of every enabled managed stack on
// the host whose compose file names the repository, and returns why the first
// one failed, or "" when they all passed (or there were none).
//
// Only stacks naming the repository: a host runs many stacks, and a database's
// smoke test failing has nothing to say about an update to the reverse proxy.
func (e *Engine) runVerifyCommands(ctx context.Context, host *models.Host, hostID uuid.UUID, repo string) string {
	stacks, err := e.store.ListStacks(ctx, &hostID)
	if err != nil {
		e.log.Warn("update rollout: could not list stacks for verify commands", "host", hostID, "err", err)
		return ""
	}
	for _, st := range stacks {
		if !st.Enabled || strings.TrimSpace(st.VerifyCommand) == "" || !stackNames(st, repo) {
			continue
		}
		out, _, failed := e.run.RunScript(ctx, hostexec.Privileged(verifyCommandScript(st.Path, st.VerifyCommand)), host)
		code := verifyCommandExit(out)
		switch {
		case failed && code < 0:
			return fmt.Sprintf("stack %s's verify command could not be run on %s: %s",
				st.Name, host.Hostname, trimOutput(out))
		case code == 124:
			return fmt.Sprintf("stack %s's verify command on %s did not finish within %d seconds: %s",
				st.Name, host.Hostname, verifyCommandTimeoutSeconds, trimOutput(stripExit(out)))
		case code != 0:
			return fmt.Sprintf("stack %s's verify command on %s exited %d: %s",
				st.Name, host.Hostname, code, trimOutput(stripExit(out)))
		}
	}
	return ""
}

func stackNames(st store.ContainerStack, repo string) bool {
	for _, ref := range composefile.Images(st.Compose) {
		if ref.Repository == repo {
			return true
		}
	}
	return false
}

func stripExit(out string) string {
	if i := strings.LastIndex(out, "::EXIT::"); i >= 0 {
		return out[:i]
	}
	return out
}
