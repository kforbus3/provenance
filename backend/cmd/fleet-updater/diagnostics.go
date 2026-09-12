package main

import (
	"context"
	"strconv"
	"strings"
)

// Diagnostics for the application's own support bundle.
//
// The updater is the only component holding a Docker socket, so it is the only
// one that can answer "what are these containers doing" — which is most of what
// anybody wants when the application itself is misbehaving. The backend assembles
// the bundle and asks here for the parts only this process can see.
//
// Read-only: ps and logs. Nothing here changes a container.

// maxLogLines bounds what one container contributes.
//
// A bundle has to be small enough to attach to a ticket. Logs are also where
// secrets are most likely to appear, so more of them is not straightforwardly
// better — the backend scrubs what comes back, and a smaller window is less to
// get wrong.
const maxLogLines = 2000

// diagnostics is what the updater can report about the running stack.
type diagnostics struct {
	Containers string            `json:"containers"`
	Logs       map[string]string `json:"logs"`
	Errors     map[string]string `json:"errors,omitempty"`
}

func (d *execDocker) collectDiagnostics(ctx context.Context, lines int) diagnostics {
	if lines <= 0 || lines > maxLogLines {
		lines = maxLogLines
	}
	out := diagnostics{Logs: map[string]string{}, Errors: map[string]string{}}

	ps, err := d.run(ctx, "ps", "-a",
		"--filter", "label=com.docker.compose.project="+d.project,
		"--format", "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.RunningFor}}")
	if err != nil {
		out.Errors["containers"] = err.Error()
	}
	out.Containers = ps

	for _, line := range strings.Split(ps, "\n") {
		name, _, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || name == "" {
			continue
		}
		// --timestamps, because "when" is half of every log question, and the
		// container's own lines do not always carry one.
		lg, lerr := d.run(ctx, "logs", "--timestamps", "--tail", strconv.Itoa(lines), name)
		if lerr != nil {
			out.Errors[name] = lerr.Error()
			continue
		}
		out.Logs[name] = lg
	}
	return out
}
