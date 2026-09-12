package containerupdate

import (
	"fmt"
	"strings"
)

// Updating a container in place, using the compose project it already belongs to.
//
// Provenance does not need to hold a copy of the compose file to pull a rebuilt
// image and recreate the service that runs it. The container's own labels say
// which project and service it is and where the project lives, so the update is:
// go there, pull that service, bring that service back up.
//
// This is deliberately limited to updates where the compose file does not need
// to change — a moved tag, which is the same version rebuilt on a patched base
// image. A version BUMP is written into the compose file, so applying one means
// editing a file Provenance does not own. That is a different decision with a
// different blast radius: on a host whose compose files are deployed from
// somewhere else (a git repo, an rsync target) an edit here is reverted on the
// next deploy, silently, leaving the fleet on an image nobody can explain. Those
// still require an adopted stack, where the change is recorded and has a history.

// inPlaceScript pulls and recreates one service of an existing compose project.
func inPlaceScript(dir, service string) string {
	var b strings.Builder
	b.WriteString("set -eu\n")
	fmt.Fprintf(&b, "cd %s\n", shellQuote(dir))

	// Which compose binary. The same two-flavour check the stack deploy uses: a
	// host on the older standalone binary must not silently do nothing.
	b.WriteString("if docker compose version >/dev/null 2>&1; then\n")
	b.WriteString("  _c=\"docker compose\"\n")
	b.WriteString("elif command -v docker-compose >/dev/null 2>&1; then\n")
	b.WriteString("  _c=\"docker-compose\"\n")
	b.WriteString("else\n")
	b.WriteString("  echo 'no docker compose on this host' >&2; exit 127\n")
	b.WriteString("fi\n")

	// Confirm compose can actually see a project HERE before touching anything.
	//
	// working_dir is recorded by whatever ran compose. For the ordinary case --
	// somebody ran `docker compose up -d` in /opt/stacks/foo -- it is exactly the
	// directory holding the compose file. For a project deployed from inside a
	// container it is whatever that container saw, and the file may not be here
	// at all. Running blind would either fail confusingly or, worse, act on a
	// DIFFERENT project that happens to live at the same path.
	b.WriteString("if ! $_c config --services >/dev/null 2>&1; then\n")
	b.WriteString("  echo '::NOPROJECT::' >&2; exit 3\n")
	b.WriteString("fi\n")

	// And that this project is the one the container belongs to. Same reason.
	fmt.Fprintf(&b, "if ! $_c config --services 2>/dev/null | grep -qx %s; then\n",
		shellQuote(service))
	b.WriteString("  echo '::NOSERVICE::' >&2; exit 4\n")
	b.WriteString("fi\n")

	// Pull first, then recreate. `up -d` alone finds the tag already present
	// locally and starts the old bytes again -- which is the entire failure this
	// exists to fix.
	fmt.Fprintf(&b, "$_c pull %s\n", shellQuote(service))
	fmt.Fprintf(&b, "$_c up -d %s\n", shellQuote(service))
	return b.String()
}

// shellQuote renders a string as a single-quoted shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// inPlaceFailure turns the script's exit into something an operator can act on.
func inPlaceFailure(dir, service string, out string) string {
	switch {
	case strings.Contains(out, "::NOPROJECT::"):
		return fmt.Sprintf(
			"this container's compose project is recorded at %s, but no compose project "+
				"is readable there — it was probably deployed from somewhere else. Adopt "+
				"its compose file as a stack to make it updatable.", dir)
	case strings.Contains(out, "::NOSERVICE::"):
		return fmt.Sprintf(
			"the compose project at %s does not define a service called %q, so this is "+
				"not the project this container came from.", dir, service)
	}
	return trimOutput(out)
}
