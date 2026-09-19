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

// inPlaceScript pulls and recreates the named services of an existing compose
// project.
//
// Plural: one image can back several services in a project, and recreating only
// one of them leaves the others running the old image.
func inPlaceScript(dir, project string, files, services []string) string {
	var b strings.Builder
	b.WriteString("set -eu\n")
	// Asked about BEFORE cd, and reported as a marker.
	//
	// `set -eu` means a failed cd kills the script where it stands, so the checks
	// below never run and the operator gets the shell's words instead of ours:
	//
	//	/bin/sh: 2: cd: can't cd to /data/compose/40/stacks/nginx
	//	[exit code 2]
	//
	// That path is real, and it is inside a container that no longer exists — a
	// Portainer stack whose manager has been removed. Nothing about the raw error
	// says so.
	fmt.Fprintf(&b, "[ -d %s ] || { echo '::NODIR::' >&2; exit 6; }\n", shellQuote(dir))
	fmt.Fprintf(&b, "cd %s 2>/dev/null || { echo '::NOACCESS::' >&2; exit 7; }\n", shellQuote(dir))

	// Which compose binary. The same two-flavour check the stack deploy uses: a
	// host on the older standalone binary must not silently do nothing.
	b.WriteString("if docker compose version >/dev/null 2>&1; then\n")
	b.WriteString("  _c=\"docker compose\"\n")
	b.WriteString("elif command -v docker-compose >/dev/null 2>&1; then\n")
	b.WriteString("  _c=\"docker-compose\"\n")
	b.WriteString("else\n")
	b.WriteString("  echo 'no docker compose on this host' >&2; exit 127\n")
	b.WriteString("fi\n")

	// Use the project's OWN compose files, when they are here.
	//
	// Without this, compose re-discovers files by their default names in this
	// directory -- and a project assembled from an overlay does not define its
	// services in those files. keith's aptly stack is docker-compose.yml plus
	// docker-compose.tls-ui.yml, with the caddy service only in the overlay, so
	// every attempt to recreate caddy reported "no such service" and every rebuild
	// of caddy:2-alpine was written off as an orphaned container no rollout could
	// fix. Nothing was wrong with the container; compose had recorded both files
	// on it all along.
	//
	// Guarded by existence, which is why collecting these paths was avoided
	// before: a project deployed from INSIDE a container records that container's
	// paths, which are not on the host. If any recorded file is missing here, fall
	// through to default discovery -- the previous behaviour -- rather than
	// failing on a path that was never going to resolve.
	//
	// Passed through a shell FUNCTION rather than a variable of flags. A variable
	// has to be expanded unquoted to split into separate arguments, and then the
	// quoting that protects a path with a space in it arrives as literal quote
	// characters -- compose looking for a file named `'/root/x.yml'`. A function
	// keeps the arguments as written.
	flags := ""
	for _, f := range files {
		flags += " -f " + shellQuote(f)
	}
	if project != "" {
		// Named explicitly so the operation cannot land on a DIFFERENT project
		// that happens to derive the same name from these files.
		flags += " -p " + shellQuote(project)
	}
	b.WriteString("_own=0\n")
	if len(files) > 0 {
		cond := make([]string, 0, len(files))
		for _, f := range files {
			cond = append(cond, fmt.Sprintf("[ -f %s ]", shellQuote(f)))
		}
		fmt.Fprintf(&b, "if %s; then _own=1; fi\n", strings.Join(cond, " && "))
	}
	if flags != "" {
		fmt.Fprintf(&b, "_run() { if [ \"$_own\" = 1 ]; then $_c%s \"$@\"; else $_c \"$@\"; fi; }\n", flags)
	} else {
		b.WriteString("_run() { $_c \"$@\"; }\n")
	}

	// Confirm compose can actually see a project HERE before touching anything.
	//
	// working_dir is recorded by whatever ran compose. For the ordinary case --
	// somebody ran `docker compose up -d` in /opt/stacks/foo -- it is exactly the
	// directory holding the compose file. For a project deployed from inside a
	// container it is whatever that container saw, and the file may not be here
	// at all. Running blind would either fail confusingly or, worse, act on a
	// DIFFERENT project that happens to live at the same path.
	b.WriteString("if ! _run config --services >/dev/null 2>&1; then\n")
	b.WriteString("  echo '::NOPROJECT::' >&2; exit 3\n")
	b.WriteString("fi\n")

	// And that this project is the one the containers belong to. Same reason.
	// Every service is checked, not just the first: a project that defines one of
	// them and not another is not the project these containers came from, and
	// finding that out after recreating half of them is worse than not starting.
	targets := ""
	for _, service := range services {
		fmt.Fprintf(&b, "if ! _run config --services 2>/dev/null | grep -qx %s; then\n",
			shellQuote(service))
		b.WriteString("  echo '::NOSERVICE::' >&2; exit 4\n")
		b.WriteString("fi\n")
		targets += " " + shellQuote(service)
	}

	// Pull first, then recreate. `up -d` alone finds the tag already present
	// locally and starts the old bytes again -- which is the entire failure this
	// exists to fix.
	fmt.Fprintf(&b, "_run pull%s\n", targets)
	fmt.Fprintf(&b, "_run up -d%s\n", targets)
	return b.String()
}

// shellQuote renders a string as a single-quoted shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// inPlaceFailure turns the script's exit into something an operator can act on.
func inPlaceFailure(dir string, services []string, out string) string {
	switch {
	case strings.Contains(out, "::NODIR::"):
		return fmt.Sprintf(
			"this container's compose project is recorded at %s, which does not exist "+
				"on this host — that is a path inside whatever deployed it, so it was "+
				"created from another container (a Portainer stack, for instance). "+
				"Update it from wherever it is managed.", dir)
	case strings.Contains(out, "::NOACCESS::"):
		return fmt.Sprintf(
			"%s exists but could not be entered, even with sudo.", dir)
	case strings.Contains(out, "::NOPROJECT::"):
		return fmt.Sprintf(
			"this container's compose project is recorded at %s, but no compose project "+
				"is readable there — it was probably deployed from somewhere else. Adopt "+
				"its compose file as a stack to make it updatable.", dir)
	case strings.Contains(out, "::NOSERVICE::"):
		// Almost always an ORPHAN, not a wrong project.
		//
		// A container keeps the compose service label it was created with. Rename
		// or delete that service in the file and bring the project up without
		// --remove-orphans, and the old container keeps running under a name the
		// file no longer knows. `docker compose ps` still lists it; `compose up -d
		// <that service>` cannot, because there is nothing to bring up.
		//
		// The message this replaced said "this is not the project they came from",
		// which was wrong in the case that actually happens: on a live host the
		// caddy service had been replaced by nginx, the new container was healthy,
		// and the six-day-old caddy container was still running beside it. It WAS
		// that project -- the project had simply moved on without it.
		return fmt.Sprintf(
			"the compose project at %s no longer defines %s. A container usually ends "+
				"up like this when its service was renamed or replaced in the file and "+
				"the project was brought up without --remove-orphans, leaving the old "+
				"container running under a name the file has forgotten. Check whether it "+
				"is still wanted; if not, remove it with "+
				"`docker compose -f %s/docker-compose.yml up -d --remove-orphans`.",
			dir, quotedList(services), dir)
	}
	return trimOutput(out)
}

// unreachableProject reports a compose project this host cannot act on at all.
//
// Distinguished from a failure because nothing will make it work: the directory
// is a path inside whatever created the container, not a path on the host. On a
// live fleet that was a Portainer stack whose Portainer had since been removed,
// leaving a container nobody can redeploy from here.
//
// Treated as inapplicable rather than failed, for the same reason a superseded
// image is: halting a fleet-wide rollout on something permanently impossible
// stops every other host for no gain, every time it runs.
func unreachableProject(out string) bool {
	// NOSERVICE joins these: an orphaned container is not something a rollout can
	// ever fix, so failing the HOST on it halts a fleet-wide rollout over one
	// stale container and stops every other host for no gain. That is what
	// happened -- a six-day-old orphan on one host halted the whole run. Reported
	// as inapplicable, the way a host that has already moved past an image is.
	return strings.Contains(out, "::NODIR::") ||
		strings.Contains(out, "::NOACCESS::") ||
		strings.Contains(out, "::NOSERVICE::")
}

// quotedList renders service names so an empty or odd one is still visible.
func quotedList(services []string) string {
	if len(services) == 0 {
		return "the service this container names"
	}
	out := make([]string, 0, len(services))
	for _, s := range services {
		out = append(out, "\""+s+"\"")
	}
	if len(out) == 1 {
		return "a service called " + out[0]
	}
	return "services called " + strings.Join(out, ", ")
}
