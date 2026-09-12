// Package stacks deploys container stack definitions to the hosts that run them.
//
// Provenance holds the desired state; this puts it on the host and brings it up.
// The rendered compose file is LEFT on the host afterwards, which is the point:
// the break-glass runbook opens by saying Provenance is the single path to your
// hosts, and holding the only copy of every stack definition would make that more
// true. With a copy on disk, Provenance being down stops you changing what runs,
// not running it -- the property a git checkout on the deploy target was quietly
// providing.
package stacks

import (
	"fmt"
	"strings"
)

// renderScript is the script run on the host to apply one stack.
//
// Written to a temporary file and moved into place, never edited where it lives:
// a compose file half-written when a connection drops is a stack that will not
// come up, and `mv` within a filesystem is atomic where a partial write is not.
//
// The previous revision is kept alongside as .prev. It costs one file and it is
// the difference between "roll back" and "find the old one somewhere".
//
// `docker compose up -d --remove-orphans` rather than `restart`: the file is the
// desired state, and a container the file no longer mentions should stop existing
// rather than linger because nothing told it to. That mirrors what an
// rsync --delete deploy already did on this fleet, which is the behaviour being
// replaced -- being unambiguous about what the source of truth means is the whole
// job.
// RenderScript builds the script that writes a stack's compose file to its host
// and brings it up. Exported so the end-to-end tests can run the REAL deploy
// against a real Docker rather than a copy of it — every bug this feature has
// shipped lived in the gap between a script, the shell that runs it and the
// parser that reads it back, which only a real run can close.
//
// pull says whether to fetch images before bringing the stack up.
//
// Off for an ordinary deploy, because `up -d` already pulls anything it does not
// have and pulling every image on every deploy would make a one-line compose
// edit as slow as a full update.
//
// On for an update rollout, where it is the entire point: when a tag has MOVED
// -- the same 1.0.0 rebuilt on a patched base image -- `up -d` finds the tag
// already present locally and starts the old bytes again. The deploy reports
// success, the digest never changes, and the rollout marches a no-op across the
// fleet while every host stays on the vulnerable image.
// service, when set, narrows the bring-up to one compose service.
//
// A stack deploy is about the whole file, so an operator pressing Deploy gets
// the whole project — that is what they asked for. An update ROLLOUT is about one
// image, and bringing up the whole project to change one of them restarts
// everything beside it: on a host running a model server, a vector database and
// five other things, updating curl would have restarted all of them. Nobody asked
// for that, and the blast radius is the part an operator cannot undo.
//
// --remove-orphans is dropped with it: removing containers the file no longer
// defines is a whole-project decision, and making it as a side effect of updating
// one image would delete things nobody mentioned.
func RenderScript(dir, compose string, revision int, pull bool, service string) string {
	var b strings.Builder
	b.WriteString("set -eu\n")
	// The heredoc delimiter is quoted, so nothing inside the compose file is
	// expanded by the shell on the way through. A compose file is full of $ --
	// ${VAR:-default} is ordinary in one -- and expanding those here would write
	// something different from what was reviewed.
	fmt.Fprintf(&b, "mkdir -p %s\n", shellQuote(dir))
	fmt.Fprintf(&b, "cat > %s <<'PROVENANCE_COMPOSE_EOF'\n%s\nPROVENANCE_COMPOSE_EOF\n",
		shellQuote(dir+"/.docker-compose.yml.new"), compose)
	fmt.Fprintf(&b, "if [ -f %s ]; then cp -f %s %s; fi\n",
		shellQuote(dir+"/docker-compose.yml"),
		shellQuote(dir+"/docker-compose.yml"),
		shellQuote(dir+"/docker-compose.yml.prev"))
	fmt.Fprintf(&b, "mv -f %s %s\n",
		shellQuote(dir+"/.docker-compose.yml.new"),
		shellQuote(dir+"/docker-compose.yml"))
	// The revision this host has applied, readable from the host itself. So an
	// operator standing on the machine can answer "what is this" without the
	// control plane, and so a drifted host can be identified without trusting a
	// database that may be describing an apply that never landed.
	fmt.Fprintf(&b, "printf '%%s\\n' %s > %s\n",
		shellQuote(fmt.Sprint(revision)), shellQuote(dir+"/.provenance-revision"))
	fmt.Fprintf(&b, "cd %s\n", shellQuote(dir))

	// Which compose binary, established once and used for both the validation
	// below and the bring-up. The same two-flavour check as everywhere else: a
	// host on the older standalone binary must not silently do nothing.
	b.WriteString("if docker compose version >/dev/null 2>&1; then\n")
	b.WriteString("  _c=\"docker compose\"\n")
	b.WriteString("elif command -v docker-compose >/dev/null 2>&1; then\n")
	b.WriteString("  _c=\"docker-compose\"\n")
	b.WriteString("else\n")
	b.WriteString("  echo 'no docker compose on this host' >&2; exit 127\n")
	b.WriteString("fi\n")

	// Validate BEFORE acting, and put the previous file back if it does not parse.
	//
	// A compose file is written here from whatever the stack record holds, and a
	// stack record is only as good as what went into it. One did go in bad — an
	// adoption swallowed the command runner's trailing "[exit code 0]" line — and
	// because the deploy wrote the stored copy without looking at it, every
	// attempt rewrote the same broken file onto the host. Fixing the intake
	// stopped new damage; it did nothing for the record already poisoned, and the
	// host stayed broken.
	//
	// So the deploy refuses to be the thing that breaks a host. compose's own
	// parser is the check — not a YAML library here, which would be a second
	// opinion about a format only compose has the final say on.
	b.WriteString("if ! $_c config -q >/dev/null 2>&1; then\n")
	b.WriteString("  _why=$($_c config -q 2>&1 | head -5)\n")
	fmt.Fprintf(&b, "  if [ -f %s ]; then mv -f %s %s; fi\n",
		shellQuote(dir+"/docker-compose.yml.prev"),
		shellQuote(dir+"/docker-compose.yml.prev"),
		shellQuote(dir+"/docker-compose.yml"))
	b.WriteString("  echo \"::BADCOMPOSE::$_why\" >&2\n")
	b.WriteString("  exit 5\n")
	b.WriteString("fi\n")

	// What to act on: one service, or the whole project.
	//
	// A narrowed deploy still brings anything sharing that service's network
	// namespace. Leaving those behind strands them on a namespace that no longer
	// exists — running, healthy, and with no network. See networkDependents.
	target := " --remove-orphans"
	if service != "" {
		target = " " + shellQuote(service)
		for _, dep := range networkDependents(compose, service) {
			target += " " + shellQuote(dep)
		}
	}
	if pull {
		b.WriteString("$_c pull" + target + "\n")
	}
	b.WriteString("$_c up -d" + target + "\n")
	return b.String()
}

// rollbackScript restores the previous compose file and brings the stack back up.
func rollbackScript(dir string) string {
	var b strings.Builder
	b.WriteString("set -eu\n")
	fmt.Fprintf(&b, "cd %s\n", shellQuote(dir))
	b.WriteString("if [ ! -f docker-compose.yml.prev ]; then\n")
	b.WriteString("  echo 'no previous revision on this host to roll back to' >&2; exit 1\n")
	b.WriteString("fi\n")
	b.WriteString("mv -f docker-compose.yml.prev docker-compose.yml\n")
	b.WriteString("if docker compose version >/dev/null 2>&1; then\n")
	b.WriteString("  docker compose up -d --remove-orphans\n")
	b.WriteString("else\n")
	b.WriteString("  docker-compose up -d --remove-orphans\n")
	b.WriteString("fi\n")
	return b.String()
}

// shellQuote wraps a string in single quotes for /bin/sh, escaping any single
// quotes within.
//
// Every path here is built from a stack name and a configured root, and the name
// is validated before it ever reaches the database -- but a path that reaches a
// privileged shell unquoted is one validation bug away from being a command, and
// the validation is in a different file from this one.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
