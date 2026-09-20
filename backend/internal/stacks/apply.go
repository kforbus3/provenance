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
func RenderScript(dir, compose string, revision int, pull bool, services ...string) string {
	services = narrowTo(services...)
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
	// Read before it is overwritten, so a failed deploy can put back the number the
	// host was actually running rather than guessing at revision-1.
	fmt.Fprintf(&b, "_prevrev=$(cat %s 2>/dev/null || echo '')\n",
		shellQuote(dir+"/.provenance-revision"))
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
	if len(services) > 0 {
		target = ""
		seen := map[string]bool{}
		for _, svc := range services {
			// Every named service AND every service sharing one's network
			// namespace. Deduplicated because two named services can share a
			// dependent, and naming it twice on one command line is an error.
			for _, name := range append([]string{svc}, networkDependents(compose, svc)...) {
				if seen[name] {
					continue
				}
				seen[name] = true
				target += " " + shellQuote(name)
			}
		}
	}
	// `pull` takes services, never --remove-orphans: that flag is an `up`
	// concept, and passing it here failed the whole deploy with "unknown flag"
	// and exit 16 before a single image was fetched. It only ever fired on a
	// WHOLE-project pulling deploy, which is why it survived so long.
	pullTarget := target
	if len(services) == 0 {
		pullTarget = ""
	}
	if pull {
		b.WriteString("$_c pull" + pullTarget + "\n")
	}
	// --no-deps when narrowed, or the narrowing is undone by compose.
	//
	// `up -d <service>` also brings up that service's depends_on. If one of those
	// has drifted from the file it is RECREATED, so a deploy asked to touch one
	// service reaches into its database instead. That is not hypothetical: a
	// rollout of quay.io/keycloak/keycloak ran `up -d keycloak`, compose
	// recreated keycloak-db because the file pinned a different Postgres than the
	// container was running, the new one refused the existing data directory, and
	// `up` exited 1 with "dependency failed to start: container keycloak-db is
	// unhealthy". Keycloak was down and nothing in the rollout had been a
	// Postgres change.
	//
	// The services that MUST come along are already named in `target`: anything
	// sharing this service's network namespace, which is stranded otherwise. That
	// is the complete set, so compose does not need to work any of it out.
	//
	// Not passed on a whole-project deploy, where dependency order is the point.
	// The risk --no-deps carries is a dependency that is genuinely stopped, which
	// it will not start: the service then comes up and fails. That is a
	// pre-existing broken state, it is visible (the verification reads back what
	// is RUNNING), and it is much cheaper than recreating a database nobody asked
	// about.
	noDeps := ""
	if len(services) > 0 {
		noDeps = " --no-deps"
	}
	// A deploy that does not come up must not be the thing that leaves the host down.
	//
	// The parse check above already refuses to replace a working file with one compose
	// cannot read. That is the CHEAP failure. The expensive one parses, deploys, and
	// does not come up -- and until now it kept the new file in place with the stack
	// stopped, so the host stayed broken until a person noticed and rolled back by
	// hand.
	//
	// That is how a Keycloak went down twice for the same reason. The stored compose
	// pinned postgres 18 over a version 17 data directory; the new database refused
	// the directory, keycloak's depends_on: service_healthy was never satisfied, `up`
	// exited non-zero -- and the previous file, the one that had been serving fine,
	// was sitting right there as .prev, untouched, for twenty hours.
	//
	// So: put it back, bring it up with the same narrowing, and restore the revision
	// marker to what the host was running. The deploy is still recorded as FAILED --
	// it failed, and the operator has to fix the file -- but the service is up while
	// they do. The rejected file is kept beside it as .rejected, because a failure
	// nobody can inspect is one nobody can fix.
	up := "$_c up -d" + noDeps + target
	b.WriteString("_rc=0\n")
	b.WriteString(up + " || _rc=$?\n")
	b.WriteString("if [ \"$_rc\" -ne 0 ]; then\n")
	b.WriteString("  echo \"::UPFAILED::the stack did not come up (exit $_rc)\"\n")
	b.WriteString("  if [ -f docker-compose.yml.prev ]; then\n")
	b.WriteString("    cp -f docker-compose.yml docker-compose.yml.rejected\n")
	b.WriteString("    mv -f docker-compose.yml.prev docker-compose.yml\n")
	b.WriteString("    if [ -n \"$_prevrev\" ]; then printf '%s\\n' \"$_prevrev\" > .provenance-revision; fi\n")
	b.WriteString("    if " + up + "; then\n")
	b.WriteString("      echo '::RESTORED::the previous compose file was put back and the stack is up on it'\n")
	b.WriteString("    else\n")
	b.WriteString("      echo '::RESTOREFAILED::the previous compose file was put back but the stack did not come up on it either'\n")
	b.WriteString("    fi\n")
	b.WriteString("  else\n")
	b.WriteString("    echo '::NOPREVIOUS::there is no previous compose file on this host to fall back to'\n")
	b.WriteString("  fi\n")
	b.WriteString("  exit $_rc\n")
	b.WriteString("fi\n")
	return b.String()
}

// narrowTo drops empty and duplicate service names.
//
// Empty is how every caller says "the whole project", and it arrives as a real
// element through the variadic, so it has to be filtered rather than assumed
// absent -- otherwise `up -d ”` runs and compose fails on a service named "".
func narrowTo(services ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range services {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
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
