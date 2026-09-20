package stacks

import (
	"fmt"
	"strings"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/stateful"
)

// StatefulMajorError refuses a deploy that would put a stateful image a major
// version ahead of the data directory it is about to be pointed at.
//
// The rollout engine and the Updates list already refuse this (see package
// stateful, whose doc comment is about this exact Keycloak outage). A stack
// DEPLOY did not, and it is the same act with the same consequence: the file
// pins postgres 18, the container starts against a version 17 directory, refuses
// it, and the service that depends on it never becomes healthy.
//
// That gap cost the same Keycloak twice. The second time, the compose stored here
// still held the pin from the first -- the fix had been made on the host, where
// nothing reads it -- so pressing Deploy re-applied a change whose outcome was
// already recorded as a failure.
type StatefulMajorError struct {
	Service  string // compose service
	Repo     string // image repository
	FromTag  string // what the host is running
	ToTag    string // what this deploy would pin
	How      string // the migration this needs instead
	Stateful bool   // always true; present so a JSON consumer can branch on it
}

func (e *StatefulMajorError) Error() string {
	return fmt.Sprintf("service %q would move %s from %s to %s, which crosses a major "+
		"version of an image that owns its on-disk format: the new one will refuse the "+
		"existing data directory and the stack will not come up. That needs %s first.",
		e.Service, e.Repo, e.FromTag, e.ToTag, e.How)
}

// statefulPinConflict compares the images this deploy will bring up against what the
// host is running right now.
//
// Only the services being brought up are considered. A deploy narrowed to one
// service leaves the rest alone (--no-deps), so refusing it because a service it
// will not touch carries a bad pin would block work for a risk that is not being
// taken. A whole-project deploy considers every service, because it brings up every
// service.
//
// The comparison is against the RUNNING container, not against the stored compose's
// previous revision: what matters is the format on disk, and the only evidence of
// that is the image that has been writing it.
func statefulPinConflict(compose string, services []string, running []models.Container, dir string) *StatefulMajorError {
	want := composeImages(compose)
	if len(want) == 0 {
		return nil
	}
	narrowed := map[string]bool{}
	for _, s := range narrowTo(services...) {
		narrowed[s] = true
	}
	for _, c := range running {
		if c.ComposeService == "" || c.Repository == "" || c.Tag == "" {
			continue
		}
		// A host can run more than one project with a service called "postgres".
		// When the container says where its project lives, believe it; when it says
		// nothing (an older collection), fall back to the name.
		if c.ComposeDir != "" && dir != "" && strings.TrimRight(c.ComposeDir, "/") != strings.TrimRight(dir, "/") {
			continue
		}
		if len(narrowed) > 0 && !narrowed[c.ComposeService] {
			continue
		}
		img, ok := want[c.ComposeService]
		if !ok {
			continue
		}
		repo, tag := splitImage(img)
		if repo == "" || tag == "" || !strings.EqualFold(repo, c.Repository) {
			// A different repository entirely is not a version move; it is a
			// replacement, and this check has nothing to say about it.
			continue
		}
		if how, yes := stateful.MajorBump(repo, c.Tag, tag); yes {
			return &StatefulMajorError{
				Service: c.ComposeService, Repo: repo, FromTag: c.Tag, ToTag: tag,
				How: how, Stateful: true,
			}
		}
	}
	return nil
}

// composeImages reads service -> image from a compose file's own text.
//
// Hand-parsed, like networkDependents beside it and for the same reason: this runs
// on a file the host is about to be given verbatim, and a YAML round-trip here would
// be a second opinion about a format compose has the final say on. Only the two
// shapes that appear in a service body are read -- `image: x` and a quoted form --
// and anything else is simply not matched, which means this check says nothing rather
// than something wrong.
func composeImages(compose string) map[string]string {
	out := map[string]string{}
	inServices := false
	current := ""
	for _, raw := range strings.Split(compose, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if line == "" || strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		trimmed := strings.TrimLeft(line, " \t")
		indent := len(line) - len(trimmed)
		if indent == 0 {
			// A top-level key: services, networks, volumes...
			inServices = trimmed == "services:"
			current = ""
			continue
		}
		if !inServices {
			continue
		}
		if indent == 2 && strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
			current = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if current == "" {
			continue
		}
		rest, ok := strings.CutPrefix(trimmed, "image:")
		if !ok {
			continue
		}
		v := strings.TrimSpace(rest)
		if i := strings.IndexByte(v, '#'); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		v = strings.Trim(v, `"'`)
		if v != "" {
			out[current] = v
		}
	}
	return out
}

// splitImage separates a reference into repository and tag, leaving a registry port
// alone: registry.example.com:5000/app:1.2 is that registry's app at 1.2, and
// splitting on the first colon gets it wrong in a way nobody notices until it is
// their registry.
func splitImage(ref string) (repo, tag string) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.Contains(ref, "$") {
		// An interpolated tag is resolved on the host from its .env, which is not
		// readable from here. Unknown, so nothing is claimed about it.
		return "", ""
	}
	if i := strings.LastIndexByte(ref, '@'); i >= 0 {
		ref = ref[:i] // a digest pin carries no major version to compare
	}
	i := strings.LastIndexByte(ref, ':')
	if i < 0 {
		return ref, "latest"
	}
	if strings.Contains(ref[i+1:], "/") {
		return ref, "latest" // the colon was a registry port
	}
	return ref[:i], ref[i+1:]
}
