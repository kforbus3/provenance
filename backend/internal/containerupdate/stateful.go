package containerupdate

import (
	"fmt"
	"strings"

	"github.com/kforbus3/provenance/backend/internal/composefile"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/stateful"
)

// dangerousPin reports a stateful image the compose file pins across a major
// version from what the host is actually running.
//
// isStatefulMajorBump guards the image being ROLLED OUT. It cannot see this,
// and this is how the rule was got round in production: a rollout of
// quay.io/keycloak/keycloak ran `docker compose up -d keycloak`, compose brought
// up its `depends_on` database as well, and the compose file still pinned
// postgres 18 against a version-17 data directory left by an earlier incident.
// Postgres 18 refuses a 17 data directory, so the database crash-looped, the
// dependency never became healthy, and Keycloak never started. Nothing in the
// rollout was a Postgres bump; the file did it.
//
// So the check has to be "what is this deploy about to apply", not "what did
// this rollout intend to change". A pin that disagrees with the running data is
// a landmine whatever stepped on it.
//
// Reported rather than repaired: the compose file may be right and the container
// merely old, and Provenance cannot tell which the operator meant. Refusing says
// so; rewriting somebody's pin would be a guess with a service behind it.
func dangerousPin(compose string, running []models.Container) (string, bool) {
	for _, ref := range composefile.Images(compose) {
		how, ok := stateful.Repo(ref.Repository)
		if !ok {
			continue
		}
		pinned, okPin := stateful.MajorVersion(ref.Tag)
		if !okPin {
			continue
		}
		for _, c := range running {
			if !sameRepo(c.Repository, ref.Repository) {
				continue
			}
			live, okLive := stateful.MajorVersion(c.Tag)
			if !okLive || live == pinned {
				continue
			}
			return fmt.Sprintf(
				"the compose file pins %s:%s but %s is running %s:%s — a different major "+
					"version. This image owns its on-disk format, so bringing the file up "+
					"would recreate it onto a data directory the new version refuses, and "+
					"the container would restart forever with the service down. It needs %s "+
					"first, with both versions available. Deploying was refused: fix the pin "+
					"(or upgrade the data) and run this again.",
				ref.Repository, ref.Tag, c.Name, c.Repository, c.Tag, how), true
		}
	}
	return "", false
}

// sameRepo compares repositories ignoring a registry host prefix, so
// "postgres" and "docker.io/library/postgres" are one image.
func sameRepo(a, b string) bool {
	return strings.EqualFold(bareRepo(a), bareRepo(b))
}

func bareRepo(r string) string {
	r = strings.ToLower(strings.TrimSpace(r))
	r = strings.TrimPrefix(r, "docker.io/library/")
	r = strings.TrimPrefix(r, "docker.io/")
	if i := strings.Index(r, "/"); i >= 0 {
		if host := r[:i]; strings.Contains(host, ".") || strings.Contains(host, ":") || host == "localhost" {
			r = r[i+1:]
		}
	}
	return r
}
