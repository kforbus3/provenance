package containerupdate

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/kforbus3/provenance/backend/internal/composefile"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// A major-version bump of a stateful image is not an update a rollout can apply.
//
// These images keep an on-disk format owned by one major version. Pulling the
// next one does not migrate it -- the new binary reads the old data directory,
// refuses it, and exits, and the container is restarted forever:
//
//	This is usually the result of upgrading the Docker image without upgrading
//	the underlying database using "pg_upgrade" (which requires both versions).
//
// That is not a deploy that failed cleanly. The service is DOWN, its data is
// untouched but unreadable by the image now pinned in front of it, and the only
// way out is running the migration by hand with both versions available -- which
// is precisely what a container rollout cannot do.
//
// This is how a Keycloak database went down for twenty hours: postgres
// 17.11-alpine -> 18.6-alpine, applied and then recorded as verified.
//
// Like this application's own containers, these updates stay VISIBLE. Knowing
// postgres 18 exists is useful, and its vulnerability scanning more so. Only
// applying it this way is refused, because the operator has to choose a
// migration path first.
//
// Minor and patch moves are untouched: 17.11 -> 17.14 is an ordinary update, and
// those carry the security fixes.
var statefulRepos = map[string]string{
	"postgres":                     "pg_upgrade",
	"postgis/postgis":              "pg_upgrade",
	"timescale/timescaledb":        "pg_upgrade",
	"mysql":                        "mysql_upgrade",
	"mariadb":                      "mariadb-upgrade",
	"percona":                      "mysql_upgrade",
	"mongo":                        "a staged mongod featureCompatibilityVersion upgrade",
	"elasticsearch":                "a reindex or a rolling upgrade",
	"opensearchproject/opensearch": "a reindex or a rolling upgrade",
	"neo4j":                        "a store upgrade",
	"influxdb":                     "an influxd upgrade",
}

// statefulRepo matches a repository against the table above, ignoring the
// registry host so that ghcr.io/x/postgres and docker.io/library/postgres are
// recognised alike. Matching is on the FULL final path, never a substring: a
// repository called "my-postgres-backup" keeps no data directory of postgres's
// and must not be refused.
func statefulRepo(repo string) (string, bool) {
	r := strings.ToLower(strings.TrimSpace(repo))
	if how, ok := statefulRepos[r]; ok {
		return how, true
	}
	// Strip a registry host ("ghcr.io/", "docker.io/library/", "quay.io/").
	if i := strings.Index(r, "/"); i >= 0 {
		host := r[:i]
		if strings.Contains(host, ".") || strings.Contains(host, ":") || host == "localhost" {
			rest := r[i+1:]
			if how, ok := statefulRepos[rest]; ok {
				return how, true
			}
			rest = strings.TrimPrefix(rest, "library/")
			if how, ok := statefulRepos[rest]; ok {
				return how, true
			}
		}
	}
	return "", false
}

// majorVersion reads the leading numeric component of a tag: "17.11-alpine" is
// 17, "18-alpine" is 18, "8.0.36" is 8.
//
// Returns ok=false for anything that does not START with a digit -- "latest",
// "stable", "server-cuda-b10975". An unparseable tag is NOT treated as a major
// change: this refuses updates, so guessing here would block ordinary rebuilds
// of images that merely happen to share a name with a database.
func majorVersion(tag string) (int, bool) {
	t := strings.TrimSpace(tag)
	t = strings.TrimPrefix(t, "v")
	end := 0
	for end < len(t) && t[end] >= '0' && t[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(t[:end])
	if err != nil {
		return 0, false
	}
	return n, true
}

// isStatefulMajorBump reports whether moving this repository from one tag to
// another crosses a major version of an image that owns an on-disk format.
func isStatefulMajorBump(repo, fromTag, toTag string) (how string, yes bool) {
	how, ok := statefulRepo(repo)
	if !ok {
		return "", false
	}
	fromMajor, okFrom := majorVersion(fromTag)
	toMajor, okTo := majorVersion(toTag)
	if !okFrom || !okTo {
		return "", false
	}
	if toMajor <= fromMajor {
		// Equal is a minor/patch move or a rebuild; lower is a rollback, which is
		// a deliberate act and not this check's business.
		return "", false
	}
	return how, true
}

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
		how, ok := statefulRepo(ref.Repository)
		if !ok {
			continue
		}
		pinned, okPin := majorVersion(ref.Tag)
		if !okPin {
			continue
		}
		for _, c := range running {
			if !sameRepo(c.Repository, ref.Repository) {
				continue
			}
			live, okLive := majorVersion(c.Tag)
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
