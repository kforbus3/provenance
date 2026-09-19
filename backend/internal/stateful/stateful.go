// Package stateful knows which container images own an on-disk format, and when a
// tag change crosses a major version of one.
//
// Its own package because two callers need the same answer and must not each have
// their own: the rollout engine refuses such an update, and the Updates list marks
// it so nobody selects it in the first place. A second copy of this list would drift,
// and the failure it prevents -- a database that refuses its own data directory and
// restarts forever -- is not one to learn about twice.
package stateful

import (
	"strconv"
	"strings"
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
var repos = map[string]string{
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
func Repo(repo string) (string, bool) {
	r := strings.ToLower(strings.TrimSpace(repo))
	if how, ok := repos[r]; ok {
		return how, true
	}
	// Strip a registry host ("ghcr.io/", "docker.io/library/", "quay.io/").
	if i := strings.Index(r, "/"); i >= 0 {
		host := r[:i]
		if strings.Contains(host, ".") || strings.Contains(host, ":") || host == "localhost" {
			rest := r[i+1:]
			if how, ok := repos[rest]; ok {
				return how, true
			}
			rest = strings.TrimPrefix(rest, "library/")
			if how, ok := repos[rest]; ok {
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
func MajorVersion(tag string) (int, bool) {
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
func MajorBump(repo, fromTag, toTag string) (how string, yes bool) {
	how, ok := Repo(repo)
	if !ok {
		return "", false
	}
	fromMajor, okFrom := MajorVersion(fromTag)
	toMajor, okTo := MajorVersion(toTag)
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
