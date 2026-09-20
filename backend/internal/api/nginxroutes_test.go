package api

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every path the backend serves OUTSIDE /api must be proxied by the frontend, or it is
// only reachable by bypassing the frontend entirely.
//
// This is the gap that made federation unusable. The site-facing join and link
// endpoints are mounted at /federation/... deliberately — they are machine-to-machine,
// not part of the operator API — and nginx proxies /api/, /headlamp/ and /aldgate/ and
// nothing else. A hub hands a joining site its PUBLIC url, the site POSTs the join
// there, and nginx answers:
//
//	405 Not Allowed
//
// because it was trying to serve /federation/join as a static file. Every layer was
// behaving correctly on its own terms and the feature could not work at all.
//
// The check is deliberately crude — a path prefix appearing somewhere in nginx.conf —
// because the precise thing that went wrong was a prefix nobody had thought about, not
// a misconfigured one.
func TestEveryNonAPIRouteIsProxiedByTheFrontend(t *testing.T) {
	conf, err := os.ReadFile("../../../frontend/nginx.conf")
	if err != nil {
		conf, err = os.ReadFile("../../frontend/nginx.conf")
	}
	if err != nil {
		t.Skipf("frontend/nginx.conf not readable from here: %v", err)
	}
	nginx := string(conf)

	srcs := []string{"server.go"}
	// The federation mounts register their own top-level routes.
	if b, err := os.ReadFile("../federation/federation.go"); err == nil {
		_ = b
		srcs = append(srcs, "../federation/federation.go")
	}

	// Only the TOP-LEVEL router. Routes on a sub-router (pr/ar inside an
	// r.Route("/api/v1/...")) carry a prefix this cannot see, and treating their
	// bare paths as top-level ones reports /mode and /sites as unproxied when they
	// are served under /api and covered by its location.
	route := regexp.MustCompile(`(?m)^\s*r\.(?:Get|Post|Put|Patch|Delete|Handle|Mount)\("(/[^"]*)"`)
	seen := map[string]bool{}
	for _, f := range srcs {
		body, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, m := range route.FindAllStringSubmatch(string(body), -1) {
			p := m[1]
			switch {
			case strings.HasPrefix(p, "/api"):
				continue // proxied by the /api/ location
			case p == "/" || p == "/*":
				continue
			}
			// The first path segment is what an nginx location keys on.
			seg := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)[0]
			if seg == "" {
				continue
			}
			seen["/"+seg] = true
		}
	}
	if len(seen) == 0 {
		t.Fatal("no non-/api routes found — the extraction is broken, and a test that " +
			"checks nothing is worse than no test")
	}

	var missing []string
	for p := range seen {
		// Either a location block for the prefix, or an exact-match location for the
		// path itself (health, version and ping are served that way).
		if strings.Contains(nginx, "location "+p+"/") ||
			strings.Contains(nginx, "location = "+p) ||
			strings.Contains(nginx, "location "+p+" ") {
			continue
		}
		missing = append(missing, p)
	}
	if len(missing) > 0 {
		t.Errorf("the backend serves these outside /api and nginx does not proxy them, so "+
			"they are unreachable through the frontend: %v\n"+
			"Add a location block to frontend/nginx.conf, or the feature that uses them "+
			"only works when the backend port is addressed directly.", missing)
	}
}
