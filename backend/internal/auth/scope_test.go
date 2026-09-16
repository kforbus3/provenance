package auth

import "testing"

func TestAnEmptyScopeIsUnscoped(t *testing.T) {
	// Every session, and every token minted before scopes existed.
	for _, path := range []string{"/api/v1/hosts", "/api/v1/k8s/clusters", "/"} {
		if !scopeAllows("", path) {
			t.Errorf("empty scope blocked %q; it must allow everything", path)
		}
	}
}

func TestAScopedTokenReachesOnlyItsOwnPrefix(t *testing.T) {
	const scope = "/api/v1/k8s"
	allowed := []string{
		"/api/v1/k8s",
		"/api/v1/k8s/clusters",
		"/api/v1/k8s/clusters/abc/proxy/api/v1/pods",
	}
	for _, p := range allowed {
		if !scopeAllows(scope, p) {
			t.Errorf("scope %q blocked %q, which is inside it", scope, p)
		}
	}
	denied := []string{
		"/api/v1/hosts",
		"/api/v1/credentials",
		"/api/v1/auth/change-password",
	}
	for _, p := range denied {
		if scopeAllows(scope, p) {
			t.Errorf("scope %q allowed %q — a kubeconfig token must not reach the rest of the API", scope, p)
		}
	}
}

// The trap. strings.HasPrefix alone lets a token scoped to "/api/v1/k8s" reach
// any endpoint whose path merely STARTS with that text — which is a silent
// privilege escalation the moment somebody adds such a route.
func TestAScopeMatchesOnPathSegmentsNotCharacters(t *testing.T) {
	for _, p := range []string{
		"/api/v1/k8superadmin",
		"/api/v1/k8s-secrets",
		"/api/v1/k8sx/clusters",
	} {
		if scopeAllows("/api/v1/k8s", p) {
			t.Errorf("scope /api/v1/k8s allowed %q — prefix matching must respect segment boundaries", p)
		}
	}
}

func TestATrailingSlashInTheScopeChangesNothing(t *testing.T) {
	for _, scope := range []string{"/api/v1/k8s", "/api/v1/k8s/"} {
		if !scopeAllows(scope, "/api/v1/k8s/clusters") {
			t.Errorf("scope %q should allow a path inside it", scope)
		}
		if scopeAllows(scope, "/api/v1/hosts") {
			t.Errorf("scope %q should not allow /api/v1/hosts", scope)
		}
	}
}
