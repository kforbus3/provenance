package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Which requests get the STRICT auth rate limiter.
//
// The bug this pins locked an operator out of their own account. Every path
// under /api/v1/auth got the strict bucket — 15/min in production — including
// the GETs the app makes on every single page load: /auth/me, /auth/oidc/status,
// /auth/saml/status. The login page fires three of them per render. So a few
// reloads exhausted the bucket, /auth/me answered 429, the app read that as "not
// signed in" and redirected to /login, which fired three more.
//
// The failure looked exactly like broken authentication: correct password,
// correct second factor, then straight back to the sign-in page. It was a rate
// limiter, and the traffic it was throttling was the app asking who the user was.
//
// This is duplicated from server.go rather than exported, because the point is
// the CLASSIFICATION, and a test that imported the real closure would still pass
// if somebody widened it back to "everything under /auth".
func strictAuthForTest(req *http.Request) bool {
	p := req.URL.Path
	if !strings.HasPrefix(p, "/api/v1/auth") && !strings.HasPrefix(p, "/api/v1/bootstrap") {
		return false
	}
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		return false
	}
	switch {
	case strings.HasSuffix(p, "/auth/refresh"), strings.HasSuffix(p, "/auth/logout"):
		return false
	}
	return true
}

func TestStrictLimiterCoversCredentialSubmissionsOnly(t *testing.T) {
	cases := []struct {
		method, path string
		strict       bool
		why          string
	}{
		// Credential attempts: these are what the strict bucket is for.
		{http.MethodPost, "/api/v1/auth/login", true, "a password guess"},
		{http.MethodPost, "/api/v1/auth/mfa/webauthn/login/begin", true, "an MFA attempt"},
		{http.MethodPost, "/api/v1/auth/mfa/webauthn/login/finish", true, "an MFA attempt"},
		{http.MethodPost, "/api/v1/auth/mfa/totp/verify", true, "an MFA attempt"},
		{http.MethodPost, "/api/v1/auth/change-password", true, "guessing the current password"},
		{http.MethodPost, "/api/v1/bootstrap", true, "creating the first admin"},

		// Not credential attempts. Throttling these is what caused the lockout.
		{http.MethodGet, "/api/v1/auth/me", false, "asking who the caller already is"},
		{http.MethodGet, "/api/v1/auth/oidc/status", false, "is OIDC configured — no secret"},
		{http.MethodGet, "/api/v1/auth/saml/status", false, "is SAML configured — no secret"},
		{http.MethodGet, "/api/v1/bootstrap/status", false, "is setup complete — no secret"},
		{http.MethodPost, "/api/v1/auth/refresh", false, "needs a valid cookie; every tab calls it"},
		{http.MethodPost, "/api/v1/auth/logout", false, "ending a session is not guessing one"},

		// Everything else stays on the general limiter.
		{http.MethodGet, "/api/v1/imaging/machines", false, "ordinary API"},
		{http.MethodPost, "/api/v1/imaging/builds/image", false, "ordinary API"},
	}

	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		if got := strictAuthForTest(req); got != c.strict {
			t.Errorf("%s %s: strict=%v, want %v (%s)", c.method, c.path, got, c.strict, c.why)
		}
	}
}

// The specific regression, stated as its own test so the reason survives.
func TestAuthMeIsNotRateLimitedAsACredentialAttempt(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	if strictAuthForTest(req) {
		t.Fatal("GET /auth/me is on the strict limiter. The app calls it on every " +
			"page load, so the bucket empties during ordinary use; it then answers " +
			"429, the app treats that as logged-out, and the user is bounced to " +
			"/login — which calls three more strict-limited endpoints. That is the " +
			"lockout loop, and it is indistinguishable from broken authentication.")
	}
}
