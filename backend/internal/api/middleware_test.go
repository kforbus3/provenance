package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kforbus3/Moorgate/backend/internal/auth"
)

func TestCSRFProtect(t *testing.T) {
	var reached bool
	h := csrfProtect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	do := func(method string, withRefreshCookie bool, csrfCookie, csrfHeader, bearer string) int {
		reached = false
		r := httptest.NewRequest(method, "/api/v1/auth/refresh", nil)
		if withRefreshCookie {
			r.AddCookie(&http.Cookie{Name: auth.RefreshCookie, Value: "refresh-token"})
		}
		if csrfCookie != "" {
			r.AddCookie(&http.Cookie{Name: auth.CSRFCookie, Value: csrfCookie})
		}
		if csrfHeader != "" {
			r.Header.Set("X-CSRF-Token", csrfHeader)
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// Cookie-authenticated POST with NO CSRF header/cookie: rejected.
	if code := do(http.MethodPost, true, "", "", ""); code != http.StatusForbidden || reached {
		t.Errorf("cookie POST without CSRF should be 403 and not reach handler; got %d reached=%v", code, reached)
	}
	// Cookie-authenticated POST with mismatched header: rejected.
	if code := do(http.MethodPost, true, "abc", "xyz", ""); code != http.StatusForbidden || reached {
		t.Errorf("mismatched CSRF should be 403; got %d reached=%v", code, reached)
	}
	// Cookie-authenticated POST with matching double-submit: allowed.
	if code := do(http.MethodPost, true, "match", "match", ""); code != http.StatusOK || !reached {
		t.Errorf("matching CSRF should pass; got %d reached=%v", code, reached)
	}
	// Bearer-authenticated POST (no CSRF needed): allowed even with a session cookie present.
	if code := do(http.MethodPost, true, "", "", "access-token"); code != http.StatusOK || !reached {
		t.Errorf("bearer POST should be exempt; got %d reached=%v", code, reached)
	}
	// No session cookie (e.g. login): exempt.
	if code := do(http.MethodPost, false, "", "", ""); code != http.StatusOK || !reached {
		t.Errorf("cookieless POST should be exempt; got %d reached=%v", code, reached)
	}
	// Safe method: exempt even when cookie-authenticated.
	if code := do(http.MethodGet, true, "", "", ""); code != http.StatusOK || !reached {
		t.Errorf("GET should be exempt; got %d reached=%v", code, reached)
	}
}
