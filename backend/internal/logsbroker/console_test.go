package logsbroker

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/config"
)

func tierHandler(viewerPW, adminPW string) *handler {
	return &handler{d: &app.Deps{Cfg: &config.Config{
		AldgateConsoleViewerUser:     "prov_viewer",
		AldgateConsoleViewerPassword: viewerPW,
		AldgateConsoleAdminUser:      "prov_admin",
		AldgateConsoleAdminPassword:  adminPW,
	}}}
}

func decode(t *testing.T, basic string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(basic, "Basic "))
	if err != nil {
		t.Fatalf("credential is not base64: %v", err)
	}
	return string(raw)
}

// The point of the whole feature: which collector account the console runs as is
// decided by the person's Provenance role, not by what they type.
func TestTheTierComesFromThePersonsPermissions(t *testing.T) {
	h := tierHandler("vpw", "apw")

	reader := &auth.Principal{Permissions: map[string]bool{permLogsView: true}}
	tier, basic := h.tierFor(reader)
	if tier != "view" {
		t.Errorf("a reader got the %q tier", tier)
	}
	if got := decode(t, basic); got != "prov_viewer:vpw" {
		t.Errorf("reader authenticates as %q, want the viewer account", got)
	}

	admin := &auth.Principal{Permissions: map[string]bool{permLogsView: true, permLogsAdminister: true}}
	tier, basic = h.tierFor(admin)
	if tier != "administer" {
		t.Errorf("an administrator got the %q tier", tier)
	}
	if got := decode(t, basic); got != "prov_admin:apw" {
		t.Errorf("administrator authenticates as %q, want the admin account", got)
	}
}

// A deployment whose collector has not been bootstrapped has no viewer
// credential. Promoting the reader into the admin account would hand every
// reader the keys to the audit trail, so it must refuse instead.
func TestAReaderIsNeverPromotedToTheAdminAccount(t *testing.T) {
	h := tierHandler("", "apw")
	reader := &auth.Principal{Permissions: map[string]bool{permLogsView: true}}
	if tier, basic := h.tierFor(reader); tier != "" || basic != "" {
		t.Errorf("with no viewer credential a reader got tier %q (%q) — that is the "+
			"admin account, and every reader would hold it", tier, decode(t, basic))
	}
	// An administrator still gets in on the credential that IS configured.
	admin := &auth.Principal{Permissions: map[string]bool{permLogsView: true, permLogsAdminister: true}}
	if tier, _ := h.tierFor(admin); tier != "administer" {
		t.Errorf("administrator got %q, want administer", tier)
	}
}

// consoleAuthz must answer with the credential in a HEADER, and nothing in the
// body: nginx copies the header into the proxied request, and anything in the body
// would be on its way to the browser.
func TestConsoleAuthzReturnsTheCredentialInAHeaderOnly(t *testing.T) {
	h := tierHandler("vpw", "apw")
	w := httptest.NewRecorder()
	h.writeConsoleAuthz(w, &auth.Principal{Permissions: map[string]bool{permLogsView: true}})

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if got := w.Header().Get("X-Aldgate-Authorization"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("no credential header for nginx to copy: %q", got)
	}
	if body := w.Body.String(); strings.Contains(body, "vpw") || strings.Contains(body, "prov_viewer") {
		t.Errorf("the credential appears in the body, which is sent to the browser: %q", body)
	}
}

// The console's cookie is how a page load authenticates, since Provenance's
// session cookies are scoped to /api/v1/auth and never arrive here. An existing
// Authorization header must always win, so this can never downgrade a real call.
func TestTheConsoleCookieAuthenticatesButNeverOverridesAHeader(t *testing.T) {
	var seen string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
	})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/logs/console-authz", nil)
	r.AddCookie(&http.Cookie{Name: consoleCookie, Value: "flt_fromcookie"})
	cookieAsBearer(next).ServeHTTP(httptest.NewRecorder(), r)
	if seen != "Bearer flt_fromcookie" {
		t.Errorf("cookie did not authenticate the request: %q", seen)
	}

	r = httptest.NewRequest(http.MethodGet, "/api/v1/logs/console-authz", nil)
	r.Header.Set("Authorization", "Bearer real")
	r.AddCookie(&http.Cookie{Name: consoleCookie, Value: "flt_fromcookie"})
	cookieAsBearer(next).ServeHTTP(httptest.NewRecorder(), r)
	if seen != "Bearer real" {
		t.Errorf("the cookie replaced a real Authorization header: %q", seen)
	}
}
