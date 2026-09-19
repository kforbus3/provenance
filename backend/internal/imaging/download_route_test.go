package imaging

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/config"
)

// keith clicked Download on an image and got an error. Twice.
//
// The route carried a comment saying it was outside the bearer-only group so it could
// authenticate from a token in the URL -- which is what a browser navigation can
// actually send. The comment was the only thing that had been arranged: the route was
// registered by mountBuilds, mountBuilds is called with the authenticated group's
// router, and RequireAuth therefore ran first and answered "missing access token"
// before the handler ever looked at the URL.
//
// So this test drives the REAL router. It asserts the negative that matters -- the
// request is not rejected for having no Authorization header -- because that is the
// failure, and every version of this bug produces exactly that message.
//
// No database is touched either way: RequireAuth rejects before any lookup when the
// header is absent, and the handler's own check fails in ParseAccessToken. The two
// paths are told apart by which 401 comes back, which is the whole point.
func TestImageDownloadIsReachableWithoutABearerHeader(t *testing.T) {
	r := mountForTest(t)

	req := httptest.NewRequest(http.MethodGet, "/imaging/images/debian-trixie-amd64-ab.img.zst/download?token=nonsense", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, "missing access token") {
		t.Fatalf("the download route is behind RequireAuth again: a browser navigation "+
			"cannot send an Authorization header, so this is the Download button failing.\n"+
			"status %d, body %s", w.Code, body)
	}
	// It must still refuse a token that is not valid -- moving it out of the group
	// must not have moved it out of authentication.
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a nonsense token returned %d (%s); the route must authenticate itself", w.Code, body)
	}
}

// The neighbouring SBOM route is fetched by the app with a header, so it belongs
// inside the group. If it ever moves out, it loses its permission check.
func TestTheSBOMRouteStaysBehindTheHeaderCheck(t *testing.T) {
	r := mountForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/imaging/images/x/sbom", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "missing access token") {
		t.Errorf("the SBOM route no longer requires a bearer header: status %d, body %s", w.Code, w.Body.String())
	}
}

// mountForTest mounts the imaging routes with an auth service that has a signing key
// and nothing else. Registration only needs the middleware constructors, and neither
// authentication path reaches the store for the requests above.
func mountForTest(t *testing.T) chi.Router {
	t.Helper()
	cfg := &config.Config{JWTSecret: []byte("0123456789abcdef0123456789abcdef")}
	d := &app.Deps{
		Cfg:  cfg,
		Log:  slog.New(slog.DiscardHandler),
		Auth: auth.NewService(nil, cfg, slog.New(slog.DiscardHandler)),
	}
	r := chi.NewRouter()
	Mount(r, d, nil)
	return r
}
