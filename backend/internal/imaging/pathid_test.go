package imaging

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// A machine id survives the round trip through the URL path.
//
// Machine ids are MAC addresses, and a MAC has colons in it. Go sets
// URL.RawPath whenever the decoded path differs from the raw, chi routes on
// RawPath when set, and chi.URLParam then hands back the STILL-ENCODED segment.
// So a client that percent-encodes the id — correct HTTP, and what every client
// in this product does — sent "bc%3A24%3A11%3Afd%3Ac8%3Ac0" and the handler
// looked up a machine by that literal string.
//
// Every per-machine action 404'd because of it: pair, hold, check in now,
// install directly, forget. And an id with nothing to encode worked perfectly,
// so the routes looked fine to anything that tested them with a simple string —
// which is exactly what a test would have used.
func TestMachineIDSurvivesPercentEncoding(t *testing.T) {
	const mac = "bc:24:11:fd:c8:c0"

	cases := []struct {
		name, path string
	}{
		{"percent-encoded colons (what the UI sends)", "/m/bc%3A24%3A11%3Afd%3Ac8%3Ac0"},
		{"literal colons (also legal in a path segment)", "/m/" + mac},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got string
			r := chi.NewRouter()
			r.Get("/m/{id}", func(w http.ResponseWriter, req *http.Request) {
				got = pathID(req, "id")
			})
			r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, c.path, nil))

			if got != mac {
				t.Errorf("id read from the path = %q, want %q.\n"+
					"Every per-machine action looks the machine up by this string; "+
					"when it does not match, they all return 404 and the UI looks "+
					"like it is doing nothing.", got, mac)
			}
		})
	}
}

// An id needing no encoding must be unaffected — that is the case that always
// worked and must keep working.
func TestPlainMachineIDIsUnchanged(t *testing.T) {
	var got string
	r := chi.NewRouter()
	r.Get("/m/{id}", func(w http.ResponseWriter, req *http.Request) { got = pathID(req, "id") })
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/m/test", nil))
	if got != "test" {
		t.Errorf("id = %q, want %q", got, "test")
	}
}

// There is deliberately no test for a malformed escape like "/m/bc%ZZ": such a
// URL cannot be parsed into a Request at all, so it never reaches the router and
// the fallback in pathID is unreachable over HTTP. The fallback stays anyway --
// it costs nothing and it is the right behaviour if that ever changes -- but a
// test asserting it would only be exercising net/http.
