package imaging

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/tenant"
)

// Every route a MACHINE posts to must reach its handler with a tenant set.
//
// These are the only writes in the product that arrive with no principal at all:
// a machine on a provisioning segment has no session, no user and therefore no
// tenant, while imaging_machines is row-level-security protected with tenant_id
// defaulting to prov_current_tenant(). On a multi-tenant instance every heartbeat
// was refused —
//
//	new row violates row-level security policy for table "imaging_machines"
//
// — and the endpoint answered 200 anyway, because a heartbeat that cannot be
// recorded must not make a machine retry forever. So machines could never
// register, never appeared on the Machines page, and could never be targeted by a
// rollout, while each one was told every five minutes that it had checked in. The
// entire A/B update path was dead on a multi-tenant instance and nothing said so.
//
// Found by pointing a real imaged machine at a real instance and asking why it
// never showed up.
func TestMachineIntakeRoutesCarryATenant(t *testing.T) {
	// Every path a machine posts to, as mounted by Mount and mountImager.
	paths := []string{
		"/imaging/heartbeat",
		"/imaging/report",
		"/imaging/checkin",
		"/api/fleet/heartbeat",
		"/api/prov/heartbeat",
		"/api/imaging/report",
		"/api/imaging/checkin",
	}

	seen := map[string]string{}
	r := chi.NewRouter()
	record := func(w http.ResponseWriter, req *http.Request) {
		seen[req.URL.Path] = tenant.GUCValue(req.Context())
		w.WriteHeader(http.StatusOK)
	}
	// The same grouping the real Mount uses. If the bypass is dropped from either
	// group, the corresponding paths come back with "".
	r.Group(func(mr chi.Router) {
		mr.Use(auth.TenantBypass)
		mr.Post("/imaging/heartbeat", record)
		mr.Post("/imaging/report", record)
		mr.Post("/imaging/checkin", record)
	})
	r.Group(func(mr chi.Router) {
		mr.Use(auth.TenantBypass)
		mr.Post("/api/fleet/heartbeat", record)
		mr.Post("/api/prov/heartbeat", record)
		mr.Post("/api/imaging/report", record)
		mr.Post("/api/imaging/checkin", record)
	})

	for _, p := range paths {
		req := httptest.NewRequest(http.MethodPost, p, strings.NewReader("id=probe"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(httptest.NewRecorder(), req)
	}

	for _, p := range paths {
		got, ok := seen[p]
		if !ok {
			t.Errorf("%s was not routed at all", p)
			continue
		}
		// "" is the deny case — the value that refused every write.
		if got == "" {
			t.Errorf("%s reaches its handler with no tenant; every write it makes is "+
				"refused by row-level security and the machine is told 200", p)
		}
		if got != tenant.Bypass {
			t.Errorf("%s carries tenant %q, want the bypass sentinel: a machine has no "+
				"tenant of its own, so intake cannot be scoped to one", p, got)
		}
	}
}

// And the routes a PERSON uses must NOT be bypassed — the fix must not widen
// past machine intake.
func TestTheBypassDoesNotLeakToOperatorRoutes(t *testing.T) {
	var got string
	r := chi.NewRouter()
	r.Group(func(mr chi.Router) {
		mr.Use(auth.TenantBypass)
		mr.Post("/imaging/heartbeat", func(http.ResponseWriter, *http.Request) {})
	})
	// Mounted outside that group, as every authenticated imaging route is.
	r.Get("/imaging/machines", func(_ http.ResponseWriter, req *http.Request) {
		got = tenant.GUCValue(req.Context())
	})

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/imaging/machines", nil))
	if got == tenant.Bypass {
		t.Error("an operator route inherited the machine-intake bypass, so one tenant " +
			"would see every tenant's machines")
	}
}
