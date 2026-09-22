package enrollment

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kforbus3/provenance/backend/internal/tenant"
)

// The bug these cover: enrollment ran on r.Context(), and the router caps every request
// at 60s (middleware.Timeout). The overlay verification waits up to 90s for the tunnel
// to carry traffic, so the cap always won — the run died mid-verify reporting the bare
// "context deadline exceeded", and because the WireGuard teardown is gated on that
// verification the host was left holding both transports.

// TestEnrollmentOutlivesTheRequest fails if enrollment is run on the request context:
// the returned context must still be live after the request's deadline has passed.
func TestEnrollmentOutlivesTheRequest(t *testing.T) {
	r := httptest.NewRequest("POST", "/hosts/x/enroll", nil)

	// Stand in for middleware.Timeout, with a deadline short enough to observe.
	reqCtx, cancel := context.WithTimeout(r.Context(), 20*time.Millisecond)
	defer cancel()
	r = r.WithContext(reqCtx)

	ctx, cancelEnroll := detachEnrollment(r)
	defer cancelEnroll()

	<-reqCtx.Done() // the request is over
	if err := reqCtx.Err(); err == nil {
		t.Fatal("precondition: the request context should have expired")
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("enrollment context died with the request: %v — the 60s cap is deciding "+
			"the outcome again, not the step", err)
	}
}

// TestEnrollmentKeepsTheResolvedTenant fails if the detach is written as
// context.Background(): this route passes through RequireAuth, so the tenant the
// middleware resolved (including a provider admin's X-Prov-Tenant switch) is only
// present in the request context. Losing it sends the enrollment to the wrong tenant,
// or has RLS deny the host lookup outright.
func TestEnrollmentKeepsTheResolvedTenant(t *testing.T) {
	const switched = "11111111-2222-3333-4444-555555555555"

	r := httptest.NewRequest("POST", "/hosts/x/enroll", nil)
	r = r.WithContext(tenant.WithID(r.Context(), switched))

	ctx, cancel := detachEnrollment(r)
	defer cancel()

	if got := tenant.GUCValue(ctx); got != switched {
		t.Fatalf("tenant lost when detaching: got %q, want %q", got, switched)
	}
}

// TestEnrollmentBudgetCoversOverlayVerify is the invariant the incident came down to.
// The budget an enrollment runs under has to exceed the longest single step inside it,
// or that step can never reach its own verdict.
func TestEnrollmentBudgetCoversOverlayVerify(t *testing.T) {
	if enrollmentBudget <= overlayVerifyWindow {
		t.Fatalf("enrollmentBudget %s does not cover overlayVerifyWindow %s: the overlay "+
			"verification cannot reach its own deadline, so a tunnel that is seconds from "+
			"working is reported as a failure", enrollmentBudget, overlayVerifyWindow)
	}
	// Also give the steps before the verification room: provisioning the jump server and
	// the host precede it and legitimately take minutes over SSH.
	if enrollmentBudget < 5*time.Minute {
		t.Fatalf("enrollmentBudget %s leaves too little for the provisioning steps that "+
			"run before the overlay verification", enrollmentBudget)
	}
}

// TestEnrollmentBudgetIsBounded guards the other direction: detaching must not mean
// "runs forever". A wedged enrollment has to end by itself.
func TestEnrollmentBudgetIsBounded(t *testing.T) {
	r := httptest.NewRequest("POST", "/hosts/x/enroll", nil)
	ctx, cancel := detachEnrollment(r)
	defer cancel()

	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("detached enrollment context has no deadline of its own")
	}
	if left := time.Until(dl); left > enrollmentBudget+time.Second {
		t.Fatalf("deadline %s is further out than the budget %s", left, enrollmentBudget)
	}
}
