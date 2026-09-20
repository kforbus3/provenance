package vulnscan

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/tenant"
)

// A scan runs after the request that started it has returned, so it needs a
// context that is not cancelled with the request -- and that still knows which
// tenant it is for.
//
// It used to get context.WithoutCancel(context.Background()), which is just
// context.Background(): no cancellation and no VALUES. Under multi-tenancy that
// made vulnerability scanning fail completely, and in a way that pointed nowhere
// near the cause. The scan row was created on the request's context so it landed
// in the right tenant; the scan itself ran, reached the host over SSH, and came
// back with findings; and then the insert was refused with
//
//	new row violates row-level security policy for table "vuln_findings"
//
// because vuln_findings.tenant_id defaults to prov_current_tenant(), which on a
// context with no tenant is nobody. Every manual scan on a multi-tenant instance
// finished as "failed" with nothing stored.
//
// This test is about the property that was missing rather than the whole handler:
// whatever context the goroutine is given must carry a tenant.
func TestADetachedContextMustStillCarryItsTenant(t *testing.T) {
	id := uuid.New().String()

	// What the code did before: cancellation dropped AND values dropped.
	broken := context.WithoutCancel(context.Background())
	if got := tenant.GUCValue(broken); got != "" {
		t.Fatalf("context.Background() somehow carries tenant %q", got)
	}

	// What it does now: a background context explicitly scoped to the tenant. The
	// request context is not carried wholesale into a goroutine that outlives it.
	scoped := tenant.WithID(context.Background(), id)
	if got := tenant.GUCValue(scoped); got != id {
		t.Errorf("tenant on the detached context is %q, want %q — an empty value is "+
			"the deny case, which is what refused every finding", got, id)
	}

	// And it must survive the thing that is actually done to it: dropping the
	// deadline. WithoutCancel keeps values; it was being handed a context that had
	// none to keep.
	if got := tenant.GUCValue(context.WithoutCancel(scoped)); got != id {
		t.Errorf("WithoutCancel lost the tenant: got %q", got)
	}
	dl, cancel := context.WithTimeout(scoped, 0)
	defer cancel()
	if got := tenant.GUCValue(dl); got != id {
		t.Errorf("WithTimeout lost the tenant: got %q", got)
	}
}
