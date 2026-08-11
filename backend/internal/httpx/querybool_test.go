package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// QueryBool gates destructive opt-ins (host teardown on delete), so it has to fail
// closed. A typo, an unexpected spelling, or a client that sends the parameter with
// no value must all read as "not asked for" — the failure mode of the other
// direction is tearing a host down that the operator only meant to un-inventory.
func TestQueryBoolFailsClosed(t *testing.T) {
	ask := func(q string) bool {
		r := httptest.NewRequest(http.MethodDelete, "/api/v1/hosts/x"+q, nil)
		return QueryBool(r, "teardown")
	}

	for _, q := range []string{"?teardown=true", "?teardown=1", "?teardown=yes", "?teardown=on",
		"?teardown=TRUE", "?teardown=True",
		// Percent-encoded surrounding whitespace, which is what a client actually sends.
		"?teardown=%20true%20"} {
		if !ask(q) {
			t.Errorf("%q should opt in", q)
		}
	}

	for _, q := range []string{
		"",                // absent
		"?teardown",       // present with no value
		"?teardown=",      // empty
		"?teardown=false", //
		"?teardown=0",     //
		"?teardown=no",    //
		"?teardown=ture",  // typo — must not opt in
		"?teardown=maybe", //
		"?teardown=2",     //
		"?teardowns=true", // different parameter
		"?ateardown=true", // different parameter
	} {
		if ask(q) {
			t.Errorf("%q must NOT opt in", q)
		}
	}
}
