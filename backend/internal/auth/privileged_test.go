package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveWith runs a request through mw carrying p as the authenticated principal,
// and reports whether the wrapped handler was reached.
func serveWith(t *testing.T, mw func(http.Handler) http.Handler, p *Principal) (int, string, bool) {
	t.Helper()
	reached := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/playbooks/x/run", nil)
	if p != nil {
		req = req.WithContext(withPrincipal(req.Context(), p))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), reached
}

// The gap this closes: Playbook.Run, remediation-apply, and support-bundle
// collection all execute as root on the target, but Host.Sudo used to gate only
// interactive sessions. A role that granted the automation permission while
// withholding Host.Sudo therefore handed out root anyway, and the operator who
// withheld it had no way to tell.
func TestPrivilegedPermissionRequiresHostSudo(t *testing.T) {
	mw := (&Service{}).RequirePrivilegedPermission("Playbook.Run")

	// The arrangement that used to succeed: the automation permission, deliberately
	// without Host.Sudo.
	code, body, reached := serveWith(t, mw, &Principal{
		Permissions: map[string]bool{"Playbook.Run": true},
	})
	if reached {
		t.Fatal("a user denied Host.Sudo reached a root-level playbook run")
	}
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
	if !strings.Contains(body, "Host.Sudo") {
		t.Errorf("the denial must name the missing permission so it is actionable, got %q", body)
	}

	// Both permissions: allowed. This is the builtin Administrator role, so the
	// change must be a no-op for a default deployment.
	if _, _, reached := serveWith(t, mw, &Principal{
		Permissions: map[string]bool{"Playbook.Run": true, "Host.Sudo": true},
	}); !reached {
		t.Error("holding both permissions must still be allowed")
	}

	// Super admins and Admin.All hold everything through the wildcard.
	if _, _, reached := serveWith(t, mw, &Principal{IsSuperAdmin: true}); !reached {
		t.Error("super admin must be allowed")
	}
	if _, _, reached := serveWith(t, mw, &Principal{
		Permissions: map[string]bool{"Admin.All": true},
	}); !reached {
		t.Error("Admin.All must be allowed")
	}
}

// The base permission still has to be checked first, and its denial must name the
// base permission — not Host.Sudo — or the message misdirects the operator.
func TestPrivilegedPermissionStillChecksTheBasePermission(t *testing.T) {
	mw := (&Service{}).RequirePrivilegedPermission("Playbook.Run")

	code, body, reached := serveWith(t, mw, &Principal{
		Permissions: map[string]bool{"Host.Sudo": true},
	})
	if reached {
		t.Fatal("Host.Sudo alone must not authorize a playbook run")
	}
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
	if !strings.Contains(body, "Playbook.Run") || strings.Contains(body, "also requires") {
		t.Errorf("denial should cite the missing base permission, got %q", body)
	}

	if code, _, reached := serveWith(t, mw, nil); reached || code != http.StatusUnauthorized {
		t.Errorf("unauthenticated request: code = %d, reached = %v; want 401 and no handler", code, reached)
	}
}
