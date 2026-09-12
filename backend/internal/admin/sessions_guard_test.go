package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// The per-session terminate route must be gated exactly like the bulk one.
//
// This is the shape the bug takes when a narrower endpoint is added beside a
// wider one: /users/{id}/terminate-sessions has always required
// Session.Terminate and refused a super-administrator target, and a new
// DELETE /sessions/{id} that forgot either check would be a way around both. An
// admin who may not end a super-administrator's sessions could end them one at a
// time and reach the identical result.
//
// Asserted against the source rather than over HTTP because the alternative
// needs a database, and a check that only runs where a database happens to be
// configured is a check that does not run. What it costs is that it proves the
// call is written, not that it fires -- so it is paired with the behavioural
// bound in TestListActiveSessionsExcludesEnded.
func parseAdmin(t *testing.T, file string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return fset, f
}

// bodyOf returns the source text of a top-level function.
func bodyOf(t *testing.T, file, name string) string {
	t.Helper()
	fset, f := parseAdmin(t, file)
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		start := fset.Position(fn.Pos()).Offset
		end := fset.Position(fn.End()).Offset
		src := readFile(t, file)
		return src[start:end]
	}
	t.Fatalf("no func %s in %s", name, file)
	return ""
}

func TestTerminateSessionGuardsSuperAdmin(t *testing.T) {
	body := bodyOf(t, "users.go", "terminateSession")

	if !strings.Contains(body, "guardSuperTarget") {
		t.Error("terminateSession does not call guardSuperTarget: an admin who may " +
			"not terminate a super-administrator's sessions could end them one at a " +
			"time through this route")
	}

	// store.RevokeSession marks the row and nothing else -- the terminal stays
	// open, the certificate stays valid, the key stays in memory. An operator
	// told "session terminated" would be wrong in the way that matters most.
	if strings.Contains(body, "Store.RevokeSession") {
		t.Error("terminateSession calls Store.RevokeSession, which only marks the " +
			"row; it must use Auth.DestroySession so the live terminal is closed " +
			"and the certificate revoked")
	}
	if !strings.Contains(body, "Auth.DestroySession") {
		t.Error("terminateSession must end the session through Auth.DestroySession")
	}

	// A state change an operator can make must be attributable.
	if !strings.Contains(body, "h.audit(") {
		t.Error("terminateSession does not write an audit entry")
	}
}

// NOTE: this asserts the route is mounted and gated. It cannot see another
// module registering the same path -- which is exactly what happened: /sessions
// already belonged to the SSH recordings api, chi took that one, and this test
// passed while the screen showed recordings. Collisions are checked across every
// module by deploy/builder-runner/test_route_collisions.py.
func TestSessionRoutesRequireTerminatePermission(t *testing.T) {
	src := readFile(t, "admin.go")

	for _, want := range []string{
		`RequirePermission("Session.Terminate")).Get("/active-sessions"`,
		`RequirePermission("Session.Terminate")).Delete("/active-sessions/{id}"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("admin.go does not mount a route gated as: %s\n"+
				"Both the list and the revoke are oversight capabilities and must "+
				"carry the same permission the bulk terminate does.", want)
		}
	}

	// Every route in this file is inside the RequireAuth group; a session route
	// added outside it would be unauthenticated. Cheap to assert, and the thing
	// nobody re-reads once the group is long.
	if strings.Count(src, "d.Auth.RequireAuth") < 1 {
		t.Error("admin routes are not behind RequireAuth")
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
