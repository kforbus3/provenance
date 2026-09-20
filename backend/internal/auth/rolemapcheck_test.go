package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The roles this product actually ships with.
var realRoles = []string{"Administrator", "Auditor", "Operator", "Read-Only", "Super Administrator"}

type fakeRoleStore struct {
	roles []string
	err   error
}

func (f *fakeRoleStore) RoleNames(context.Context) ([]string, error) {
	return f.roles, f.err
}

func (f *fakeRoleStore) UnknownRoleNames(_ context.Context, names []string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	known := map[string]bool{}
	for _, r := range f.roles {
		known[r] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		if n == "" || seen[n] || known[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, nil
}

func check(t *testing.T, defaultRole string, m map[string]string) (bool, int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	ok := checkRoleMapping(context.Background(), w, &fakeRoleStore{roles: realRoles}, defaultRole, m)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	msg, _ := body["error"].(string)
	if msg == "" {
		msg, _ = body["message"].(string)
	}
	return ok, w.Code, msg
}

// The exact configuration that was saved against a live Keycloak, accepted with
// {"saved": true}, and granted one of its three mappings.
//
// prov-admins → "Admin" and prov-readonly → "Viewer" name nothing. Both users
// then authenticated perfectly -- right identity, right email, group claim read --
// and held no permissions at all. Nothing was logged. Nothing about the saved
// configuration looked wrong. The symptom is a person who can sign in and cannot
// do anything, which looks like a permissions problem everywhere except where the
// cause is.
func TestTheMappingThatSilentlyGrantedNothingIsRefused(t *testing.T) {
	ok, code, msg := check(t, "Viewer", map[string]string{
		"prov-admins":    "Admin",
		"prov-operators": "Operator",
		"prov-readonly":  "Viewer",
	})
	if ok {
		t.Fatal("a mapping onto roles that do not exist was accepted")
	}
	if code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", code)
	}
	for _, want := range []string{`"Admin"`, `"Viewer"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not name %s: %q", want, msg)
		}
	}
	// "Operator" was the one mapping that worked. Naming it as a problem would
	// send the operator to fix the only line that was right.
	if strings.Contains(msg, `"Operator"`) {
		t.Errorf("the refusal blames a role that does exist: %q", msg)
	}
	// The whole difficulty is not knowing the names, so the message carries them.
	for _, want := range []string{"Administrator", "Read-Only"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not list the valid role %s: %q", want, msg)
		}
	}
}

func TestACorrectMappingIsAccepted(t *testing.T) {
	ok, _, msg := check(t, "Read-Only", map[string]string{
		"prov-admins":    "Administrator",
		"prov-operators": "Operator",
		"prov-readonly":  "Read-Only",
	})
	if !ok {
		t.Errorf("a valid mapping was refused: %q", msg)
	}
}

// An empty configuration is how SSO is disabled, and how it looks before anything
// has been filled in. It must not be refused.
func TestAnEmptyMappingIsAccepted(t *testing.T) {
	if ok, _, msg := check(t, "", nil); !ok {
		t.Errorf("an empty mapping was refused: %q", msg)
	}
	if ok, _, msg := check(t, "", map[string]string{"some-group": ""}); !ok {
		t.Errorf("a mapping with no role set was refused: %q", msg)
	}
}

// The default role is the one every auto-provisioned user gets, so a wrong one
// there affects everybody rather than one group.
func TestABadDefaultRoleIsRefusedOnItsOwn(t *testing.T) {
	ok, _, msg := check(t, "Viewer", nil)
	if ok {
		t.Fatal("a default role that names nothing was accepted")
	}
	if !strings.Contains(msg, `"Viewer"`) {
		t.Errorf("the refusal does not name the bad default role: %q", msg)
	}
}

// The same mistake must produce the same sentence twice: map iteration order
// would otherwise shuffle the names between two identical requests.
func TestTheRefusalIsStable(t *testing.T) {
	m := map[string]string{"g1": "Nope1", "g2": "Nope2", "g3": "Nope3", "g4": "Nope4"}
	_, _, first := check(t, "", m)
	for i := 0; i < 8; i++ {
		if _, _, again := check(t, "", m); again != first {
			t.Fatalf("the message varies between identical requests:\n  %q\n  %q", first, again)
		}
	}
}

// A store that cannot answer must not be read as "every role is fine".
func TestAFailedLookupDoesNotWaveTheConfigurationThrough(t *testing.T) {
	w := httptest.NewRecorder()
	ok := checkRoleMapping(context.Background(), w,
		&fakeRoleStore{err: errors.New("database is down")}, "Administrator", nil)
	if ok {
		t.Error("the configuration was accepted although the roles could not be read")
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", w.Code)
	}
}
