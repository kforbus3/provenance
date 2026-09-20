package auth

import (
	"sort"
	"testing"
	"time"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// TestIdpAccountConflictBlocksLocalTakeover is the regression for the LDAP
// account-takeover blocker: a directory entry whose uid/mail collides with an
// existing LOCAL-password account must be treated as a conflict, never authenticated
// as that account. The same guard protects the OIDC and SAML paths, and the
// bootstrap super-admin is off-limits to every external source. Without the guard
// (the old LDAP path had none) the local/"" and super-admin cases below would be
// allowed — this test fails against that code.
func TestIdpAccountConflictBlocksLocalTakeover(t *testing.T) {
	cases := []struct {
		name   string
		user   models.User
		source string
		want   bool // true = conflict (login refused)
	}{
		// The takeover the fix closes: an LDAP uid matches a local-password account.
		{"ldap onto local-password account", models.User{AuthSource: "local"}, "ldap", true},
		// A local account created before AuthSource was stamped has an empty source;
		// it is still a local account and must not be assumable by the directory.
		{"ldap onto unset (legacy local) account", models.User{AuthSource: ""}, "ldap", true},
		// The bootstrap super-admin is never assumable, whatever its source.
		{"ldap onto super-admin", models.User{AuthSource: "ldap", IsSuperAdmin: true}, "ldap", true},
		{"oidc onto super-admin", models.User{AuthSource: "oidc", IsSuperAdmin: true}, "oidc", true},
		// Cross-source collisions are conflicts too.
		{"ldap onto oidc account", models.User{AuthSource: "oidc"}, "ldap", true},
		{"oidc onto saml account", models.User{AuthSource: "saml"}, "oidc", true},
		// The legitimate re-login case: a directory-owned account authenticating via
		// its own source must be allowed.
		{"ldap re-login of ldap account", models.User{AuthSource: "ldap"}, "ldap", false},
		{"oidc re-login of oidc account", models.User{AuthSource: "oidc"}, "oidc", false},
		{"saml re-login of saml account", models.User{AuthSource: "saml"}, "saml", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := tc.user
			if got := idpAccountConflict(&u, tc.source); got != tc.want {
				t.Errorf("idpAccountConflict(%+v, %q) = %v, want %v", tc.user, tc.source, got, tc.want)
			}
		})
	}
}

// TestReconcileGroupRoleActionsIsAuthoritative verifies the group→role sync is
// authoritative for IdP-managed roles (adds AND removes) while never touching
// locally-assigned roles. The value set of the mapping is the IdP-managed universe.
func TestReconcileGroupRoleActionsIsAuthoritative(t *testing.T) {
	mapping := map[string]string{
		"cn=admins":    "Administrator",
		"cn=ops":       "Operator",
		"cn=readonly":  "Read-Only",
		"cn=empty-map": "", // ignored: maps to no role
	}

	sortStrs := func(s []string) []string { sort.Strings(s); return s }
	eq := func(a, b []string) bool {
		a, b = sortStrs(a), sortStrs(b)
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	// No default role in these cases (the "" argument): with one configured the
	// floor is never revoked, which has its own test below.
	//
	// User is currently in cn=admins only. Operator/Read-Only are IdP-managed roles
	// the user no longer has a group for → must be revoked. Administrator → assigned.
	add, remove := reconcileGroupRoleActions(mapping, []string{"cn=admins"}, "")
	if !eq(add, []string{"Administrator"}) {
		t.Errorf("add = %v, want [Administrator]", add)
	}
	if !eq(remove, []string{"Operator", "Read-Only"}) {
		t.Errorf("remove = %v, want [Operator Read-Only]", remove)
	}

	// A group not in the mapping (cn=other) contributes nothing; "Read-Only" and
	// "Operator" remain in the remove set because no current group grants them.
	add, remove = reconcileGroupRoleActions(mapping, []string{"cn=admins", "cn=ops", "cn=other"}, "")
	if !eq(add, []string{"Administrator", "Operator"}) {
		t.Errorf("add = %v, want [Administrator Operator]", add)
	}
	if !eq(remove, []string{"Read-Only"}) {
		t.Errorf("remove = %v, want [Read-Only]", remove)
	}

	// No groups: every IdP-managed role is revoked, none assigned. A locally-assigned
	// role (never a value in the mapping) is by construction absent from both lists,
	// so it is never disturbed.
	add, remove = reconcileGroupRoleActions(mapping, nil, "")
	if len(add) != 0 {
		t.Errorf("add = %v, want empty", add)
	}
	if !eq(remove, []string{"Administrator", "Operator", "Read-Only"}) {
		t.Errorf("remove = %v, want all managed roles", remove)
	}

	// An empty mapping is a no-op in both directions (feature unconfigured).
	if add, remove = reconcileGroupRoleActions(nil, []string{"cn=admins"}, ""); add != nil || remove != nil {
		t.Errorf("empty mapping: add=%v remove=%v, want nil/nil", add, remove)
	}
}

// TestSAMLReplayCacheRejectsReplays verifies the assertion-ID replay guard: a fresh
// ID is accepted once, an immediate re-presentation is rejected, and the entry
// expires after its TTL so a genuinely new (later) assertion with a reused ID is
// accepted again once the window passes.
func TestSAMLReplayCacheRejectsReplays(t *testing.T) {
	c := newAssertionReplayCache(10 * time.Minute)
	base := time.Now()

	if c.observe("assertion-1", base) {
		t.Fatal("first sighting of an ID must not be a replay")
	}
	if !c.observe("assertion-1", base.Add(time.Second)) {
		t.Error("re-presenting the same ID within the window must be a replay")
	}
	// A different ID is independent.
	if c.observe("assertion-2", base.Add(time.Second)) {
		t.Error("a distinct ID must not be treated as a replay")
	}
	// After the TTL the entry is evicted; the ID may legitimately recur.
	if c.observe("assertion-1", base.Add(11*time.Minute)) {
		t.Error("after the TTL the ID must no longer be considered a replay")
	}
}

// The default role is a floor, and must survive a reconciliation that finds the
// user in none of the mapped groups.
//
// This configuration is the ordinary one, and it was broken:
//
//	defaultRole:  "Read-Only"
//	groupRoleMap: {"prov-admins": "Administrator", "prov-readonly": "Read-Only"}
//
// Read-Only is both the floor and a mapped value. A user in none of the mapped
// groups was provisioned with Read-Only and then stripped of it by this
// reconciliation inside the same login, finishing with no roles at all — while the
// configuration said every SSO user gets Read-Only. Seen against a live Keycloak:
// the user in no mapped group ended with (NONE), and the only reason the other
// three looked right is that their groups happened to grant the same role back.
func TestTheDefaultRoleIsNeverRevokedByGroupReconciliation(t *testing.T) {
	mapping := map[string]string{
		"prov-admins":    "Administrator",
		"prov-operators": "Operator",
		"prov-readonly":  "Read-Only",
	}
	has := func(list []string, want string) bool {
		for _, v := range list {
			if v == want {
				return true
			}
		}
		return false
	}

	// In no mapped group at all: the floor stays.
	add, remove := reconcileGroupRoleActions(mapping, nil, "Read-Only")
	if has(remove, "Read-Only") {
		t.Errorf("the default role is revoked for a user in no mapped group: remove=%v", remove)
	}
	if has(add, "Read-Only") {
		t.Errorf("the default role is re-granted on every login: add=%v — provisioning "+
			"grants it once, and re-imposing a role an administrator removed is a "+
			"different wrong answer", add)
	}
	// The roles that genuinely are group-conferred are still revoked: this must not
	// turn into "nothing is ever taken away".
	for _, want := range []string{"Administrator", "Operator"} {
		if !has(remove, want) {
			t.Errorf("%s was not revoked for a user in no group: remove=%v", want, remove)
		}
	}

	// And in a group that does grant the floor, it is granted rather than skipped.
	add, _ = reconcileGroupRoleActions(mapping, []string{"prov-readonly"}, "Read-Only")
	if !has(add, "Read-Only") {
		t.Errorf("a user whose group grants the default role was not granted it: add=%v", add)
	}

	// A default role outside the mapping is untouched either way, as before.
	_, remove = reconcileGroupRoleActions(mapping, nil, "Auditor")
	if has(remove, "Auditor") {
		t.Errorf("a default role outside the mapping appeared in remove: %v", remove)
	}
}
