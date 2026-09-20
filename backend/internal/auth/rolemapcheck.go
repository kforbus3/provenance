package auth

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// checkRoleMapping refuses an identity-provider configuration whose role names do
// not name roles, and writes the refusal.
//
// This is the gate; the logging in reconcileGroupRoles is the net behind it.
//
// Three Keycloak groups were mapped onto Provenance roles -- prov-admins →
// "Admin", prov-operators → "Operator", prov-readonly → "Viewer" -- and the
// configuration saved with {"saved": true}. Provenance's roles are called
// Administrator, Operator, Read-Only and Auditor, so exactly one of the three
// mappings did anything. All three users then authenticated perfectly: correct
// identity, correct email, group claim present and read. The two whose role names
// did not exist held no permissions at all, nothing appeared in the log, and
// nothing about the configuration looked wrong.
//
// That failure is very likely on a first SSO setup, because "Admin" and "Viewer"
// are what most products call these, and its symptom -- a person who can log in
// and then cannot do anything -- looks like a permissions problem anywhere except
// where the cause is.
//
// Returns true when the configuration is acceptable and the caller should carry
// on saving.
func checkRoleMapping(ctx context.Context, w http.ResponseWriter, st roleNameStore,
	defaultRole string, groupRoleMap map[string]string) bool {
	names := []string{defaultRole}
	// Sorted, so the message is stable rather than in map order: the same mistake
	// should produce the same sentence twice.
	groups := make([]string, 0, len(groupRoleMap))
	for g := range groupRoleMap {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	for _, g := range groups {
		names = append(names, groupRoleMap[g])
	}

	unknown, err := st.UnknownRoleNames(ctx, names)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not check the configured role names")
		return false
	}
	if len(unknown) == 0 {
		return true
	}
	valid, err := st.RoleNames(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not check the configured role names")
		return false
	}
	// The valid names are included because the whole difficulty is not knowing
	// them. An error that says only "unknown role" leaves the operator guessing at
	// the spelling that was already wrong.
	writeError(w, http.StatusBadRequest, fmt.Sprintf(
		"no role is named %s. Nothing would be granted to anyone mapped to %s, and they "+
			"would be able to sign in and do nothing. The roles on this instance are: %s.",
		quoteList(unknown), plural(len(unknown), "it", "them"), strings.Join(valid, ", ")))
	return false
}

// roleNameStore is the part of the store this check needs, so the three config
// handlers can be tested without one.
type roleNameStore interface {
	RoleNames(ctx context.Context) ([]string, error)
	UnknownRoleNames(ctx context.Context, names []string) ([]string, error)
}

func quoteList(s []string) string {
	q := make([]string, len(s))
	for i, v := range s {
		q[i] = `"` + v + `"`
	}
	if len(q) <= 2 {
		return strings.Join(q, " or ")
	}
	return strings.Join(q[:len(q)-1], ", ") + " or " + q[len(q)-1]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
