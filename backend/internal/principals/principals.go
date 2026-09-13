// Package principals defines the SSH certificate principal names Provenance
// uses to authorize a certificate to a managed-host account, and the helpers
// that make those principals host-scoped.
//
// Two models coexist so host scoping can be rolled out without breaking already
// enrolled hosts:
//
//   - Global principals ("fleet" / "prov-login") are trusted by every host. A
//     certificate carrying one authenticates to ANY enrolled host — convenient,
//     but it means a leaked certificate is usable fleet-wide.
//   - Host-scoped principals ("prov-h-<hostID>" / "prov-login-h-<hostID>") are
//     trusted by exactly one host. A certificate carrying only a host-scoped
//     principal authenticates to that single host and is rejected everywhere
//     else, so it cannot be replayed against hosts the user was never granted.
//
// Enrollment writes the accepted principals into each host's
// AuthorizedPrincipalsFile; issuance stamps the matching principals into the
// certificate. Both derive the host-scoped name from the host's stable UUID, so
// they always agree without extra coordination.
package principals

import (
	"strings"

	"github.com/google/uuid"
)

const (
	// Global is the fleet-wide privileged (sudo) principal.
	Global = "prov"
	// GlobalLogin is the fleet-wide login-only (no sudo) principal.
	GlobalLogin = "prov-login"

	hostPrefix      = "prov-h-"
	hostLoginPrefix = "prov-login-h-"
)

// The pre-rename spellings. A host enrolled before the rename has these written
// into its AuthorizedPrincipalsFile, and sshd — not the backend — is what enforces
// them, so they cannot be retired by deploying new code. They stop being issued
// once every host has been migrated to the new account (see WithLegacy).
const (
	// LegacyGlobal is the pre-rename spelling of Global.
	LegacyGlobal = "fleet"
	// LegacyGlobalLogin is the pre-rename spelling of GlobalLogin.
	LegacyGlobalLogin = "fleet-login"

	legacyHostPrefix      = "fleet-h-"
	legacyHostLoginPrefix = "fleet-login-h-"
)

// Host returns the privileged principal scoped to a single host.
func Host(id uuid.UUID) string { return hostPrefix + id.String() }

// HostLogin returns the login-only principal scoped to a single host.
func HostLogin(id uuid.UUID) string { return hostLoginPrefix + id.String() }

// LegacyHost is the pre-rename spelling of Host.
func LegacyHost(id uuid.UUID) string { return legacyHostPrefix + id.String() }

// LegacyHostLogin is the pre-rename spelling of HostLogin.
func LegacyHostLogin(id uuid.UUID) string { return legacyHostLoginPrefix + id.String() }

// WithLegacy returns in with the pre-rename counterpart of every Provenance
// principal appended, so one certificate authenticates both to hosts already
// migrated to the new account names and to hosts still on the old ones.
//
// The mapping is strictly one-for-one and never crosses the privilege boundary:
// the privileged principals map to each other and the login-only principals map to
// each other. That matters because SystemHostLoginPrincipals deliberately omits
// the privileged principal so a certificate minted for the no-sudo account cannot
// open the privileged one; adding legacy names must not quietly undo that.
//
// Principals with no legacy spelling (the informational "user:<name>") pass through.
func WithLegacy(in []string) []string {
	out := make([]string, 0, len(in)*2)
	for _, p := range in {
		out = append(out, p)
		if l, ok := legacyOf(p); ok {
			out = append(out, l)
		}
	}
	return dedupe(out)
}

// legacyOf maps one principal to the name it had before the rename.
func legacyOf(p string) (string, bool) {
	switch p {
	case Global:
		return LegacyGlobal, true
	case GlobalLogin:
		return LegacyGlobalLogin, true
	}
	// Check the login-scoped prefix first. It is not a prefix of hostPrefix, but
	// testing the more specific name first keeps that a property of the code rather
	// than of the two string constants happening not to overlap.
	if id, ok := strings.CutPrefix(p, hostLoginPrefix); ok {
		return legacyHostLoginPrefix + id, true
	}
	if id, ok := strings.CutPrefix(p, hostPrefix); ok {
		return legacyHostPrefix + id, true
	}
	return "", false
}

// dedupe drops empty and repeated principals, preserving first-seen order.
func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// User returns the informational, namespaced principal for a Provenance username. It
// is embedded in a certificate for provenance only and matches no host's
// AuthorizedPrincipalsFile. The "user:" prefix ensures a username can never
// collide with a "fleet"/"prov-h-<id>" principal and thus can never be abused to
// gain access — even if the username were chosen adversarially.
func User(name string) string { return "user:" + name }
