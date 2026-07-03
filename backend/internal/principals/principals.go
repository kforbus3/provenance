// Package principals defines the SSH certificate principal names Fleet Terminal
// uses to authorize a certificate to a managed-host account, and the helpers
// that make those principals host-scoped.
//
// Two models coexist so host scoping can be rolled out without breaking already
// enrolled hosts:
//
//   - Global principals ("fleet" / "fleet-login") are trusted by every host. A
//     certificate carrying one authenticates to ANY enrolled host — convenient,
//     but it means a leaked certificate is usable fleet-wide.
//   - Host-scoped principals ("fleet-h-<hostID>" / "fleet-login-h-<hostID>") are
//     trusted by exactly one host. A certificate carrying only a host-scoped
//     principal authenticates to that single host and is rejected everywhere
//     else, so it cannot be replayed against hosts the user was never granted.
//
// Enrollment writes the accepted principals into each host's
// AuthorizedPrincipalsFile; issuance stamps the matching principals into the
// certificate. Both derive the host-scoped name from the host's stable UUID, so
// they always agree without extra coordination.
package principals

import "github.com/google/uuid"

const (
	// Global is the fleet-wide privileged (sudo) principal.
	Global = "fleet"
	// GlobalLogin is the fleet-wide login-only (no sudo) principal.
	GlobalLogin = "fleet-login"
)

// Host returns the privileged principal scoped to a single host.
func Host(id uuid.UUID) string { return "fleet-h-" + id.String() }

// HostLogin returns the login-only principal scoped to a single host.
func HostLogin(id uuid.UUID) string { return "fleet-login-h-" + id.String() }
