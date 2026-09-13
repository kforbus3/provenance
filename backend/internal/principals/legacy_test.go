package principals

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Certificates must carry the pre-rename spelling of every principal. Hosts
// enrolled before the rename have those names in their AuthorizedPrincipalsFile
// and it is sshd that checks them, so a certificate carrying only the new names
// authenticates to nothing that has not been migrated yet.
func TestWithLegacyCarriesBothSpellings(t *testing.T) {
	id := uuid.MustParse("abcdef01-2345-6789-abcd-ef0123456789")

	got := WithLegacy([]string{Global, Host(id)})
	for _, want := range []string{Global, LegacyGlobal, Host(id), LegacyHost(id)} {
		if !slices.Contains(got, want) {
			t.Errorf("privileged set %v is missing %q", got, want)
		}
	}

	got = WithLegacy([]string{GlobalLogin, HostLogin(id)})
	for _, want := range []string{GlobalLogin, LegacyGlobalLogin, HostLogin(id), LegacyHostLogin(id)} {
		if !slices.Contains(got, want) {
			t.Errorf("login-only set %v is missing %q", got, want)
		}
	}
}

// The mapping must never cross the privilege boundary. SystemHostLoginPrincipals
// deliberately omits the privileged principal so a certificate minted for the
// no-sudo account cannot open the privileged one; if the legacy expansion added
// "fleet" to a login-only set it would hand back exactly that privilege on every
// host not yet migrated — silently, and only on the old hosts.
func TestWithLegacyNeverAddsAPrivilegedPrincipalToALoginOnlySet(t *testing.T) {
	id := uuid.MustParse("abcdef01-2345-6789-abcd-ef0123456789")

	got := WithLegacy([]string{GlobalLogin, HostLogin(id), User("alice")})
	for _, banned := range []string{Global, LegacyGlobal, Host(id), LegacyHost(id)} {
		if slices.Contains(got, banned) {
			t.Fatalf("login-only set %v gained privileged principal %q", got, banned)
		}
	}
}

// "prov-login-h-<id>" starts with neither "prov-h-" nor a bare prefix of it, but
// the check must be on the code rather than on the two constants happening not to
// overlap: mapping it with the privileged prefix would produce "fleet-h-login-h-…",
// a principal no host trusts, and the login-only account would stop working on
// every un-migrated host.
func TestHostLoginPrincipalMapsToItsOwnLegacyName(t *testing.T) {
	id := uuid.MustParse("abcdef01-2345-6789-abcd-ef0123456789")
	got := WithLegacy([]string{HostLogin(id)})
	if !slices.Contains(got, LegacyHostLogin(id)) {
		t.Fatalf("%v does not contain %q", got, LegacyHostLogin(id))
	}
	for _, p := range got {
		if strings.HasPrefix(p, legacyHostPrefix) {
			t.Fatalf("login-only principal mapped onto the privileged legacy prefix: %q", p)
		}
	}
}

// The informational username principal has no legacy spelling and must pass
// through untouched — it matches no AuthorizedPrincipalsFile by design.
func TestWithLegacyPassesThroughPrincipalsWithNoLegacyName(t *testing.T) {
	got := WithLegacy([]string{User("alice")})
	if len(got) != 1 || got[0] != User("alice") {
		t.Fatalf("WithLegacy(user) = %v, want exactly [%q]", got, User("alice"))
	}
}

// A set that already contains both spellings must not grow duplicates: sshd is
// tolerant of them, but the certificate is size-bounded and the audit record of
// which principals were issued should read as what was decided.
func TestWithLegacyDoesNotDuplicate(t *testing.T) {
	got := WithLegacy([]string{Global, LegacyGlobal})
	if len(got) != 2 {
		t.Fatalf("WithLegacy = %v, want 2 entries", got)
	}
}
