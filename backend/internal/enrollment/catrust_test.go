package enrollment

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/config"
	princ "github.com/kforbus3/provenance/backend/internal/principals"
)

// caTrustScript must write the host-scoped principal into each account's
// AuthorizedPrincipalsFile so that only this host's certificates are accepted.
func TestCATrustScriptWritesHostScopedPrincipals(t *testing.T) {
	id := uuid.MustParse("abcdef01-2345-6789-abcd-ef0123456789")

	// Additive (default): the host trusts BOTH the fleet-wide and the host-scoped
	// principal, so certs for not-yet-migrated hosts keep working.
	//
	// Each is listed in both spellings. Certificates carry both
	// (principals.WithLegacy), so the current names alone would serve a rolling
	// upgrade — but sshd reads this file, and a backend rolled BACK to the previous
	// release issues only the old names. Dropping them here locks that backend out
	// of every host re-enrolled in between.
	add := (&Service{cfg: &config.Config{HostScopedOnly: false}}).caTrustScript("prov", "ca-key", id)
	for _, want := range []string{
		"printf '" + princ.Global + `\n` + princ.LegacyGlobal + `\n` + princ.Host(id) + `\n` + princ.LegacyHost(id) + `\n'`,
		"printf '" + princ.GlobalLogin + `\n` + princ.LegacyGlobalLogin + `\n` + princ.HostLogin(id) + `\n` + princ.LegacyHostLogin(id) + `\n'`,
	} {
		if !strings.Contains(add, want) {
			t.Errorf("additive script missing %q\n---\n%s", want, add)
		}
	}

	// Lockdown: the host trusts ONLY its host-scoped principals. Neither spelling
	// of the fleet-wide principal may survive — trusting "fleet" is exactly as
	// fleet-wide as trusting "prov", so a rename that left the old one behind would
	// silently undo lockdown on every host enrolled before it.
	lock := (&Service{cfg: &config.Config{HostScopedOnly: true}}).caTrustScript("prov", "ca-key", id)
	for _, want := range []string{princ.Host(id), princ.LegacyHost(id)} {
		if !strings.Contains(lock, want) {
			t.Errorf("lockdown script missing host-scoped sudo principal %q\n%s", want, lock)
		}
	}
	for _, banned := range []string{
		"printf '" + princ.Global + `\n`,
		"printf '" + princ.LegacyGlobal + `\n`,
		"printf '" + princ.GlobalLogin + `\n`,
		"printf '" + princ.LegacyGlobalLogin + `\n`,
	} {
		if strings.Contains(lock, banned) {
			t.Errorf("lockdown script must not trust the fleet-wide principal %q\n%s", banned, lock)
		}
	}
}
