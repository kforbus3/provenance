package enrollment

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/config"
	princ "github.com/fleet-terminal/backend/internal/principals"
)

// caTrustScript must write the host-scoped principal into each account's
// AuthorizedPrincipalsFile so that only this host's certificates are accepted.
func TestCATrustScriptWritesHostScopedPrincipals(t *testing.T) {
	id := uuid.MustParse("abcdef01-2345-6789-abcd-ef0123456789")

	// Additive (default): host trusts BOTH the fleet-wide and the host-scoped
	// principal, so certs for not-yet-migrated hosts keep working.
	add := (&Service{cfg: &config.Config{HostScopedOnly: false}}).caTrustScript("fleet", "ca-key", id)
	for _, want := range []string{
		"printf 'fleet\\n" + princ.Host(id) + `\n'`,
		"printf 'fleet-login\\n" + princ.HostLogin(id) + `\n'`,
	} {
		if !strings.Contains(add, want) {
			t.Errorf("additive script missing %q\n---\n%s", want, add)
		}
	}

	// Lockdown: host trusts ONLY its host-scoped principal — the fleet-wide
	// "fleet"/"fleet-login" lines must be gone.
	lock := (&Service{cfg: &config.Config{HostScopedOnly: true}}).caTrustScript("fleet", "ca-key", id)
	if !strings.Contains(lock, "printf '"+princ.Host(id)+`\n'`) {
		t.Errorf("lockdown script missing host-scoped sudo principal\n%s", lock)
	}
	if strings.Contains(lock, `printf 'fleet\n`) {
		t.Errorf("lockdown script must not trust the fleet-wide principal\n%s", lock)
	}
}
