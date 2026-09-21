package hosttrust

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The strongest path gives up nothing, and every weaker one says what it gave up.
//
// The point of this package is that the difference between access paths was invisible.
// A posture that reported a weaker tier without naming the cost would reproduce the
// problem in a new place.
func TestEveryWeakerPathSaysWhatItGaveUp(t *testing.T) {
	if p := Assess("prov_cert", "ssh", "10.100.0.2"); p.Tier != TierBrokeredOverlay || len(p.GivesUp) != 0 {
		t.Errorf("the strongest path is not clean: %+v", p)
	}
	for _, tc := range []struct {
		name                         string
		auth, proto, overlay         string
		wantTier                     Tier
		wantPerSession, wantConfined bool
	}{
		{"direct, certificate", "prov_cert", "ssh", "", TierBrokeredDirect, true, false},
		{"overlay, vaulted", "vault_password", "ssh", "10.100.0.2", TierVaultedOverlay, false, true},
		{"direct, vaulted", "vault_ssh_key", "ssh", "", TierVaultedDirect, false, false},
		{"windows desktop", "prov_cert", "rdp", "10.100.0.2", TierVaultedOverlay, false, true},
	} {
		p := Assess(tc.auth, tc.proto, tc.overlay)
		if p.Tier != tc.wantTier {
			t.Errorf("%s: tier %q, want %q", tc.name, p.Tier, tc.wantTier)
		}
		if p.PerSessionCredential != tc.wantPerSession || p.ConfinedToOverlay != tc.wantConfined {
			t.Errorf("%s: perSession=%v confined=%v, want %v/%v", tc.name,
				p.PerSessionCredential, p.ConfinedToOverlay, tc.wantPerSession, tc.wantConfined)
		}
		if len(p.GivesUp) == 0 {
			t.Errorf("%s: a weaker path reported nothing given up, which is the invisibility "+
				"this package exists to remove", tc.name)
		}
	}
}

// A Windows host is vaulted whatever its auth_method column says.
//
// There is no SSH certificate for a Windows desktop session: RDP authenticates with
// the vaulted credential and WinRM with NTLM. A host row can still carry
// auth_method="prov_cert" (it is the column default), so trusting that column alone
// would report Windows hosts as brokered — the strongest tier — when they are not.
func TestAWindowsHostIsNeverReportedAsBrokered(t *testing.T) {
	p := Assess("prov_cert", "rdp", "10.100.0.2")
	if p.PerSessionCredential || p.RevocableByCertificate {
		t.Error("an RDP host was reported as authenticating with a per-session certificate " +
			"because its auth_method column said so; there is no SSH certificate for a " +
			"Windows desktop session")
	}
	if !strings.Contains(strings.Join(p.GivesUp, " "), "guacd") {
		t.Error("the recording difference for desktop sessions is not stated")
	}
}

// Ordering has to mean something, or a policy floor built on it would be arbitrary.
func TestTierOrderingIsMeaningful(t *testing.T) {
	if !AtLeast(TierBrokeredOverlay, TierVaultedDirect) {
		t.Error("the strongest tier does not satisfy the weakest floor")
	}
	if AtLeast(TierVaultedDirect, TierBrokeredOverlay) {
		t.Error("the weakest tier satisfies the strongest floor")
	}
	if len(All()) != 4 {
		t.Errorf("All() lists %d tiers", len(All()))
	}
}

// A new access path must not be able to appear without being classified.
//
// This is the failure a documentation-only matrix has: somebody adds an auth method,
// the store accepts it, and the matrix silently describes a world with one fewer path
// in it than the product has. The store's own switch is the list of truth, so this
// reads it rather than keeping a second copy.
func TestEveryAuthMethodTheStoreAcceptsIsClassified(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "store", "hosts.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := funcBody(string(src), "func (in HostInput) authMethod() string")
	if body == "" {
		t.Fatal("HostInput.authMethod not found — this test no longer guards what it claims")
	}
	found := regexp.MustCompile(`"([a-z_]+)"`).FindAllStringSubmatch(body, -1)
	if len(found) == 0 {
		t.Fatal("no auth methods parsed out of the store")
	}
	for _, m := range found {
		method := m[1]
		p := Assess(method, "ssh", "10.100.0.2")
		// Every known method must land on a tier this package names, with a credential
		// kind it can describe. An unrecognised method falling through to the vaulted
		// branch would be wrong in the safe direction, but silently.
		if p.Credential != "ephemeral-certificate" && p.Credential != "standing-vaulted" {
			t.Errorf("auth method %q is not classified by this package", method)
		}
		if method != "prov_cert" && p.PerSessionCredential {
			t.Errorf("auth method %q was treated as certificate-based", method)
		}
		if method == "prov_cert" && !p.PerSessionCredential {
			t.Errorf("the certificate method was not treated as certificate-based")
		}
	}
	// And the set is the one this package was written against: a NEW method appearing
	// here should make somebody read the matrix, not slip through as "vaulted".
	var names []string
	for _, m := range found {
		names = append(names, m[1])
	}
	got := strings.Join(names, ",")
	const known = "vault_password,vault_ssh_key,prov_cert"
	if got != known {
		t.Errorf("the store now accepts a different set of auth methods:\n  got  %s\n  want %s\n"+
			"Classify the new one in hosttrust and add it to the matrix in "+
			"docs/security-guide.md before changing this test.", got, known)
	}
}

func funcBody(src, sig string) string {
	i := strings.Index(src, sig)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		return rest
	}
	return rest[:end]
}
