package command

import (
	"testing"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// The bug this guards: "Run command" dialled with certificates only, so every
// host authenticating from the vault -- the switches, the router, the AP, none of
// which will ever trust our CA -- failed with "unable to authenticate, attempted
// methods [none publickey]". The classification below is what decides whether the
// credential is fetched at all, and the default for an unrecognised method has to
// be "fetch it": dialling with a certificate a host was never going to accept
// fails in a way that blames the host.
func TestWhichHostsNeedACredentialFromTheVault(t *testing.T) {
	for _, tc := range []struct {
		method string
		want   bool
		why    string
	}{
		{"", false, "empty means Provenance's own certificates, the default"},
		{"prov_cert", false, "certificates are issued per run; nothing to fetch"},
		{"vault_password", true, "the network gear: password held in the vault"},
		{"vault_ssh_key", true, "a key held in the vault, not one we issue"},
		{"something_new", true, "unknown method must not silently fall back to certs"},
	} {
		h := &models.Host{AuthMethod: tc.method}
		if got := needsInjection(h); got != tc.want {
			t.Errorf("auth_method %q: needsInjection = %v, want %v — %s", tc.method, got, tc.want, tc.why)
		}
	}
}
