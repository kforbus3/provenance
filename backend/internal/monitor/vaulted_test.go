package monitor

import (
	"testing"

	"github.com/google/uuid"

	"github.com/kforbus3/Moorgate/backend/internal/models"
)

func TestHasVaultedCredential(t *testing.T) {
	cid := uuid.New()
	cases := []struct {
		name string
		host models.Host
		want bool
	}{
		{"vault password with credential", models.Host{AuthMethod: "vault_password", CredentialID: &cid}, true},
		{"vault key with credential", models.Host{AuthMethod: "vault_ssh_key", CredentialID: &cid}, true},
		{"fleet cert", models.Host{AuthMethod: "fleet_cert", CredentialID: &cid}, false},
		{"default (empty) auth", models.Host{AuthMethod: "", CredentialID: &cid}, false},
		{"vaulted method but no credential attached", models.Host{AuthMethod: "vault_password"}, false},
	}
	for _, c := range cases {
		if got := hasVaultedCredential(&c.host); got != c.want {
			t.Errorf("%s: hasVaultedCredential = %v, want %v", c.name, got, c.want)
		}
	}
}
