package config

import "testing"

func TestVaultKey(t *testing.T) {
	// development: falls back to the CA passphrase so the local stack just works.
	dev := &Config{Environment: "development", CAKeyPassphrase: []byte("ca-dev-key")}
	if k, err := dev.VaultKey(); err != nil || string(k) != "ca-dev-key" {
		t.Fatalf("dev fallback = (%q, %v), want ca-dev-key", k, err)
	}

	// production without a vault passphrase: must fail closed.
	prod := &Config{Environment: "production", CAKeyPassphrase: []byte("cakey-cakey-cakey")}
	if _, err := prod.VaultKey(); err == nil {
		t.Error("production without FLEET_VAULT_PASSPHRASE should error")
	}

	// production with a vault passphrase equal to the CA passphrase: must fail.
	same := &Config{Environment: "production", CAKeyPassphrase: []byte("shared"), VaultPassphrase: "shared"}
	if _, err := same.VaultKey(); err == nil {
		t.Error("production with vault == CA passphrase should error")
	}

	// production with a distinct vault passphrase: allowed.
	ok := &Config{Environment: "production", CAKeyPassphrase: []byte("cakey"), VaultPassphrase: "distinct-vault-key"}
	if k, err := ok.VaultKey(); err != nil || string(k) != "distinct-vault-key" {
		t.Fatalf("prod distinct = (%q, %v), want distinct-vault-key", k, err)
	}
}
