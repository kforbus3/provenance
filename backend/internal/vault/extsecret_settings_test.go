package vault

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/secretbox"
)

var testPass = []byte("test-passphrase-for-sealing-secrets")

// The screen never receives a credential. It is told only whether one is set, so it
// can show "configured" without being able to leak it — and so a blank field on save
// unambiguously means "leave it alone" rather than "clear it".
func TestRedactedNeverCarriesACredential(t *testing.T) {
	tok, _ := secretbox.Seal(testPass, []byte("hvs.super-secret-token"))
	sk, _ := secretbox.Seal(testPass, []byte("aws-secret-key"))
	c := extSecretConfig{
		VaultAddr: "https://bao.internal:8200", VaultTokenEnc: tok,
		AWSRegion: "eu-west-2", AWSAccessKey: "AKIAEXAMPLE", AWSSecretKeyEnc: sk,
	}
	b, err := json.Marshal(c.redacted())
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, leak := range []string{"hvs.super-secret-token", "aws-secret-key", tok, sk} {
		if strings.Contains(body, leak) {
			t.Errorf("redacted output contains %q:\n%s", leak, body)
		}
	}
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out["vaultTokenSet"] != true || out["awsSecretKeySet"] != true {
		t.Errorf("redacted output does not report which credentials are set: %v", out)
	}
	if out["vaultAddr"] != "https://bao.internal:8200" {
		t.Errorf("the address is not secret and should be shown: %v", out["vaultAddr"])
	}
	// An access key id is an identifier, not a secret; the secret key is the secret.
	if out["awsAccessKey"] != "AKIAEXAMPLE" {
		t.Errorf("access key id should be shown: %v", out["awsAccessKey"])
	}
}

// Nothing set reports nothing set, rather than claiming a credential exists.
func TestRedactedReportsUnsetCredentials(t *testing.T) {
	var out map[string]any
	b, _ := json.Marshal(extSecretConfig{}.redacted())
	_ = json.Unmarshal(b, &out)
	for _, k := range []string{"vaultTokenSet", "awsSecretKeySet", "awsSessionSet"} {
		if out[k] != false {
			t.Errorf("%s = %v, want false", k, out[k])
		}
	}
}

// Sealed credentials come back out for use.
func TestStoredCredentialsUnsealForUse(t *testing.T) {
	tok, _ := secretbox.Seal(testPass, []byte("hvs.token"))
	c := extSecretConfig{VaultAddr: " https://bao:8200 ", VaultTokenEnc: tok, VaultSkipVerify: true}
	got := c.toExtSecret(testPass)
	if got.VaultToken != "hvs.token" {
		t.Errorf("token = %q, want it unsealed", got.VaultToken)
	}
	if got.VaultAddr != "https://bao:8200" {
		t.Errorf("address = %q, want it trimmed", got.VaultAddr)
	}
	if !got.VaultTLSSkipVerify {
		t.Error("skip-verify was lost")
	}
}

// A credential that cannot be unsealed — a rotated CA passphrase, a corrupt row —
// must resolve to EMPTY, not to garbage. Empty merges as "not set" and falls back to
// the environment, which is a connection the operator can reason about; a partial or
// wrong value would authenticate as somebody else, or fail in a way that looks like
// the manager being down.
func TestAnUnsealableCredentialResolvesToEmpty(t *testing.T) {
	c := extSecretConfig{VaultAddr: "https://bao:8200", VaultTokenEnc: "not-valid-ciphertext"}
	if got := c.toExtSecret(testPass).VaultToken; got != "" {
		t.Errorf("token = %q, want empty when it cannot be unsealed", got)
	}
	// Sealed under a different passphrase: same requirement.
	other, _ := secretbox.Seal([]byte("a-completely-different-passphrase"), []byte("hvs.token"))
	c2 := extSecretConfig{VaultTokenEnc: other}
	if got := c2.toExtSecret(testPass).VaultToken; got != "" {
		t.Errorf("token = %q, want empty when sealed under another key", got)
	}
}

// The persisted row must never contain plaintext. The write-only fields exist so the
// browser can SEND a credential; they must not survive into storage.
func TestThePersistedRowHoldsNoPlaintext(t *testing.T) {
	enc, _ := secretbox.Seal(testPass, []byte("hvs.token"))
	// What extSecretPut stores: plaintext cleared, ciphertext kept.
	stored := extSecretConfig{VaultAddr: "https://bao:8200", VaultTokenEnc: enc}
	b, _ := json.Marshal(stored)
	if strings.Contains(string(b), "hvs.token") {
		t.Fatalf("plaintext survived into the stored row: %s", b)
	}
	if !strings.Contains(string(b), "vaultTokenEnc") {
		t.Errorf("sealed token missing from the stored row: %s", b)
	}
}
