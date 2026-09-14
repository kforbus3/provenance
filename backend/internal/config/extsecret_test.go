package config

import (
	"testing"

	"github.com/kforbus3/provenance/backend/internal/extsecret"
)

// The environment is the baseline and saved settings layer over it FIELD BY FIELD.
// Whole-object replacement would mean an operator who fills in only the address in
// the UI has thereby unset the token their .env supplies — repointing where every
// secret is read from, without saying so.
func TestSavedSettingsLayerOverTheEnvironmentPerField(t *testing.T) {
	env := extsecret.Config{
		VaultAddr:  "https://vault.from-env:8200",
		VaultToken: "env-token",
		AWSRegion:  "us-east-1",
	}
	over := extsecret.Config{VaultAddr: "https://bao.from-ui:8200"}

	got := MergeExtSecret(env, over)
	if got.VaultAddr != "https://bao.from-ui:8200" {
		t.Errorf("address = %q, want the saved one to win", got.VaultAddr)
	}
	if got.VaultToken != "env-token" {
		t.Errorf("token = %q, want the environment's to survive a partial save", got.VaultToken)
	}
	if got.AWSRegion != "us-east-1" {
		t.Errorf("region = %q, want untouched fields preserved", got.AWSRegion)
	}
}

// A deployment that predates the settings screen has no saved row at all. The zero
// value must merge as "nothing configured here", never as "the operator cleared it" —
// otherwise upgrading silently disables every external-backed credential.
func TestAnEmptySavedConfigChangesNothing(t *testing.T) {
	env := extsecret.Config{
		VaultAddr: "https://vault.internal:8200", VaultToken: "t",
		VaultCACertFile: "/etc/ssl/ca.pem",
		AWSRegion:       "eu-west-2", AWSAccessKey: "AKIA", AWSSecretKey: "s", AWSEndpoint: "https://localstack",
	}
	if got := MergeExtSecret(env, extsecret.Config{}); got != env {
		t.Fatalf("an empty saved config changed the resolved connection:\n got %+v\nwant %+v", got, env)
	}
}

// Whitespace is not a value. Treating it as one points the deployment at an empty
// address and reports it unreachable rather than unconfigured.
func TestWhitespaceIsNotAValue(t *testing.T) {
	env := extsecret.Config{VaultAddr: "https://vault.internal:8200", VaultToken: "t"}
	got := MergeExtSecret(env, extsecret.Config{VaultAddr: "   ", VaultToken: "\t"})
	if got.VaultAddr != env.VaultAddr || got.VaultToken != env.VaultToken {
		t.Errorf("whitespace overrode real values: %+v", got)
	}
}

// TLSSkipVerify is a bool, so "false" is indistinguishable from "not set". Silently
// turning OFF a verification bypass the environment asked for would change how the
// connection is authenticated with nobody saying so; turning it ON stays explicit
// from either side.
func TestSkipVerifyIsNeverSilentlyTurnedOff(t *testing.T) {
	on := extsecret.Config{VaultTLSSkipVerify: true}
	if !MergeExtSecret(on, extsecret.Config{}).VaultTLSSkipVerify {
		t.Error("an unset saved value turned the environment's skip-verify off")
	}
	if !MergeExtSecret(extsecret.Config{}, on).VaultTLSSkipVerify {
		t.Error("a saved skip-verify did not take effect")
	}
	if MergeExtSecret(extsecret.Config{}, extsecret.Config{}).VaultTLSSkipVerify {
		t.Error("skip-verify defaulted to on")
	}
}

// With no overlay installed — the state before the store exists, and in every unit
// test — ExtSecret() must still return exactly what the environment says.
func TestWithNoOverlayTheEnvironmentIsUsedUnchanged(t *testing.T) {
	SetExtSecretOverlay(nil)
	c := &Config{ExtSecretVaultAddr: "https://vault.internal:8200", ExtSecretVaultToken: "t"}
	got := c.ExtSecret()
	if got.VaultAddr != "https://vault.internal:8200" || got.VaultToken != "t" {
		t.Fatalf("ExtSecret() = %+v, want the environment values", got)
	}
}

// And with one installed, every existing caller of ExtSecret() picks the saved
// connection up without knowing settings exist.
func TestAnInstalledOverlayReachesExistingCallers(t *testing.T) {
	t.Cleanup(func() { SetExtSecretOverlay(nil) })
	SetExtSecretOverlay(func() extsecret.Config {
		return extsecret.Config{VaultAddr: "https://bao.from-ui:8200"}
	})
	c := &Config{ExtSecretVaultAddr: "https://vault.from-env:8200", ExtSecretVaultToken: "env-token"}
	got := c.ExtSecret()
	if got.VaultAddr != "https://bao.from-ui:8200" {
		t.Errorf("address = %q, want the saved one", got.VaultAddr)
	}
	if got.VaultToken != "env-token" {
		t.Errorf("token = %q, want the environment's preserved", got.VaultToken)
	}
}
