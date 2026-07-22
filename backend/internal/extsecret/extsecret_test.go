package extsecret

import "testing"

func TestSplitRef(t *testing.T) {
	cases := []struct{ in, path, field string }{
		{"secret/db/prod#password", "secret/db/prod", "password"},
		{"secret/db/prod", "secret/db/prod", ""},
		{"kv/app#api_key", "kv/app", "api_key"},
	}
	for _, c := range cases {
		p, f := splitRef(c.in)
		if p != c.path || f != c.field {
			t.Errorf("splitRef(%q) = (%q,%q), want (%q,%q)", c.in, p, f, c.path, c.field)
		}
	}
}

func TestSplitMountPath(t *testing.T) {
	m, p, err := splitMountPath("secret/db/prod")
	if err != nil || m != "secret" || p != "db/prod" {
		t.Errorf("splitMountPath = (%q,%q,%v)", m, p, err)
	}
	if _, _, err := splitMountPath("secret"); err == nil {
		t.Error("expected error for mount-only reference")
	}
	if _, _, err := splitMountPath("secret/"); err == nil {
		t.Error("expected error for trailing-slash reference")
	}
}

func TestSupportedAndConfigured(t *testing.T) {
	if !Supported(ProviderVaultKV) {
		t.Error("vault-kv should be supported")
	}
	if Supported("nope") {
		t.Error("unknown provider should not be supported")
	}
	if (Config{}).Configured() {
		t.Error("empty config should not be Configured")
	}
	if !(Config{VaultAddr: "https://vault:8200"}).Configured() {
		t.Error("config with addr should be Configured")
	}
}

func TestNewUnknownProvider(t *testing.T) {
	if _, err := New("aws-secrets", Config{VaultAddr: "x"}); err == nil {
		t.Error("expected error for unknown provider")
	}
}
