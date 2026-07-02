package config

import "testing"

func TestValidateSecretsFailClosed(t *testing.T) {
	good := func() *Config {
		return &Config{
			Environment:     "production",
			DatabaseURL:     "postgres://x",
			JWTSecret:       []byte("0123456789012345678901234567890123"), // >=32
			CSRFSecret:      []byte("0123456789012345"),                   // >=16
			CAKeyPassphrase: []byte("0123456789012345"),                   // >=16
		}
	}

	// Development boots with no secrets (insecure fallbacks applied).
	dev := &Config{Environment: "development", DatabaseURL: "postgres://x"}
	if err := dev.validate(); err != nil {
		t.Fatalf("development should boot with fallbacks: %v", err)
	}
	if len(dev.CAKeyPassphrase) == 0 || len(dev.JWTSecret) == 0 {
		t.Fatal("development fallbacks not applied")
	}

	// Production with real secrets is fine.
	if err := good().validate(); err != nil {
		t.Fatalf("production with secrets should pass: %v", err)
	}

	// Production/staging with missing secrets must fail closed (no fallback).
	for _, envName := range []string{"production", "staging", "prod-eu"} {
		c := &Config{Environment: envName, DatabaseURL: "postgres://x"}
		if err := c.validate(); err == nil {
			t.Errorf("%s with empty secrets should fail closed", envName)
		}
		if len(c.CAKeyPassphrase) != 0 {
			t.Errorf("%s must not receive an insecure CA passphrase fallback", envName)
		}
	}

	// The accept-any host-key toggle is refused outside development.
	c := good()
	c.SSHInsecureHostKeys = true
	if err := c.validate(); err == nil {
		t.Error("SSHInsecureHostKeys must be refused in production")
	}
}
