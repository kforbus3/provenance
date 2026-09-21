package config

import "testing"

func TestValidateSecretsFailClosed(t *testing.T) {
	good := func() *Config {
		return &Config{
			Environment:            "production",
			DatabaseURL:            "postgres://x",
			JWTSecret:              []byte("0123456789012345678901234567890123"), // >=32
			CSRFSecret:             []byte("0123456789012345"),                   // >=16
			CAKeyPassphrase:        []byte("0123456789012345"),                   // >=16
			AuditHMACKey:           []byte("0123456789012345678901234567890123"), // >=32
			RecordingEncryptionKey: []byte("0123456789012345678901234567890123"), // >=32
			AnsibleRunnerToken:     "0123456789012345",                           // >=16
			// Load() always sets one; a hand-built Config must too, because
			// production now refuses to boot still pointing at localhost. That
			// check exists because the value silently drives CORS, the WebAuthn
			// relying party, the OIDC redirect, the SAML URLs and the WebSocket
			// origin -- so a wrong one boots cleanly and then breaks sign-on,
			// passkeys and terminals separately, none of them saying why.
			PublicURL:    "https://provenance.example.com",
			CookieSecure: true,
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

// The two settings that made a production deployment insecure or broken while
// booting perfectly cleanly.
func TestProductionRefusesMisleadingPublicURLAndInsecureCookies(t *testing.T) {
	base := func() *Config {
		return &Config{
			Environment:            "production",
			DatabaseURL:            "postgres://x",
			JWTSecret:              []byte("0123456789012345678901234567890123"),
			CSRFSecret:             []byte("0123456789012345"),
			CAKeyPassphrase:        []byte("0123456789012345"),
			AuditHMACKey:           []byte("0123456789012345678901234567890123"),
			RecordingEncryptionKey: []byte("0123456789012345678901234567890123"),
			AnsibleRunnerToken:     "0123456789012345",
			PublicURL:              "https://provenance.example.com",
			CookieSecure:           true,
		}
	}

	// Left at its default, this boots and then fails at sign-on, passkeys and
	// every terminal — separately, and none of them explaining why.
	for _, u := range []string{"https://localhost:8443", "http://127.0.0.1:8080", ""} {
		c := base()
		c.PublicURL = u
		if err := c.validate(); err == nil {
			t.Errorf("production accepted PROV_PUBLIC_URL=%q", u)
		}
	}

	// Serving https with cookies that are not marked Secure is not a trade-off
	// anyone makes deliberately. The compose file that `make up-single` uses
	// passes false by default, so this arrived by following the instructions.
	c := base()
	c.CookieSecure = false
	if err := c.validate(); err == nil {
		t.Error("production accepted https with PROV_COOKIE_SECURE=false")
	}

	// Plain http on a private network genuinely cannot set Secure — nobody
	// could log in. That is a warning, not a refusal.
	c = base()
	c.PublicURL, c.CookieSecure = "http://fleet.internal:8080", false
	if err := c.validate(); err != nil {
		t.Errorf("production over plain http should warn, not refuse: %v", err)
	}
}
