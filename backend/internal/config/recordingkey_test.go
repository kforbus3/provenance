package config

import (
	"strings"
	"testing"
)

// Session recordings were written in plaintext unless somebody opted in to encryption.
//
// A terminal recording is not metadata. It holds what the operator typed and what came
// back: pasted passwords, tokens, database rows, key material — and the files are
// created 0640. Anyone who can read that directory gets the contents of every
// privileged session, which is a larger prize than the credentials this product exists
// to keep out of their hands.
//
// Every other secret in this config already fails closed outside development. This one
// did not, so the safe posture depended on an operator knowing to set a variable whose
// absence produced no error, no warning, and files that look identical until opened.
func TestProductionRefusesToRecordInPlaintext(t *testing.T) {
	c := &Config{Environment: "production"}
	fillProductionSecrets(c)
	c.RecordingEncryptionKey = nil
	c.RecordingAllowPlaintext = false

	err := c.validate()
	if err == nil {
		t.Fatal("production started with no recording key and no explicit opt-out, so every " +
			"privileged session would be recorded unencrypted with nothing said about it")
	}
	if !strings.Contains(err.Error(), "PROV_RECORDING_KEY") {
		t.Errorf("the error does not name the setting to fix: %v", err)
	}
	if !strings.Contains(err.Error(), "PROV_RECORDING_ALLOW_PLAINTEXT") {
		t.Errorf("the error does not offer the deliberate escape hatch, so a deployment that "+
			"genuinely cannot encrypt has nowhere to go but downgrade: %v", err)
	}
}

// A key satisfies it.
func TestAKeyIsEnough(t *testing.T) {
	c := &Config{Environment: "production"}
	fillProductionSecrets(c)
	c.RecordingEncryptionKey = []byte(strings.Repeat("k", 32))
	if err := c.validate(); err != nil {
		t.Errorf("a configured recording key was rejected: %v", err)
	}
}

// And so does saying so explicitly — that is the point of the escape hatch.
func TestPlaintextIsAllowedWhenSaidOutLoud(t *testing.T) {
	c := &Config{Environment: "production"}
	fillProductionSecrets(c)
	c.RecordingEncryptionKey = nil
	c.RecordingAllowPlaintext = true
	if err := c.validate(); err != nil {
		t.Errorf("an explicit plaintext opt-in was still refused: %v", err)
	}
}

// Development is unaffected: the local test fabric has no secrets by design.
func TestDevelopmentIsUnaffected(t *testing.T) {
	c := &Config{Environment: "development"}
	c.DatabaseURL = "postgres://prov:prov@localhost:5432/prov?sslmode=disable"
	c.PublicURL = "https://prov.example.com"
	if err := c.validate(); err != nil {
		t.Errorf("development now requires a recording key: %v", err)
	}
}

// fillProductionSecrets satisfies every OTHER production requirement, so these tests
// fail on the recording key alone rather than on whichever check happens to run first.
func fillProductionSecrets(c *Config) {
	// Everything validate() insists on, so these tests turn on the recording key
	// alone rather than on whichever unrelated check runs first.
	c.DatabaseURL = "postgres://prov:prov@localhost:5432/prov?sslmode=disable"
	c.PublicURL = "https://prov.example.com"
	c.CookieSecure = true
	c.JWTSecret = []byte(strings.Repeat("j", 32))
	c.CSRFSecret = []byte(strings.Repeat("c", 16))
	c.CAKeyPassphrase = []byte(strings.Repeat("p", 16))
	c.AuditHMACKey = []byte(strings.Repeat("a", 32))
	c.AnsibleRunnerToken = strings.Repeat("r", 16)
	c.RecordingEncryptionKey = []byte(strings.Repeat("k", 32))
}
