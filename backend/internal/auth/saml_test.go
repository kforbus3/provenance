package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func selfSignedCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	return der
}

func TestParseIDPCert(t *testing.T) {
	der := selfSignedCertDER(t)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	b64 := base64.StdEncoding.EncodeToString(der)

	if _, err := parseIDPCert(pemStr); err != nil {
		t.Errorf("PEM cert should parse: %v", err)
	}
	if _, err := parseIDPCert(b64); err != nil {
		t.Errorf("base64 DER cert should parse: %v", err)
	}
	// Whitespace-wrapped base64 (as pasted from an IdP metadata blob).
	wrapped := b64[:20] + "\n" + b64[20:]
	if _, err := parseIDPCert(wrapped); err != nil {
		t.Errorf("whitespace-wrapped base64 should parse: %v", err)
	}
	if _, err := parseIDPCert("not a certificate"); err == nil {
		t.Error("garbage should not parse")
	}
	if _, err := parseIDPCert(""); err == nil {
		t.Error("empty should error")
	}
}

func TestSAMLRelayGuardsOpenRedirect(t *testing.T) {
	cases := map[string]string{
		"":                    "/",
		"/":                   "/",
		"/hosts":              "/hosts",
		"/hosts?tab=1":        "/hosts?tab=1",
		"//evil.com":          "/", // protocol-relative → rejected
		"https://evil.com":    "/",
		"http://evil.com":     "/",
		"javascript:alert(1)": "/",
		"  /spaced  ":         "/spaced",
	}
	for in, want := range cases {
		if got := samlRelay(in); got != want {
			t.Errorf("samlRelay(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSAMLConfigEnabled(t *testing.T) {
	full := samlConfig{Enabled: true, IdPSSOURL: "https://idp/sso", IdPEntityID: "urn:idp", IdPCertificate: "x"}
	if !full.enabled() {
		t.Error("fully configured + enabled should be enabled")
	}
	if (samlConfig{Enabled: false, IdPSSOURL: "x", IdPEntityID: "x", IdPCertificate: "x"}).enabled() {
		t.Error("Enabled=false must be disabled")
	}
	if (samlConfig{Enabled: true, IdPSSOURL: "x", IdPEntityID: "x"}).enabled() {
		t.Error("missing certificate must be disabled")
	}
	if strings.TrimSpace("") != "" {
		t.Fatal("sanity")
	}
}
