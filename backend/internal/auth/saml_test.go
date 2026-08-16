package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/kforbus3/Moorgate/backend/internal/config"
	"github.com/kforbus3/Moorgate/backend/internal/secretbox"
)

// selfSignedRSA returns a PEM RSA private key (PKCS#8) and a matching self-signed
// certificate PEM, suitable as an SP signing key pair.
func selfSignedRSA(t *testing.T) (keyPEM, certPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-sp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return keyPEM, certPEM
}

// samlTestHandler builds a Handler with no store (SP construction never touches it)
// and a config whose passphrase can unseal a sealed SP key.
func samlTestHandler(pass []byte) *Handler {
	return &Handler{svc: NewService(nil, &config.Config{
		PublicURL:       "https://fleet.example",
		CAKeyPassphrase: pass,
	}, nil)}
}

func TestParseSPKeyPair(t *testing.T) {
	keyPEM, certPEM := selfSignedRSA(t)

	if _, err := parseSPKeyPair(keyPEM, certPEM); err != nil {
		t.Errorf("valid PKCS#8 RSA key + cert should parse: %v", err)
	}
	// PKCS#1 ("RSA PRIVATE KEY") form must also parse.
	block, _ := pem.Decode([]byte(keyPEM))
	pk, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk.(*rsa.PrivateKey)),
	}))
	if _, err := parseSPKeyPair(pkcs1, certPEM); err != nil {
		t.Errorf("PKCS#1 RSA key should parse: %v", err)
	}
	if _, err := parseSPKeyPair("", certPEM); err == nil {
		t.Error("missing key must error")
	}
	if _, err := parseSPKeyPair(keyPEM, ""); err == nil {
		t.Error("missing cert must error")
	}
	if _, err := parseSPKeyPair("not a key", certPEM); err == nil {
		t.Error("garbage key must error")
	}
}

// TestSPSigningKeyStoreAndSPKey covers the sealed-key round trip and that samlSP
// loads the key (enabling request/logout signing) only when one is configured.
func TestSPSigningKeyStoreAndSPKey(t *testing.T) {
	pass := []byte("unit-test-passphrase")
	h := samlTestHandler(pass)
	keyPEM, certPEM := selfSignedRSA(t)
	enc, err := secretbox.Seal(pass, []byte(keyPEM))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// No SP key configured → no key store, no signing.
	bare := samlConfig{SPCertificate: certPEM}
	if ks, err := h.spSigningKeyStore(bare); err != nil || ks != nil {
		t.Errorf("no key configured: want (nil,nil), got (%v,%v)", ks, err)
	}
	sp, err := h.samlSP(bare)
	if err != nil {
		t.Fatalf("samlSP bare: %v", err)
	}
	if samlSPCanSign(sp) {
		t.Error("SP with no key must not sign")
	}

	// Configured SP key → key store present and signing enabled.
	withKey := samlConfig{SPCertificate: certPEM, SPPrivateKeyEnc: enc}
	ks, err := h.spSigningKeyStore(withKey)
	if err != nil || ks == nil {
		t.Fatalf("configured key: want key store, got (%v,%v)", ks, err)
	}
	sp, err = h.samlSP(withKey)
	if err != nil {
		t.Fatalf("samlSP withKey: %v", err)
	}
	if !samlSPCanSign(sp) {
		t.Error("SP with a key must sign")
	}
	if h.spPrivateKey(withKey) != keyPEM {
		t.Error("sealed SP key did not round-trip")
	}
}

// TestSAMLLogoutRequestConstruction verifies that, once an SP key is configured, a
// signed LogoutRequest destined for the IdP SLO endpoint can be built.
func TestSAMLLogoutRequestConstruction(t *testing.T) {
	pass := []byte("unit-test-passphrase")
	h := samlTestHandler(pass)
	keyPEM, certPEM := selfSignedRSA(t)
	enc, _ := secretbox.Seal(pass, []byte(keyPEM))

	c := samlConfig{
		Enabled: true, IdPSSOURL: "https://idp.example/sso", IdPEntityID: "urn:idp",
		IdPCertificate: certPEM, IdPSLOURL: "https://idp.example/slo",
		SPCertificate: certPEM, SPPrivateKeyEnc: enc,
	}
	sp, err := h.samlSP(c)
	if err != nil {
		t.Fatalf("samlSP: %v", err)
	}
	if sp.IdentityProviderSLOURL != "https://idp.example/slo" {
		t.Errorf("IdP SLO URL = %q", sp.IdentityProviderSLOURL)
	}
	if sp.ServiceProviderSLOURL != "https://fleet.example/api/v1/auth/saml/slo" {
		t.Errorf("SP SLO URL = %q", sp.ServiceProviderSLOURL)
	}
	doc, err := sp.BuildLogoutRequestDocument("user@example.com", "session-index-1")
	if err != nil {
		t.Fatalf("BuildLogoutRequestDocument: %v", err)
	}
	xmlStr, err := doc.WriteToString()
	if err != nil {
		t.Fatalf("WriteToString: %v", err)
	}
	if !strings.Contains(xmlStr, "LogoutRequest") {
		t.Error("document is not a LogoutRequest")
	}
	if !strings.Contains(xmlStr, "Signature") {
		t.Error("LogoutRequest must be signed when an SP key is configured")
	}
	// A redirect-binding logout URL should target the IdP SLO endpoint.
	u, err := sp.BuildLogoutURLRedirect("/login", doc)
	if err != nil {
		t.Fatalf("BuildLogoutURLRedirect: %v", err)
	}
	if !strings.HasPrefix(u, "https://idp.example/slo?") {
		t.Errorf("logout redirect URL = %q", u)
	}
}

// TestSAMLLogoutGracefulFallback confirms an SP without a key still builds a
// working (unsigned) SP and cannot sign, so the logout handler falls back to
// local-only logout rather than attempting SLO.
func TestSAMLLogoutGracefulFallback(t *testing.T) {
	h := samlTestHandler([]byte("unit-test-passphrase"))
	_, certPEM := selfSignedRSA(t)
	c := samlConfig{
		Enabled: true, IdPSSOURL: "https://idp.example/sso", IdPEntityID: "urn:idp",
		IdPCertificate: certPEM, IdPSLOURL: "https://idp.example/slo",
		// No SPCertificate / SPPrivateKeyEnc.
	}
	sp, err := h.samlSP(c)
	if err != nil {
		t.Fatalf("samlSP: %v", err)
	}
	if samlSPCanSign(sp) {
		t.Fatal("SP without a key must not sign (would send an unsigned LogoutRequest)")
	}
	// Unsigned AuthnRequest generation still works (login is unaffected).
	if _, err := sp.BuildAuthURL("/"); err != nil {
		t.Errorf("unsigned AuthnRequest should still build: %v", err)
	}
}

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
