package kms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func verifyRS256(pub *rsa.PublicKey, signingInput string, sig []byte) error {
	h := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
}

// TestGCPSignJWT verifies the service-account assertion is a well-formed RS256 JWT
// that verifies against the SA public key — the piece that must be exactly right for
// the Google token exchange, checkable without a live GCP project.
func TestGCPSignJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	sa := gcpServiceAccount{ClientEmail: "svc@proj.iam.gserviceaccount.com", PrivateKey: pemStr, TokenURI: "https://oauth2.googleapis.com/token"}
	saJSON, _ := json.Marshal(sa)

	p, err := New(Config{Provider: "gcp-kms", KeyID: "projects/p/locations/l/keyRings/kr/cryptoKeys/k", GCPCredentialsJSON: string(saJSON)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	g := p.(*gcpKMS)

	when := time.Unix(1_700_000_000, 0)
	tok, err := g.signJWT(when)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}
	// Header + claims decode and carry the right fields.
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if !strings.Contains(string(hdr), "RS256") {
		t.Errorf("header missing RS256: %s", hdr)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("claims not JSON: %v", err)
	}
	if claims["iss"] != sa.ClientEmail {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["scope"] != "https://www.googleapis.com/auth/cloudkms" {
		t.Errorf("scope = %v", claims["scope"])
	}
	if claims["aud"] != sa.TokenURI {
		t.Errorf("aud = %v", claims["aud"])
	}
	// Signature verifies against the SA public key.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if err := verifyRS256(&key.PublicKey, parts[0]+"."+parts[1], sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

func TestGCPUnwrapRejectsForeignToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	saJSON, _ := json.Marshal(gcpServiceAccount{ClientEmail: "a@b.iam.gserviceaccount.com", PrivateKey: pemStr})
	p, err := New(Config{Provider: "gcp-kms", KeyID: "projects/p/locations/l/keyRings/kr/cryptoKeys/k", GCPCredentialsJSON: string(saJSON)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Unwrap(nil, "vault:v1:abc"); err == nil { //nolint:staticcheck // prefix check runs before ctx use
		t.Error("gcp-kms Unwrap should reject a non-GCP token")
	}
}

func TestAzureRequiresConfig(t *testing.T) {
	// Missing tenant/client should error at construction.
	if _, err := New(Config{Provider: "azure-keyvault", KeyID: "k", AzureVaultURL: "https://v.vault.azure.net"}); err == nil {
		t.Error("azure-keyvault should require tenant/client credentials")
	}
	// A fully-specified config constructs.
	if _, err := New(Config{
		Provider: "azure-keyvault", KeyID: "k", AzureVaultURL: "https://v.vault.azure.net",
		AzureTenantID: "t", AzureClientID: "c", AzureClientSecret: "s",
	}); err != nil {
		t.Errorf("valid azure-keyvault config should construct: %v", err)
	}
}
