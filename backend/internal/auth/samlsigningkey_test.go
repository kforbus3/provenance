package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"strings"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

// With a signing key configured -- installed with SetSPSigningKeyStore, the only way
// this SP installs one -- the metadata must publish that key. It did not: the check
// asked GetSigningKey, which cannot see a key set that way, so metadata said
// AuthnRequestsSigned=true and carried no certificate to verify them with.
func TestMetadataPublishesAKeyInstalledWithSetSPSigningKeyStore(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "prov-sp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      "http://idp.test/sso",
		IdentityProviderIssuer:      "http://idp.test",
		ServiceProviderIssuer:       "http://prov.test/api/v1/auth/saml/metadata",
		AssertionConsumerServiceURL: "http://prov.test/api/v1/auth/saml/acs",
		AudienceURI:                 "http://prov.test/api/v1/auth/saml/metadata",
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{}},
	}
	// Exactly as buildSP installs it.
	if err := sp.SetSPSigningKeyStore(&saml2.KeyStore{Signer: key, Cert: der}); err != nil {
		t.Fatal(err)
	}
	sp.SignAuthnRequests = true

	md, err := spMetadata(sp)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	out, err := xml.Marshal(md)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(out)
	if !strings.Contains(doc, `AuthnRequestsSigned="true"`) {
		t.Fatalf("expected signed requests to be declared:\n%s", doc)
	}
	if !strings.Contains(doc, "KeyDescriptor") || !strings.Contains(doc, base64.StdEncoding.EncodeToString(der)) {
		t.Fatalf("signed requests are declared but the signing certificate is not published:\n%s", doc)
	}
}
