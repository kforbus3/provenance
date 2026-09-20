package auth

import (
	"crypto/x509"
	"encoding/xml"
	"strings"
	"testing"

	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

// An SP with no signing key must still publish metadata.
//
// The library cannot: gosaml2's Metadata() asks for the encryption certificate
// unconditionally and returns "empty SP encryption certificate". An SP signing key
// is optional here -- samlSP documents that and sets SignAuthnRequests only when
// one is present -- so /api/v1/auth/saml/metadata answered
//
//	500 {"error":"could not build metadata"}
//
// for a configuration that is supported and otherwise works. Every IdP's setup
// instructions begin by importing SP metadata, so the first step of configuring
// SAML failed with a message naming nothing. Found against a live Keycloak realm.
func TestMetadataIsPublishedWithoutAnSPSigningKey(t *testing.T) {
	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      "http://idp.test/sso",
		IdentityProviderIssuer:      "http://idp.test",
		ServiceProviderIssuer:       "http://prov.test/api/v1/auth/saml/metadata",
		AssertionConsumerServiceURL: "http://prov.test/api/v1/auth/saml/acs",
		ServiceProviderSLOURL:       "http://prov.test/api/v1/auth/saml/slo",
		AudienceURI:                 "http://prov.test/api/v1/auth/saml/metadata",
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{}},
	}
	md, err := spMetadata(sp)
	if err != nil {
		t.Fatalf("no metadata for an SP without a signing key: %v", err)
	}
	out, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	doc := string(out)

	// The three things an IdP actually needs.
	for _, want := range []string{
		"http://prov.test/api/v1/auth/saml/metadata", // entity ID
		"http://prov.test/api/v1/auth/saml/acs",      // where assertions go
		"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("metadata does not carry %q:\n%s", want, doc)
		}
	}
	// No key to describe, so no KeyDescriptor -- rather than an empty one, which
	// some IdPs reject outright.
	if strings.Contains(doc, "KeyDescriptor") {
		t.Errorf("an SP with no key published a KeyDescriptor:\n%s", doc)
	}
	// Assertions must still be required: this is the security-critical direction
	// and it does not depend on the SP holding a key.
	if !strings.Contains(doc, `WantAssertionsSigned="true"`) {
		t.Errorf("metadata does not require signed assertions:\n%s", doc)
	}
	if !strings.Contains(doc, `AuthnRequestsSigned="false"`) {
		t.Errorf("an SP that cannot sign claims it signs requests:\n%s", doc)
	}
	// The SLO endpoint is advertised when there is one.
	if !strings.Contains(doc, "http://prov.test/api/v1/auth/saml/slo") {
		t.Errorf("metadata omits the SLO endpoint:\n%s", doc)
	}
}

// And an SP with no SLO endpoint must not advertise one: an IdP told about an
// endpoint will use it, and naming one this deployment does not serve turns logout
// into an error the user sees.
func TestMetadataOmitsAnSLOEndpointThatDoesNotExist(t *testing.T) {
	sp := &saml2.SAMLServiceProvider{
		ServiceProviderIssuer:       "http://prov.test/meta",
		AssertionConsumerServiceURL: "http://prov.test/acs",
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{}},
	}
	md, err := spMetadata(sp)
	if err != nil {
		t.Fatal(err)
	}
	if len(md.SPSSODescriptor.SingleLogoutServices) != 0 {
		t.Error("an SLO endpoint was advertised for an SP that has none")
	}
}
