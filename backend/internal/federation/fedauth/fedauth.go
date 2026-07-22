// Package fedauth is the instance-to-instance authentication layer for multi-site
// federation. It is entirely EdDSA (Ed25519) public-key based and deliberately
// SEPARATE from the per-instance HS256 user-session tokens: no symmetric secret is
// ever shared across instances. Each side holds only the other's public key.
//
// Three token types, all short-lived signed JWTs:
//   - link token:      signed by a SITE key, proves site identity when opening the
//     persistent control channel (verified by the hub).
//   - service token:   signed by the HUB key, authenticates the hub as a service
//     principal on each request (verified by the site).
//   - actor assertion: signed by the HUB key, carries the acting hub user's
//     identity + the permissions the hub authorized, bound to one
//     exact request via a digest + single-use nonce.
package fedauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	audLink      = "fleet-federation-link"
	audService   = "fleet-federation-service"
	audAssertion = "fleet-federation-assertion"
)

// LinkClaims proves a site's identity when opening the control channel.
type LinkClaims struct {
	SiteID string `json:"sid"`
	Nonce  string `json:"nonce"`
	jwt.RegisteredClaims
}

// ServiceClaims authenticates the hub-as-service-principal to a site.
type ServiceClaims struct {
	HubID  string `json:"hub"`
	SiteID string `json:"sid"`
	jwt.RegisteredClaims
}

// AssertionClaims carries a hub-authorized acting-user identity to a site, bound
// to a single request. permissions_snapshot is what the hub authorized; the site
// enforces it via the synthesized principal.
type AssertionClaims struct {
	SiteID        string   `json:"sid"`
	HubUserID     string   `json:"uid"`
	HubUsername   string   `json:"usr"`
	Permissions   []string `json:"perms"` // ["*"] = super admin
	SuperAdmin    bool     `json:"super"`
	ActionRef     string   `json:"act"`
	RequestDigest string   `json:"dig"` // sha256(method+"\n"+path+"\n"+body)
	Nonce         string   `json:"nonce"`
	jwt.RegisteredClaims
}

// RequestDigest binds an assertion to one exact request so it can't be replayed
// against a different action, host, or body.
func RequestDigest(method, path string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{'\n'})
	h.Write([]byte(path))
	h.Write([]byte{'\n'})
	h.Write(body)
	return base64.RawStdEncoding.EncodeToString(h.Sum(nil))
}

func sign(claims jwt.Claims, priv ed25519.PrivateKey) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
}

// keyFunc enforces EdDSA and returns the caller-supplied public key.
func keyFunc(pub ed25519.PublicKey) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("fedauth: unexpected signing method %q", t.Header["alg"])
		}
		return pub, nil
	}
}

// --- link tokens (site-signed) ---

func IssueLinkToken(siteID, nonce string, priv ed25519.PrivateKey, ttl time.Duration, now time.Time) (string, error) {
	return sign(LinkClaims{
		SiteID: siteID, Nonce: nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{audLink},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}, priv)
}

func ParseLinkToken(token string, pub ed25519.PublicKey) (*LinkClaims, error) {
	var c LinkClaims
	if _, err := jwt.ParseWithClaims(token, &c, keyFunc(pub), jwt.WithAudience(audLink)); err != nil {
		return nil, err
	}
	if c.SiteID == "" {
		return nil, errors.New("fedauth: link token missing site id")
	}
	return &c, nil
}

// --- service tokens (hub-signed) ---

func IssueServiceToken(hubID, siteID string, priv ed25519.PrivateKey, ttl time.Duration, now time.Time) (string, error) {
	return sign(ServiceClaims{
		HubID: hubID, SiteID: siteID,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{audService},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}, priv)
}

func ParseServiceToken(token string, pub ed25519.PublicKey) (*ServiceClaims, error) {
	var c ServiceClaims
	if _, err := jwt.ParseWithClaims(token, &c, keyFunc(pub), jwt.WithAudience(audService)); err != nil {
		return nil, err
	}
	return &c, nil
}

// --- acting-user assertions (hub-signed) ---

func IssueAssertion(c AssertionClaims, priv ed25519.PrivateKey, ttl time.Duration, now time.Time) (string, error) {
	c.RegisteredClaims = jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{audAssertion},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	return sign(c, priv)
}

func ParseAssertion(token string, pub ed25519.PublicKey) (*AssertionClaims, error) {
	var c AssertionClaims
	if _, err := jwt.ParseWithClaims(token, &c, keyFunc(pub), jwt.WithAudience(audAssertion)); err != nil {
		return nil, err
	}
	if c.HubUserID == "" || c.Nonce == "" {
		return nil, errors.New("fedauth: assertion missing user or nonce")
	}
	return &c, nil
}
