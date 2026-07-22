package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// gcpKMSPrefix tags a wrapped blob produced by the GCP Cloud KMS backend.
const gcpKMSPrefix = "gcpkms:v1:"

// gcpKMS wraps/unwraps via Google Cloud KMS encrypt/decrypt. The key never leaves
// Cloud KMS. Authentication uses a service-account key: a signed RS256 JWT is exchanged
// for an OAuth2 access token (cached until near expiry). Implemented against the REST
// API directly — no Google SDK.
type gcpKMS struct {
	keyName     string // projects/P/locations/L/keyRings/KR/cryptoKeys/K
	clientEmail string
	tokenURI    string
	privKey     *rsa.PrivateKey
	client      *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

type gcpServiceAccount struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

func newGCPKMS(cfg Config) (Provider, error) {
	if strings.TrimSpace(cfg.KeyID) == "" {
		return nil, fmt.Errorf("kms(gcp-kms): FLEET_KMS_KEY_ID (cryptoKey resource name) is required")
	}
	raw := []byte(cfg.GCPCredentialsJSON)
	if len(raw) == 0 && cfg.GCPCredentialsFile != "" {
		b, err := os.ReadFile(cfg.GCPCredentialsFile)
		if err != nil {
			return nil, fmt.Errorf("kms(gcp-kms): read credentials file: %w", err)
		}
		raw = b
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("kms(gcp-kms): FLEET_KMS_GCP_CREDENTIALS or FLEET_KMS_GCP_CREDENTIALS_FILE is required")
	}
	var sa gcpServiceAccount
	if err := json.Unmarshal(raw, &sa); err != nil {
		return nil, fmt.Errorf("kms(gcp-kms): parse service-account JSON: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, fmt.Errorf("kms(gcp-kms): service-account JSON missing client_email/private_key")
	}
	priv, err := parseRSAPrivateKey(sa.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("kms(gcp-kms): %w", err)
	}
	tokenURI := sa.TokenURI
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token"
	}
	return &gcpKMS{
		keyName:     cfg.KeyID,
		clientEmail: sa.ClientEmail,
		tokenURI:    tokenURI,
		privKey:     priv,
		client:      &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (g *gcpKMS) Name() string { return "gcp-kms" }

func (g *gcpKMS) Wrap(ctx context.Context, plaintext []byte) (string, error) {
	var out struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := g.cryptoOp(ctx, "encrypt", map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}, &out); err != nil {
		return "", err
	}
	if out.Ciphertext == "" {
		return "", fmt.Errorf("kms(gcp-kms): empty ciphertext")
	}
	return gcpKMSPrefix + out.Ciphertext, nil
}

func (g *gcpKMS) Unwrap(ctx context.Context, token string) ([]byte, error) {
	if !strings.HasPrefix(token, gcpKMSPrefix) {
		return nil, fmt.Errorf("kms(gcp-kms): token is not a GCP KMS ciphertext")
	}
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	if err := g.cryptoOp(ctx, "decrypt", map[string]string{"ciphertext": strings.TrimPrefix(token, gcpKMSPrefix)}, &out); err != nil {
		return nil, err
	}
	pt, err := base64.StdEncoding.DecodeString(out.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("kms(gcp-kms): decode plaintext: %w", err)
	}
	return pt, nil
}

func (g *gcpKMS) Health(ctx context.Context) error {
	// GET the cryptoKey metadata: proves the token is valid and the key is reachable.
	token, err := g.bearer(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://cloudkms.googleapis.com/v1/"+g.keyName, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("kms(gcp-kms): unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("kms(gcp-kms): key check HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}

func (g *gcpKMS) cryptoOp(ctx context.Context, op string, body map[string]string, out any) error {
	token, err := g.bearer(ctx)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(body)
	u := "https://cloudkms.googleapis.com/v1/" + g.keyName + ":" + op
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("kms(gcp-kms): %s failed: %w", op, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kms(gcp-kms): %s HTTP %d: %s", op, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return json.Unmarshal(data, out)
}

// bearer returns a valid OAuth2 access token, minting one from a signed JWT assertion
// when the cached token is missing or near expiry.
func (g *gcpKMS) bearer(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.token != "" && time.Until(g.tokenExp) > 60*time.Second {
		return g.token, nil
	}
	now := time.Now()
	assertion, err := g.signJWT(now)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("kms(gcp-kms): token request failed: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kms(gcp-kms): token HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("kms(gcp-kms): bad token response")
	}
	g.token = out.AccessToken
	g.tokenExp = now.Add(time.Duration(out.ExpiresIn) * time.Second)
	return g.token, nil
}

// signJWT builds and RS256-signs the service-account assertion for the token exchange.
func (g *gcpKMS) signJWT(now time.Time) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iss":   g.clientEmail,
		"scope": "https://www.googleapis.com/auth/cloudkms",
		"aud":   g.tokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.privKey, crypto.SHA256, h[:])
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// parseRSAPrivateKey parses a PEM RSA private key (PKCS#8 or PKCS#1).
func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in private key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
		return rk, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
