package kms

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// vaultTransit wraps/unwraps via a HashiCorp Vault Transit secrets engine. Transit
// is Vault's "encryption as a service": the key never leaves Vault, and every
// encrypt/decrypt is authorized by the Vault token and audited by Vault. Implemented
// against Vault's HTTP API directly (no Vault SDK) to keep dependencies minimal.
type vaultTransit struct {
	addr   string // base address, no trailing slash
	token  string
	key    string
	client *http.Client
}

func newVaultTransit(cfg Config) (Provider, error) {
	addr := strings.TrimRight(strings.TrimSpace(cfg.VaultAddr), "/")
	if addr == "" {
		return nil, fmt.Errorf("kms(vault-transit): FLEET_KMS_VAULT_ADDR is required")
	}
	if strings.TrimSpace(cfg.VaultToken) == "" {
		return nil, fmt.Errorf("kms(vault-transit): FLEET_KMS_VAULT_TOKEN is required")
	}
	if strings.TrimSpace(cfg.KeyID) == "" {
		return nil, fmt.Errorf("kms(vault-transit): FLEET_KMS_KEY_ID (transit key name) is required")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.VaultTLSSkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}
	if cfg.VaultCACertFile != "" {
		pem, err := os.ReadFile(cfg.VaultCACertFile)
		if err != nil {
			return nil, fmt.Errorf("kms(vault-transit): read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kms(vault-transit): no certificates parsed from %s", cfg.VaultCACertFile)
		}
		tlsCfg.RootCAs = pool
	}

	return &vaultTransit{
		addr:  addr,
		token: cfg.VaultToken,
		key:   cfg.KeyID,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

func (v *vaultTransit) Name() string { return "vault-transit" }

func (v *vaultTransit) Wrap(ctx context.Context, plaintext []byte) (string, error) {
	body := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := v.call(ctx, "/v1/transit/encrypt/"+v.key, body, &out); err != nil {
		return "", err
	}
	if out.Data.Ciphertext == "" {
		return "", fmt.Errorf("kms(vault-transit): empty ciphertext from Vault")
	}
	// Vault returns a self-describing token like "vault:v1:...". Store it verbatim.
	return out.Data.Ciphertext, nil
}

func (v *vaultTransit) Unwrap(ctx context.Context, token string) ([]byte, error) {
	if !strings.HasPrefix(token, "vault:") {
		return nil, fmt.Errorf("kms(vault-transit): token is not a Vault ciphertext")
	}
	body := map[string]string{"ciphertext": token}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := v.call(ctx, "/v1/transit/decrypt/"+v.key, body, &out); err != nil {
		return nil, err
	}
	pt, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("kms(vault-transit): decode plaintext: %w", err)
	}
	return pt, nil
}

func (v *vaultTransit) Health(ctx context.Context) error {
	// Reading the transit key's metadata verifies both reachability and that the
	// configured key exists (a GET, so it needs only read on the key path).
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.addr+"/v1/transit/keys/"+v.key, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.token)
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("kms(vault-transit): unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("kms(vault-transit): key check failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}

// call POSTs a JSON body to a Vault path and decodes the JSON response into out.
func (v *vaultTransit) call(ctx context.Context, path string, body any, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.addr+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("kms(vault-transit): request failed: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kms(vault-transit): %s -> HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("kms(vault-transit): decode response: %w", err)
	}
	return nil
}
