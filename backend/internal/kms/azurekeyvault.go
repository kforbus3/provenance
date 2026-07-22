package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// azureKeyVaultPrefix tags a wrapped blob produced by the Azure Key Vault backend.
const azureKeyVaultPrefix = "azurekv:v1:"

// azureKeyVault wraps/unwraps via Azure Key Vault's wrapKey/unwrapKey operations
// (RSA-OAEP-256). The key never leaves the vault. Authentication uses the Azure AD
// client-credentials flow; tokens are cached until shortly before expiry. Implemented
// against the REST API directly — no Azure SDK.
type azureKeyVault struct {
	vaultURL string // e.g. https://myvault.vault.azure.net
	keyName  string
	tenantID string
	clientID string
	secret   string
	client   *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

func newAzureKeyVault(cfg Config) (Provider, error) {
	vault := strings.TrimRight(strings.TrimSpace(cfg.AzureVaultURL), "/")
	if vault == "" {
		return nil, fmt.Errorf("kms(azure-keyvault): FLEET_KMS_AZURE_VAULT_URL is required")
	}
	if strings.TrimSpace(cfg.KeyID) == "" {
		return nil, fmt.Errorf("kms(azure-keyvault): FLEET_KMS_KEY_ID (key name) is required")
	}
	for k, v := range map[string]string{
		"FLEET_KMS_AZURE_TENANT_ID":     cfg.AzureTenantID,
		"FLEET_KMS_AZURE_CLIENT_ID":     cfg.AzureClientID,
		"FLEET_KMS_AZURE_CLIENT_SECRET": cfg.AzureClientSecret,
	} {
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("kms(azure-keyvault): %s is required", k)
		}
	}
	return &azureKeyVault{
		vaultURL: vault,
		keyName:  cfg.KeyID,
		tenantID: cfg.AzureTenantID,
		clientID: cfg.AzureClientID,
		secret:   cfg.AzureClientSecret,
		client:   &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (a *azureKeyVault) Name() string { return "azure-keyvault" }

// bearer returns a valid Azure AD access token, fetching (and caching) one via the
// client-credentials flow when the cached token is missing or near expiry.
func (a *azureKeyVault) bearer(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && time.Until(a.tokenExp) > 60*time.Second {
		return a.token, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {a.clientID},
		"client_secret": {a.secret},
		"scope":         {"https://vault.azure.net/.default"},
	}
	tokenURL := "https://login.microsoftonline.com/" + url.PathEscape(a.tenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("kms(azure-keyvault): token request failed: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kms(azure-keyvault): token HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("kms(azure-keyvault): bad token response")
	}
	a.token = out.AccessToken
	a.tokenExp = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return a.token, nil
}

func (a *azureKeyVault) Wrap(ctx context.Context, plaintext []byte) (string, error) {
	var out struct {
		Value string `json:"value"`
	}
	if err := a.keyOp(ctx, "wrapkey", base64.RawURLEncoding.EncodeToString(plaintext), &out); err != nil {
		return "", err
	}
	if out.Value == "" {
		return "", fmt.Errorf("kms(azure-keyvault): empty wrap result")
	}
	return azureKeyVaultPrefix + out.Value, nil
}

func (a *azureKeyVault) Unwrap(ctx context.Context, token string) ([]byte, error) {
	if !strings.HasPrefix(token, azureKeyVaultPrefix) {
		return nil, fmt.Errorf("kms(azure-keyvault): token is not an Azure Key Vault ciphertext")
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := a.keyOp(ctx, "unwrapkey", strings.TrimPrefix(token, azureKeyVaultPrefix), &out); err != nil {
		return nil, err
	}
	pt, err := base64.RawURLEncoding.DecodeString(out.Value)
	if err != nil {
		return nil, fmt.Errorf("kms(azure-keyvault): decode plaintext: %w", err)
	}
	return pt, nil
}

func (a *azureKeyVault) Health(ctx context.Context) error {
	// GET the key's metadata: proves the token is valid and the key exists.
	req, err := a.authedRequest(ctx, http.MethodGet,
		a.vaultURL+"/keys/"+url.PathEscape(a.keyName)+"?api-version=7.4", nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("kms(azure-keyvault): unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("kms(azure-keyvault): key check HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}

// keyOp POSTs a wrapkey/unwrapkey operation (RSA-OAEP-256) and decodes the result.
func (a *azureKeyVault) keyOp(ctx context.Context, op, valueB64URL string, out any) error {
	body, _ := json.Marshal(map[string]string{"alg": "RSA-OAEP-256", "value": valueB64URL})
	u := a.vaultURL + "/keys/" + url.PathEscape(a.keyName) + "/" + op + "?api-version=7.4"
	req, err := a.authedRequest(ctx, http.MethodPost, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("kms(azure-keyvault): %s failed: %w", op, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kms(azure-keyvault): %s HTTP %d: %s", op, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return json.Unmarshal(data, out)
}

func (a *azureKeyVault) authedRequest(ctx context.Context, method, u string, body []byte) (*http.Request, error) {
	token, err := a.bearer(ctx)
	if err != nil {
		return nil, err
	}
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}
