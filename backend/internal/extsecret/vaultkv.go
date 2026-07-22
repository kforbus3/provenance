package extsecret

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// vaultKV reads secrets from a HashiCorp Vault KV v2 engine. A reference has the form
// "mount/path#field" (e.g. "secret/db/prod#password"). If "#field" is omitted and the
// KV secret has exactly one field, that field is returned. Implemented against the
// Vault HTTP API directly — no Vault SDK.
type vaultKV struct {
	addr   string
	token  string
	client *http.Client
}

func newVaultKV(cfg Config) (Provider, error) {
	addr := strings.TrimRight(strings.TrimSpace(cfg.VaultAddr), "/")
	if addr == "" {
		return nil, fmt.Errorf("extsecret(vault-kv): FLEET_EXTSECRET_VAULT_ADDR is required")
	}
	if strings.TrimSpace(cfg.VaultToken) == "" {
		return nil, fmt.Errorf("extsecret(vault-kv): FLEET_EXTSECRET_VAULT_TOKEN is required")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.VaultTLSSkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}
	if cfg.VaultCACertFile != "" {
		pem, err := os.ReadFile(cfg.VaultCACertFile)
		if err != nil {
			return nil, fmt.Errorf("extsecret(vault-kv): read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("extsecret(vault-kv): no certificates parsed from %s", cfg.VaultCACertFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &vaultKV{
		addr:   addr,
		token:  cfg.VaultToken,
		client: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
	}, nil
}

func (v *vaultKV) Name() string { return ProviderVaultKV }

func (v *vaultKV) Fetch(ctx context.Context, ref string) (string, error) {
	mountPath, field := splitRef(ref)
	mount, path, err := splitMountPath(mountPath)
	if err != nil {
		return "", err
	}
	// KV v2 read path: {mount}/data/{path}
	u := v.addr + "/v1/" + mount + "/data/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", v.token)
	resp, err := v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("extsecret(vault-kv): request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("extsecret(vault-kv): %s -> HTTP %d: %s", ref, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("extsecret(vault-kv): decode response: %w", err)
	}
	data := out.Data.Data
	if len(data) == 0 {
		return "", fmt.Errorf("extsecret(vault-kv): no data at %s", mountPath)
	}
	if field == "" {
		if len(data) != 1 {
			return "", fmt.Errorf("extsecret(vault-kv): %s has multiple fields; specify one as path#field", mountPath)
		}
		for _, v := range data {
			return toString(v), nil
		}
	}
	val, ok := data[field]
	if !ok {
		return "", fmt.Errorf("extsecret(vault-kv): field %q not found at %s", field, mountPath)
	}
	return toString(val), nil
}

func (v *vaultKV) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.addr+"/v1/sys/health", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.token)
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("extsecret(vault-kv): unreachable: %w", err)
	}
	defer resp.Body.Close()
	// 200 (active) or 429/473 (standby/perf-standby) all mean "reachable & unsealed".
	if resp.StatusCode == http.StatusOK || resp.StatusCode == 429 || resp.StatusCode == 473 {
		return nil
	}
	return fmt.Errorf("extsecret(vault-kv): health HTTP %d", resp.StatusCode)
}

// splitRef separates a "path#field" reference.
func splitRef(ref string) (path, field string) {
	if i := strings.LastIndexByte(ref, '#'); i >= 0 {
		return strings.TrimSpace(ref[:i]), strings.TrimSpace(ref[i+1:])
	}
	return strings.TrimSpace(ref), ""
}

// splitMountPath splits "mount/sub/path" into ("mount", "sub/path").
func splitMountPath(mp string) (mount, path string, err error) {
	mp = strings.Trim(mp, "/")
	i := strings.IndexByte(mp, '/')
	if i <= 0 || i == len(mp)-1 {
		return "", "", fmt.Errorf("extsecret(vault-kv): reference must be mount/path[#field], got %q", mp)
	}
	return mp[:i], mp[i+1:], nil
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}
