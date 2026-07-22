package k8sbroker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/secretbox"
	"github.com/fleet-terminal/backend/internal/store"
)

const proxyTimeout = 30 * time.Second

// proxy forwards a request under /k8s/clusters/{id}/proxy/* to the cluster's API server
// with the vaulted bearer token injected. This is what a user's kubectl targets.
func (h *handler) proxy(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	cluster, token, client, err := h.dialCluster(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	// Everything after ".../proxy" is the upstream path (chi wildcard).
	rest := chi.URLParam(r, "*")
	upstream := cluster.APIServer + "/" + strings.TrimPrefix(rest, "/")
	if r.URL.RawQuery != "" {
		upstream += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream, r.Body)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad upstream request")
		return
	}
	// Forward content headers, then inject auth (never forward the caller's Fleet auth).
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if acc := r.Header.Get("Accept"); acc != "" {
		req.Header.Set("Accept", acc)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "cluster unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	h.audit(r, "k8s.proxy", id, map[string]any{
		"cluster": cluster.Name, "method": r.Method, "path": "/" + strings.TrimPrefix(rest, "/"), "status": resp.StatusCode,
	})

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// resource kinds the browser can list, mapped to their API list path (%s = namespace).
var resourceKinds = map[string]struct {
	path        string
	clusterWide bool
}{
	"namespaces":  {"/api/v1/namespaces", true},
	"nodes":       {"/api/v1/nodes", true},
	"pods":        {"/api/v1/namespaces/%s/pods", false},
	"services":    {"/api/v1/namespaces/%s/services", false},
	"deployments": {"/apis/apps/v1/namespaces/%s/deployments", false},
}

// resources is a convenience read: list a supported resource kind and return a
// simplified rows view for the built-in browser (no kubectl required).
func (h *handler) resources(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	kind := r.URL.Query().Get("kind")
	rk, known := resourceKinds[kind]
	if !known {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported kind")
		return
	}
	cluster, token, client, err := h.dialCluster(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = cluster.Namespace
	}
	path := rk.path
	if !rk.clusterWide {
		path = fmt.Sprintf(rk.path, url.PathEscape(ns))
	}

	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, cluster.APIServer+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "cluster unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	h.audit(r, "k8s.list", id, map[string]any{"cluster": cluster.Name, "kind": kind, "namespace": ns, "status": resp.StatusCode})

	if resp.StatusCode != http.StatusOK {
		httpx.WriteError(w, http.StatusBadGateway, "list failed (HTTP "+fmt.Sprint(resp.StatusCode)+"): "+strings.TrimSpace(string(body)))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"kind": kind, "namespace": ns, "items": simplifyList(body)})
}

// simplifyList reduces a K8s list response to name/namespace/status/ready/age rows.
func simplifyList(body []byte) []map[string]any {
	var parsed struct {
		Items []struct {
			Metadata struct {
				Name              string `json:"name"`
				Namespace         string `json:"namespace"`
				CreationTimestamp string `json:"creationTimestamp"`
			} `json:"metadata"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(parsed.Items))
	for _, it := range parsed.Items {
		out = append(out, map[string]any{
			"name": it.Metadata.Name, "namespace": it.Metadata.Namespace,
			"status": it.Status.Phase, "created": it.Metadata.CreationTimestamp,
		})
	}
	return out
}

// dialCluster resolves the cluster, its vaulted bearer token, and an HTTP client
// configured to verify (or skip) the API server's TLS.
func (h *handler) dialCluster(ctx context.Context, id uuid.UUID) (*store.K8sCluster, string, *http.Client, error) {
	cluster, err := h.d.Store.GetK8sCluster(ctx, id)
	if err != nil {
		return nil, "", nil, fmt.Errorf("cluster not found")
	}
	if cluster.CredentialID == nil {
		return nil, "", nil, fmt.Errorf("attach a vault credential (bearer token) to this cluster first")
	}
	token, err := h.credentialToken(ctx, *cluster.CredentialID)
	if err != nil {
		return nil, "", nil, fmt.Errorf("credential unavailable: %w", err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cluster.InsecureTLS {
		tlsCfg.InsecureSkipVerify = true
	} else if cluster.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cluster.CACert)) {
			return nil, "", nil, fmt.Errorf("cluster CA certificate is invalid")
		}
		tlsCfg.RootCAs = pool
	}
	client := &http.Client{Timeout: proxyTimeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	return cluster, token, client, nil
}

// credentialToken decrypts the vaulted secret and returns its value as the bearer
// token. Zero-knowledge: the plaintext exists only in RAM at point of use.
func (h *handler) credentialToken(ctx context.Context, credID uuid.UUID) (string, error) {
	key, err := h.d.Cfg.VaultKey()
	if err != nil {
		return "", err
	}
	sealed, err := h.d.Store.GetVaultSecretSealed(ctx, credID)
	if err != nil {
		return "", err
	}
	pt, err := secretbox.Open(key, sealed)
	if err != nil {
		return "", fmt.Errorf("could not decrypt credential")
	}
	return strings.TrimSpace(string(pt)), nil
}
