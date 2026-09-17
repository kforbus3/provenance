package k8sbroker

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/credresolve"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/store"
)

const proxyTimeout = 30 * time.Second

// proxy forwards a request under /k8s/clusters/{id}/proxy/* to the cluster's API
// server with the vaulted bearer token injected. This is what a user's kubectl
// targets, and what the cluster UI's live screens are built on.
//
// Implemented with httputil.ReverseProxy rather than client.Do + io.Copy,
// because three things a Kubernetes client does every day are impossible by
// hand:
//
//   - WATCHES. A watch is one long-lived response that trickles events. Copying
//     a body without flushing leaves those events in Go's write buffer until it
//     fills, so a UI built on watches shows nothing and then shows everything.
//     FlushInterval -1 flushes each write straight through.
//
//   - EXEC, ATTACH and PORT-FORWARD. These are not ordinary HTTP: the client
//     sends Upgrade and then speaks SPDY or WebSocket over the raw connection.
//     There is no body to copy. ReverseProxy detects the upgrade and hands the
//     hijacked connection over.
//
//   - LOGS -f. A follow is the same shape as a watch and fails the same way.
//
// The old 30s client timeout is deliberately not applied here either: every one
// of the above is *supposed* to stay open. A timeout belongs on getting the
// response headers back, not on how long the response may last.
func (h *handler) proxy(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	cluster, token, err := h.dialClusterStreaming(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	base, err := url.Parse(cluster.APIServer)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "cluster API server URL is invalid")
		return
	}

	// Everything after ".../proxy" is the upstream path (chi wildcard).
	rest := "/" + strings.TrimPrefix(chi.URLParam(r, "*"), "/")

	// Who is asking decides what they may do -- not the cluster's
	// ServiceAccount, which is the same for everyone. Checked HERE, before the
	// request is forwarded and before the cluster credential is attached, so a
	// refusal never reaches the cluster at all.
	//
	// Route middleware cannot do this: it gates the path /k8s/clusters/{id}/proxy/*
	// as one thing, and the distinction is inside the wildcard.
	p := auth.MustPrincipal(r)
	if p == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "not signed in")
		return
	}
	if ok, why := authorize(p.Has, r.Method, rest); !ok {
		h.audit(r, "k8s.proxy.denied", id, map[string]any{
			"cluster": cluster.Name, "method": r.Method, "path": rest,
			"needs": requiredPermission(r.Method, rest),
		})
		httpx.WriteError(w, http.StatusForbidden, why)
		return
	}

	// A self-review's answer is rewritten on the way back so Headlamp's buttons
	// match this person's Provenance role. Its request body is needed to know
	// what was asked, and it is read ONLY for these calls: buffering a watch or
	// a log follow would defeat the streaming this proxy exists to do.
	var reviewBody []byte
	if isSelfReview(rest) {
		reviewBody, _ = io.ReadAll(io.LimitReader(r.Body, reviewBodyLimit))
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(reviewBody))
		r.ContentLength = int64(len(reviewBody))
	}

	rp := newClusterProxy(cluster, token, base, rest,
		func(status int, err error) {
			d := map[string]any{"cluster": cluster.Name, "method": r.Method, "path": rest}
			if err != nil {
				d["error"] = err.Error()
			} else {
				d["status"] = status
			}
			h.audit(r, "k8s.proxy", id, d)
		})
	if reviewBody != nil || isSelfReview(rest) {
		if f := reviewIntersector(p.Has, rest, reviewBody); f != nil {
			audited := rp.ModifyResponse
			rp.ModifyResponse = func(resp *http.Response) error {
				if err := audited(resp); err != nil {
					return err
				}
				return f(resp)
			}
		}
	}
	rp.ServeHTTP(w, r)
}

// reviewBodyLimit bounds what is read from a self-review request. These carry a
// handful of fields; anything larger is not one, and reading it would hand a
// caller a way to make the broker buffer whatever they like.
const reviewBodyLimit = 64 << 10

// isSelfReview reports whether a path is one of the self-inspection APIs whose
// answer gets intersected with the caller's Provenance permissions.
func isSelfReview(path string) bool {
	resource, _, _ := parseAPIPath(path)
	return resource == "selfsubjectaccessreviews" || resource == "selfsubjectrulesreviews"
}

// streamingTransport dials the cluster with its TLS settings and NO overall
// request deadline.
//
// ResponseHeaderTimeout bounds the part that should be quick -- getting a reply
// at all -- while leaving the body open indefinitely, which is the whole point
// for a watch, a log follow or a shell.
func streamingTransport(cluster *store.K8sCluster) *http.Transport {
	return &http.Transport{
		TLSClientConfig:       clusterTLS(cluster),
		ResponseHeaderTimeout: proxyTimeout,
		// Proxied streams are long-lived and few; idle pooling across them buys
		// nothing and holds sockets open against the API server.
		IdleConnTimeout:     30 * time.Second,
		MaxIdleConnsPerHost: 4,
		ForceAttemptHTTP2:   false, // upgrade (SPDY/WebSocket) needs HTTP/1.1
	}
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

// simplifyList reduces a K8s list response to name/namespace/status/age rows.
//
// Status is derived per KIND rather than read from one field, because there is
// no single field that carries it. Reading only `status.phase` -- which is what
// this did -- worked for pods and namespaces and left NODES and DEPLOYMENTS
// blank, which reads as "no status" rather than "this view cannot tell you".
func simplifyList(body []byte) []map[string]any {
	var parsed struct {
		Items []listItem `json:"items"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(parsed.Items))
	for _, it := range parsed.Items {
		out = append(out, map[string]any{
			"name": it.Metadata.Name, "namespace": it.Metadata.Namespace,
			"status": statusOf(it), "created": it.Metadata.CreationTimestamp,
		})
	}
	return out
}

// listItem is the union of the fields the supported kinds carry a status in.
type listItem struct {
	Metadata struct {
		Name              string `json:"name"`
		Namespace         string `json:"namespace"`
		CreationTimestamp string `json:"creationTimestamp"`
	} `json:"metadata"`
	Spec struct {
		// Nodes: cordoned. A Ready node that takes no work is not simply "Ready",
		// and that distinction is the whole reason somebody looks at this column.
		Unschedulable bool `json:"unschedulable"`
	} `json:"spec"`
	Status struct {
		// Pods and namespaces.
		Phase string `json:"phase"`
		// Nodes: readiness lives in a condition, not a phase.
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
		// Deployments, statefulsets, daemonsets: a count, not a word.
		Replicas      *int `json:"replicas"`
		ReadyReplicas *int `json:"readyReplicas"`
	} `json:"status"`
}

// statusOf picks the most specific status the object actually carries.
func statusOf(it listItem) string {
	if it.Status.Phase != "" {
		return it.Status.Phase // pods, namespaces
	}
	if it.Status.Replicas != nil {
		ready := 0
		if it.Status.ReadyReplicas != nil {
			ready = *it.Status.ReadyReplicas
		}
		return fmt.Sprintf("%d/%d", ready, *it.Status.Replicas) // workloads
	}
	for _, c := range it.Status.Conditions {
		if c.Type != "Ready" {
			continue
		}
		s := "NotReady"
		if c.Status == "True" {
			s = "Ready"
		}
		if it.Spec.Unschedulable {
			// Matches what kubectl prints, and it matters: a cordoned node looks
			// healthy by every other measure while running nothing new.
			s += ",SchedulingDisabled"
		}
		return s // nodes
	}
	// Genuinely statusless (a Service, a ConfigMap). Left empty so the UI can say
	// so, rather than inventing a word for it.
	return ""
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
	if !cluster.InsecureTLS && cluster.CACert != "" {
		if p := x509.NewCertPool(); !p.AppendCertsFromPEM([]byte(cluster.CACert)) {
			return nil, "", nil, fmt.Errorf("cluster CA certificate is invalid")
		}
	}
	client := &http.Client{Timeout: proxyTimeout, Transport: &http.Transport{
		TLSClientConfig: clusterTLS(cluster),
	}}
	return cluster, token, client, nil
}

// clusterTLS builds the TLS config for reaching one cluster's API server.
//
// One definition, shared by the timeout-bounded client the resource browser uses
// and the streaming transport the proxy uses -- so "verify against this CA" and
// "skip verification" cannot come to mean different things on the two paths.
func clusterTLS(cluster *store.K8sCluster) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cluster.InsecureTLS {
		cfg.InsecureSkipVerify = true
		return cfg
	}
	if cluster.CACert != "" {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM([]byte(cluster.CACert)) {
			cfg.RootCAs = pool
		}
	}
	return cfg
}

// dialClusterStreaming resolves a cluster and its credential without building a
// client: the proxy supplies its own transport, because a shared one would carry
// the request timeout that must not apply to streams.
func (h *handler) dialClusterStreaming(ctx context.Context, id uuid.UUID) (*store.K8sCluster, string, error) {
	cluster, token, _, err := h.dialCluster(ctx, id)
	return cluster, token, err
}

// credentialToken decrypts the vaulted secret and returns its value as the bearer
// token. Zero-knowledge: the plaintext exists only in RAM at point of use.
func (h *handler) credentialToken(ctx context.Context, credID uuid.UUID) (string, error) {
	key, _ := h.d.Cfg.VaultKey() // used only for locally-sealed secrets; external ignores it
	_, pt, err := credresolve.OpenByID(ctx, h.d.Store, credID, key, h.d.Cfg.ExtSecret())
	if err != nil {
		return "", fmt.Errorf("could not resolve credential")
	}
	return strings.TrimSpace(string(pt)), nil
}

// newClusterProxy builds the reverse proxy for one upstream request.
//
// Separated from the handler so the three things that are easy to get silently
// wrong -- credential swapping, upgrade passthrough and flushing -- can be
// tested against a real upstream without a database.
func newClusterProxy(
	cluster *store.K8sCluster, token string, base *url.URL, rest string,
	audited func(status int, err error),
) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		FlushInterval: -1, // flush every write: watches and log follows are useless batched
		Rewrite:       clusterRewrite(base, rest, token),
		Transport:     streamingTransport(cluster),
		ModifyResponse: func(resp *http.Response) error {
			audited(resp.StatusCode, nil)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			audited(0, err)
			httpx.WriteError(w, http.StatusBadGateway, "cluster unreachable: "+err.Error())
		},
	}
}

// clusterRewrite retargets the request at the cluster and swaps the credential.
func clusterRewrite(base *url.URL, rest, token string) func(*httputil.ProxyRequest) {
	return func(pr *httputil.ProxyRequest) {
		pr.Out.URL.Scheme = base.Scheme
		pr.Out.URL.Host = base.Host
		pr.Out.URL.Path = strings.TrimSuffix(base.Path, "/") + rest
		pr.Out.URL.RawQuery = pr.In.URL.RawQuery
		pr.Out.Host = base.Host

		// The caller authenticated to Provenance. That credential must never
		// reach the cluster, and the cluster's must never reach the caller.
		pr.Out.Header.Del("Authorization")
		pr.Out.Header.Del("Cookie")
		pr.Out.Header.Del("X-Csrf-Token")
		pr.Out.Header.Set("Authorization", "Bearer "+token)

		// k8s selects its exec/attach protocol from this header; dropping it
		// makes a shell negotiate down or fail outright.
		if v, ok := pr.In.Header["X-Stream-Protocol-Version"]; ok {
			pr.Out.Header["X-Stream-Protocol-Version"] = v
		}
	}
}
