// Package k8sbroker brokers access to registered Kubernetes clusters. Fleet acts as an
// authenticating proxy: a user (or their kubectl) authenticates to Fleet, and Fleet
// forwards the request to the cluster's API server with a vaulted bearer-token
// credential injected — the operator never sees the token — auditing every call. A
// small resource browser is layered on the same proxy. Mirrors internal/dbbroker.
package k8sbroker

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// Mount attaches the cluster-registry CRUD (Kubernetes.Manage) and the proxy /
// resource-browser routes (Kubernetes.Access).
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)

		// Registry management.
		pr.With(d.Auth.RequirePermission("Kubernetes.Manage")).Get("/k8s/clusters", h.list)
		pr.With(d.Auth.RequirePermission("Kubernetes.Manage")).Post("/k8s/clusters", h.create)
		pr.With(d.Auth.RequirePermission("Kubernetes.Manage")).Put("/k8s/clusters/{id}", h.update)
		pr.With(d.Auth.RequirePermission("Kubernetes.Manage")).Delete("/k8s/clusters/{id}", h.del)

		// Brokered access.
		pr.With(d.Auth.RequirePermission("Kubernetes.Access")).Get("/k8s/clusters/{id}", h.get)
		// The resource browser makes specific, safe read calls through the proxy.
		pr.With(d.Auth.RequirePermission("Kubernetes.Access")).Get("/k8s/clusters/{id}/resources", h.resources)
		// Raw authenticating proxy: everything under /proxy/* is forwarded to the API
		// server. This is what a user's kubectl points at.
		proxyRoute := "/k8s/clusters/{id}/proxy/*"
		pr.With(d.Auth.RequirePermission("Kubernetes.Access")).Handle(proxyRoute, http.HandlerFunc(h.proxy))
	})
}

type handler struct{ d *app.Deps }

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	cs, err := h.d.Store.ListK8sClusters(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list clusters")
		return
	}
	if cs == nil {
		cs = []store.K8sCluster{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"clusters": cs})
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	c, err := h.d.Store.GetK8sCluster(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

type clusterReq struct {
	Name         string     `json:"name"`
	APIServer    string     `json:"apiServer"`
	CredentialID *uuid.UUID `json:"credentialId"`
	CACert       string     `json:"caCert"`
	InsecureTLS  bool       `json:"insecureTls"`
	Namespace    string     `json:"namespace"`
	Description  string     `json:"description"`
}

func (rq clusterReq) toInput(by uuid.UUID) store.K8sClusterInput {
	ns := strings.TrimSpace(rq.Namespace)
	if ns == "" {
		ns = "default"
	}
	return store.K8sClusterInput{
		Name: strings.TrimSpace(rq.Name), APIServer: strings.TrimRight(strings.TrimSpace(rq.APIServer), "/"),
		CredentialID: rq.CredentialID, CACert: rq.CACert, InsecureTLS: rq.InsecureTLS,
		Namespace: ns, Description: rq.Description, CreatedBy: by,
	}
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var rq clusterReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if strings.TrimSpace(rq.Name) == "" || !strings.HasPrefix(rq.APIServer, "https://") {
		httpx.WriteError(w, http.StatusBadRequest, "name and an https:// API server are required")
		return
	}
	p := auth.MustPrincipal(r)
	c, err := h.d.Store.CreateK8sCluster(r.Context(), rq.toInput(p.UserID))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not register the cluster")
		return
	}
	h.audit(r, "k8s.cluster.create", c.ID, map[string]any{"name": c.Name, "apiServer": c.APIServer})
	httpx.WriteJSON(w, http.StatusCreated, c)
}

func (h *handler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var rq clusterReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	p := auth.MustPrincipal(r)
	c, err := h.d.Store.UpdateK8sCluster(r.Context(), id, rq.toInput(p.UserID))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update the cluster")
		return
	}
	h.audit(r, "k8s.cluster.update", c.ID, map[string]any{"name": c.Name})
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (h *handler) del(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.DeleteK8sCluster(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete the cluster")
		return
	}
	h.audit(r, "k8s.cluster.delete", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) audit(r *http.Request, action string, id uuid.UUID, detail map[string]any) {
	p := auth.MustPrincipal(r)
	ev := models.AuditEvent{Action: action, TargetKind: "k8s_cluster", TargetID: id.String(), Detail: detail, IP: clientIP(r)}
	if p != nil {
		ev.ActorID = &p.UserID
		ev.ActorName = p.Username
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), ev)
}

func parseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return uuid.Nil, false
	}
	return id, true
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}
