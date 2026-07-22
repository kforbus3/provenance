// Package itsmapi is the management API for the ITSM (ServiceNow/Jira) integration:
// configure the connection and test it. Gated by System.Configure. The approval flow
// (internal/approvals) uses the stored config to open a ticket per access request.
package itsmapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/itsm"
)

// Mount attaches the ITSM config routes, gated by System.Configure.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.Use(d.Auth.RequirePermission("System.Configure"))
		pr.Get("/itsm/config", h.get)
		pr.Put("/itsm/config", h.put)
		pr.Post("/itsm/test", h.test)
	})
}

type handler struct{ d *app.Deps }

type configResponse struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"baseUrl"`
	User     string `json:"user"`
	Project  string `json:"project"`
	Enabled  bool   `json:"enabled"`
	HasToken bool   `json:"hasToken"` // the token itself is never returned
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	cfg, err := itsm.LoadConfig(r.Context(), h.d.Store, h.d.Cfg.CAKeyPassphrase)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load configuration")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, configResponse{
		Provider: cfg.Provider, BaseURL: cfg.BaseURL, User: cfg.User, Project: cfg.Project,
		Enabled: cfg.Enabled, HasToken: cfg.Token != "",
	})
}

type configRequest struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"baseUrl"`
	User     string `json:"user"`
	Project  string `json:"project"`
	Enabled  bool   `json:"enabled"`
	Token    string `json:"token"` // omit/blank to keep the stored token
}

func (h *handler) put(w http.ResponseWriter, r *http.Request) {
	var rq configRequest
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if rq.Enabled && !itsm.Supported(rq.Provider) {
		httpx.WriteError(w, http.StatusBadRequest, "provider must be servicenow or jira")
		return
	}
	// Preserve the existing token when the client sends a blank one (it's never echoed).
	existing, _ := itsm.LoadConfig(r.Context(), h.d.Store, h.d.Cfg.CAKeyPassphrase)
	token := strings.TrimSpace(rq.Token)
	if token == "" {
		token = existing.Token
	}
	cfg := itsm.Config{
		Provider: rq.Provider, BaseURL: strings.TrimSpace(rq.BaseURL), User: strings.TrimSpace(rq.User),
		Project: strings.TrimSpace(rq.Project), Enabled: rq.Enabled, Token: token,
	}
	if err := itsm.SaveConfig(r.Context(), h.d.Store, h.d.Cfg.CAKeyPassphrase, cfg); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save configuration")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, configResponse{
		Provider: cfg.Provider, BaseURL: cfg.BaseURL, User: cfg.User, Project: cfg.Project,
		Enabled: cfg.Enabled, HasToken: cfg.Token != "",
	})
}

func (h *handler) test(w http.ResponseWriter, r *http.Request) {
	cfg, err := itsm.LoadConfig(r.Context(), h.d.Store, h.d.Cfg.CAKeyPassphrase)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load configuration")
		return
	}
	if !cfg.Configured() {
		httpx.WriteError(w, http.StatusBadRequest, "configure and enable the ITSM integration first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := itsm.New(cfg).Test(ctx); err != nil {
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
