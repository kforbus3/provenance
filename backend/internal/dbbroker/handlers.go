// Package dbbroker brokers privileged SQL access to registered database targets:
// it reaches the database through the jump host, authenticates with a vaulted
// credential (the operator never sees the password), executes the caller's query,
// and audits it. Postgres in this first version.
package dbbroker

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
	"github.com/fleet-terminal/backend/internal/sshgw"
	"github.com/fleet-terminal/backend/internal/store"
)

type handler struct {
	d  *app.Deps
	gw *sshgw.Gateway
}

// Mount attaches the database-broker routes. Management is Database.Manage; opening a
// brokered session and running queries is Database.Connect.
func Mount(r chi.Router, d *app.Deps, gw *sshgw.Gateway) {
	h := &handler{d: d, gw: gw}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Database.Connect")).Get("/databases", h.list)
		pr.With(d.Auth.RequirePermission("Database.Connect")).Post("/databases/{id}/query", h.query)

		pr.With(d.Auth.RequirePermission("Database.Manage")).Post("/databases", h.create)
		pr.With(d.Auth.RequirePermission("Database.Manage")).Put("/databases/{id}", h.update)
		pr.With(d.Auth.RequirePermission("Database.Manage")).Delete("/databases/{id}", h.del)
	})
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	dbs, err := h.d.Store.ListDatabases(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list databases")
		return
	}
	if dbs == nil {
		dbs = []models.Database{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"databases": dbs})
}

type dbReq struct {
	Name         string     `json:"name"`
	Engine       string     `json:"engine"`
	Address      string     `json:"address"`
	Port         int        `json:"port"`
	DatabaseName string     `json:"databaseName"`
	CredentialID *uuid.UUID `json:"credentialId"`
	Description  string     `json:"description"`
}

func (rq dbReq) toInput(by uuid.UUID) store.DatabaseInput {
	engine := normalizeEngine(rq.Engine)
	info := engines[engine] // engine validity is checked by the caller before this
	port := rq.Port
	if port == 0 {
		port = info.defaultPort
	}
	dbName := strings.TrimSpace(rq.DatabaseName)
	if dbName == "" {
		dbName = info.defaultDB
	}
	return store.DatabaseInput{
		Name: strings.TrimSpace(rq.Name), Engine: engine, Address: strings.TrimSpace(rq.Address),
		Port: port, DatabaseName: dbName, CredentialID: rq.CredentialID,
		Description: rq.Description, CreatedBy: by,
	}
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var rq dbReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if strings.TrimSpace(rq.Name) == "" || strings.TrimSpace(rq.Address) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name and address are required")
		return
	}
	if !engineSupported(normalizeEngine(rq.Engine)) {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported engine (want postgres, mysql, mariadb, or sqlserver)")
		return
	}
	p := auth.MustPrincipal(r)
	db, err := h.d.Store.CreateDatabase(r.Context(), rq.toInput(p.UserID))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not register the database")
		return
	}
	h.audit(r, "database.create", db.ID, map[string]any{"name": db.Name, "address": db.Address})
	httpx.WriteJSON(w, http.StatusCreated, db)
}

func (h *handler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var rq dbReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !engineSupported(normalizeEngine(rq.Engine)) {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported engine (want postgres, mysql, mariadb, or sqlserver)")
		return
	}
	p := auth.MustPrincipal(r)
	db, err := h.d.Store.UpdateDatabase(r.Context(), id, rq.toInput(p.UserID))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update the database")
		return
	}
	h.audit(r, "database.update", db.ID, map[string]any{"name": db.Name})
	httpx.WriteJSON(w, http.StatusOK, db)
}

func (h *handler) del(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.DeleteDatabase(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete the database")
		return
	}
	h.audit(r, "database.delete", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func parseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return uuid.Nil, false
	}
	return id, true
}

func (h *handler) audit(r *http.Request, action string, id uuid.UUID, detail map[string]any) {
	p := auth.MustPrincipal(r)
	ev := models.AuditEvent{Action: action, TargetKind: "database", TargetID: id.String(), Detail: detail}
	if p != nil {
		ev.ActorID = &p.UserID
		ev.ActorName = p.Username
	}
	if r.RemoteAddr != "" {
		ev.IP = clientIP(r)
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), ev)
}

// clientIP extracts the request IP (best-effort; the reverse proxy sets X-Forwarded-For).
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
