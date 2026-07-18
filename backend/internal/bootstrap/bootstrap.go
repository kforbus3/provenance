// Package bootstrap implements the one-time first-run wizard that creates the
// initial Super Administrator. Once any user exists the wizard is permanently
// closed; it can only be reopened via an offline recovery process (fleetctl).
package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// Handler serves bootstrap endpoints.
type Handler struct {
	store *store.Store
	cfg   *config.Config
}

// NewHandler constructs the bootstrap Handler.
func NewHandler(st *store.Store, cfg *config.Config) *Handler {
	return &Handler{store: st, cfg: cfg}
}

// Mount attaches bootstrap routes (intentionally unauthenticated — they are
// self-gating on the absence of any user account).
func (h *Handler) Mount(r chi.Router) {
	r.Get("/bootstrap/status", h.status)
	r.Post("/bootstrap/init", h.init)
}

// available reports whether bootstrapping is currently permitted.
func (h *Handler) available(r *http.Request) (bool, error) {
	if !h.cfg.AllowBootstrap {
		return false, nil
	}
	n, err := h.store.CountUsers(r.Context())
	if err != nil {
		return false, err
	}
	return n == 0, nil
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	ok, err := h.available(r)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "status check failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"bootstrapAvailable": ok})
}

type initReq struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Password    string `json:"password"`
}

func (h *Handler) init(w http.ResponseWriter, r *http.Request) {
	ok, err := h.available(r)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "status check failed")
		return
	}
	if !ok {
		httpx.WriteError(w, http.StatusConflict, "bootstrap is no longer available")
		return
	}
	var req initReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" {
		httpx.WriteError(w, http.StatusBadRequest, "username is required")
		return
	}
	if err := auth.DefaultPolicy.Validate(req.Password); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "hash failed")
		return
	}
	u, err := h.store.CreateInitialSuperAdmin(r.Context(), store.CreateUserParams{
		Username: req.Username, Email: req.Email, DisplayName: req.DisplayName,
		PasswordHash: hash,
	})
	if errors.Is(err, store.ErrUsersExist) {
		// Another concurrent bootstrap won the race and created the first admin.
		httpx.WriteError(w, http.StatusConflict, "bootstrap is no longer available")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create administrator")
		return
	}
	// Grant the built-in Super Administrator role for completeness.
	_ = h.store.AssignRoleByName(r.Context(), u.ID, "Super Administrator")
	_, _ = h.store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &u.ID, ActorName: u.Username, Action: "bootstrap.init",
		TargetKind: "user", TargetID: u.ID.String(),
		Detail: map[string]any{"username": u.Username},
	})
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"status": "bootstrapped", "user": u})
}
