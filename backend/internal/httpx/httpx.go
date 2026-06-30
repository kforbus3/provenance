// Package httpx holds small HTTP helpers shared by every API handler module:
// JSON responses, a standard error shape, request-body decoding, URL-id parsing,
// and audit-event recording. Previously each handler package carried its own
// byte-identical copies of these.
package httpx

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// WriteJSON writes v as a JSON response with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes a {"error": msg} JSON response with the given status.
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}

// Decode reads a JSON request body (capped at 1 MiB) into v, writing a 400 and
// returning false on failure.
func Decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

// ParseID parses the chi "id" URL param as a UUID, writing a 400 and returning
// false on failure.
func ParseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "bad id")
		return uuid.Nil, false
	}
	return id, true
}

// Audit appends an audit event, filling the actor from the request principal.
func Audit(r *http.Request, st *store.Store, ev models.AuditEvent) {
	if p := auth.MustPrincipal(r); p != nil {
		ev.ActorID = &p.UserID
		ev.ActorName = p.Username
	}
	_, _ = st.AppendAudit(r.Context(), ev)
}
