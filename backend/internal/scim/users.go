package scim

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

const userSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

// scimName is the SCIM complex "name" attribute.
type scimName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// scimEmail is one entry of the SCIM multi-valued "emails" attribute.
type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

// scimUser is the SCIM 2.0 core User representation (the subset Fleet supports).
type scimUser struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Name        *scimName   `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []scimEmail `json:"emails,omitempty"`
	Active      bool        `json:"active"`
	Meta        *scimMeta   `json:"meta,omitempty"`
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location,omitempty"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
}

// primaryEmail returns the primary email (or the first) from a SCIM payload.
func (u scimUser) primaryEmail() string {
	for _, e := range u.Emails {
		if e.Primary && strings.TrimSpace(e.Value) != "" {
			return strings.TrimSpace(e.Value)
		}
	}
	for _, e := range u.Emails {
		if strings.TrimSpace(e.Value) != "" {
			return strings.TrimSpace(e.Value)
		}
	}
	return ""
}

func (u scimUser) displayName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if u.Name != nil {
		if u.Name.Formatted != "" {
			return u.Name.Formatted
		}
		full := strings.TrimSpace(u.Name.GivenName + " " + u.Name.FamilyName)
		if full != "" {
			return full
		}
	}
	return ""
}

// toSCIM maps a Fleet user to a SCIM User resource.
func (h *handler) toSCIM(u *models.User) scimUser {
	su := scimUser{
		Schemas:     []string{userSchema},
		ID:          u.ID.String(),
		UserName:    u.Username,
		DisplayName: u.DisplayName,
		Active:      !u.IsDisabled,
		Meta: &scimMeta{
			ResourceType: "User",
			Location:     h.baseURL() + "/Users/" + u.ID.String(),
			Created:      u.CreatedAt.UTC().Format(time.RFC3339),
			LastModified: u.UpdatedAt.UTC().Format(time.RFC3339),
		},
	}
	if u.Email != "" {
		su.Emails = []scimEmail{{Value: u.Email, Primary: true, Type: "work"}}
	}
	return su
}

// ---- Users collection ------------------------------------------------------

func (h *handler) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.d.Store.ListUsers(r.Context())
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "could not list users")
		return
	}
	// Support the one filter IdPs rely on: userName eq "value".
	if f := r.URL.Query().Get("filter"); f != "" {
		want, ok := parseUserNameEq(f)
		if !ok {
			writeSCIMError(w, http.StatusBadRequest, "unsupported filter (only 'userName eq' is supported)")
			return
		}
		filtered := users[:0]
		for _, u := range users {
			if strings.EqualFold(u.Username, want) {
				filtered = append(filtered, u)
			}
		}
		users = filtered
	}

	resources := make([]scimUser, 0, len(users))
	for i := range users {
		resources = append(resources, h.toSCIM(&users[i]))
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(resources),
		"startIndex":   1,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	})
}

func (h *handler) getUser(w http.ResponseWriter, r *http.Request) {
	u, ok := h.lookup(w, r)
	if !ok {
		return
	}
	writeSCIM(w, http.StatusOK, h.toSCIM(u))
}

func (h *handler) createUser(w http.ResponseWriter, r *http.Request) {
	var in scimUser
	if err := decodeSCIM(r, &in); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	in.UserName = strings.TrimSpace(in.UserName)
	if in.UserName == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName is required")
		return
	}
	// Idempotency: if the user already exists, return 409 as SCIM expects.
	if existing, err := h.d.Store.GetUserByUsername(r.Context(), in.UserName); err == nil && existing != nil {
		writeSCIMError(w, http.StatusConflict, "user already exists")
		return
	}

	c := h.config(r.Context())
	u, err := h.d.Store.CreateUser(r.Context(), store.CreateUserParams{
		Username:     in.UserName,
		Email:        in.primaryEmail(),
		DisplayName:  in.displayName(),
		PasswordHash: randPassword(), // unusable local password; auth is via SSO
		AuthSource:   c.authSource(),
	})
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "could not create user")
		return
	}
	_ = h.d.Store.AssignRoleByName(r.Context(), u.ID, c.defaultRole())
	// A create with active:false provisions an already-disabled account.
	if !in.Active {
		_ = h.d.Store.SetDisabled(r.Context(), u.ID, true)
		u.IsDisabled = true
	}
	h.provisionAudit(r, "scim.user_provision", u, map[string]any{"userName": u.Username})
	writeSCIM(w, http.StatusCreated, h.toSCIM(u))
}

// replaceUser (PUT) overwrites the mutable attributes of a user.
func (h *handler) replaceUser(w http.ResponseWriter, r *http.Request) {
	u, ok := h.lookup(w, r)
	if !ok {
		return
	}
	var in scimUser
	if err := decodeSCIM(r, &in); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.d.Store.UpdateUser(r.Context(), u.ID, store.UpdateUserParams{
		Email:       in.primaryEmail(),
		DisplayName: in.displayName(),
		IsDisabled:  !in.Active,
	}); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "could not update user")
		return
	}
	h.applyDeprovisionSideEffects(r.Context(), u.ID, !in.Active)
	h.provisionAudit(r, "scim.user_update", u, map[string]any{"active": in.Active})
	updated, _ := h.d.Store.GetUserByID(r.Context(), u.ID)
	if updated == nil {
		updated = u
	}
	writeSCIM(w, http.StatusOK, h.toSCIM(updated))
}

// scimPatchOp is a single SCIM PATCH operation.
type scimPatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

// patchUser applies a SCIM PatchOp. The essential case for deprovisioning is
// setting "active" to false, which most IdPs send here.
func (h *handler) patchUser(w http.ResponseWriter, r *http.Request) {
	u, ok := h.lookup(w, r)
	if !ok {
		return
	}
	var body struct {
		Schemas    []string      `json:"schemas"`
		Operations []scimPatchOp `json:"Operations"`
	}
	if err := decodeSCIM(r, &body); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email, display, disabled := u.Email, u.DisplayName, u.IsDisabled
	changedActive := false
	for _, op := range body.Operations {
		if strings.EqualFold(op.Op, "remove") && strings.EqualFold(op.Path, "active") {
			disabled, changedActive = true, true
			continue
		}
		path := strings.ToLower(strings.TrimSpace(op.Path))
		switch path {
		case "active":
			if b, ok := decodeBool(op.Value); ok {
				disabled, changedActive = !b, true
			}
		case "displayname":
			display = decodeString(op.Value)
		case "emails", "emails[type eq \"work\"].value":
			if s := decodeString(op.Value); s != "" {
				email = s
			}
		case "": // no path: value is an object of attributes to merge
			var obj scimUser
			if json.Unmarshal(op.Value, &obj) == nil {
				if obj.DisplayName != "" {
					display = obj.DisplayName
				}
				if e := obj.primaryEmail(); e != "" {
					email = e
				}
				// active is a real boolean in the merged object; detect its presence.
				var probe map[string]json.RawMessage
				if json.Unmarshal(op.Value, &probe) == nil {
					if raw, has := probe["active"]; has {
						if b, ok := decodeBool(raw); ok {
							disabled, changedActive = !b, true
						}
					}
				}
			}
		}
	}

	if err := h.d.Store.UpdateUser(r.Context(), u.ID, store.UpdateUserParams{
		Email: email, DisplayName: display, IsDisabled: disabled,
	}); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "could not update user")
		return
	}
	if changedActive {
		h.applyDeprovisionSideEffects(r.Context(), u.ID, disabled)
		h.provisionAudit(r, "scim.user_update", u, map[string]any{"active": !disabled})
	}
	updated, _ := h.d.Store.GetUserByID(r.Context(), u.ID)
	if updated == nil {
		updated = u
	}
	writeSCIM(w, http.StatusOK, h.toSCIM(updated))
}

// deleteUser deprovisions by disabling the account (SCIM DELETE). We disable
// rather than hard-delete so the audit trail and prior session records remain
// intact; a re-created SCIM user reactivates the same account.
func (h *handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	u, ok := h.lookup(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.SetDisabled(r.Context(), u.ID, true); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "could not deprovision user")
		return
	}
	h.applyDeprovisionSideEffects(r.Context(), u.ID, true)
	h.provisionAudit(r, "scim.user_deprovision", u, map[string]any{"userName": u.Username})
	w.WriteHeader(http.StatusNoContent)
}

// applyDeprovisionSideEffects tears down live access the moment an account is
// disabled: ends sessions and destroys their ephemeral SSH credentials.
func (h *handler) applyDeprovisionSideEffects(ctx context.Context, id uuid.UUID, disabled bool) {
	if disabled {
		h.d.Auth.DestroyUserSessions(ctx, id)
	}
}

func (h *handler) provisionAudit(r *http.Request, action string, u *models.User, detail map[string]any) {
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorName: "scim", Action: action, TargetKind: "user", TargetID: u.ID.String(), Detail: detail,
	})
}

// lookup resolves the {id} path param to a user, writing a SCIM 404 if absent.
func (h *handler) lookup(w http.ResponseWriter, r *http.Request) (*models.User, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return nil, false
	}
	u, err := h.d.Store.GetUserByID(r.Context(), id)
	if err != nil || u == nil {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return nil, false
	}
	return u, true
}

// ---- helpers ---------------------------------------------------------------

func decodeSCIM(r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v)
}

func decodeBool(raw json.RawMessage) (bool, bool) {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, true
	}
	// Tolerate string "true"/"false" some IdPs send.
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.EqualFold(strings.TrimSpace(s), "true"), true
	}
	return false, false
}

func decodeString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	return ""
}

// parseUserNameEq parses a SCIM `userName eq "value"` filter.
func parseUserNameEq(filter string) (string, bool) {
	f := strings.TrimSpace(filter)
	lower := strings.ToLower(f)
	if !strings.HasPrefix(lower, "username eq ") {
		return "", false
	}
	rest := strings.TrimSpace(f[len("userName eq "):])
	rest = strings.Trim(rest, "\"")
	if rest == "" {
		return "", false
	}
	return rest, true
}

func randPassword() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
