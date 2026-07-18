// Package aiaction implements the AI assistant's action registry and the
// propose→confirm→execute lifecycle. The assistant may only PROPOSE an action;
// it is persisted as a pending proposal, the user explicitly confirms it, and the
// registry executes it — re-authorizing against the live caller at execution time.
// This is the security boundary that keeps the assistant (and any prompt injection
// reaching it) from ever taking an action a human did not confirm.
package aiaction

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// Risk tiers. Phase 2 ships only "safe" actions (reversible, low-impact, executed
// on the user's own authority). Guarded/destructive actions route through an
// approval in a later phase.
const (
	RiskSafe        = "safe"
	RiskGuarded     = "guarded"
	RiskDestructive = "destructive"
)

// Action kinds.
const (
	KindVulnScan = "scan.vulnerability"
	KindTagHost  = "host.tag"
)

// Actor is the authenticated caller on whose behalf an action is proposed or
// executed. Can mirrors auth.Principal.Has, so both a propose-time snapshot and
// the live execute-time principal satisfy it without a type dependency.
type Actor struct {
	UserID   uuid.UUID
	Username string
	IsSuper  bool
	Can      func(permission string) bool
}

// ActionDef defines one registered action kind.
type ActionDef struct {
	Kind       string
	Permission string // permission the caller must hold to propose AND execute
	Risk       string
	// Prepare validates the raw model-supplied args, authorizes resource access,
	// and returns the resolved params + a human-readable preview. It must not
	// mutate anything.
	Prepare func(ctx context.Context, r *Registry, actor Actor, raw json.RawMessage) (params json.RawMessage, preview string, err error)
	// Execute performs the action for the (re-authorized) actor.
	Execute func(ctx context.Context, r *Registry, actor Actor, params json.RawMessage) (outcome string, err error)
}

// Registry holds the action definitions and the dependencies actions need.
type Registry struct {
	store *store.Store
	log   *slog.Logger
	defs  map[string]ActionDef

	// runVulnScan starts a vulnerability scan asynchronously (wired from the
	// server so this package doesn't import the vulnscan service).
	runVulnScan func(scanID uuid.UUID, h *models.Host)
}

// New builds the registry with its runner hooks and registers the safe actions.
func New(st *store.Store, log *slog.Logger, runVulnScan func(uuid.UUID, *models.Host)) *Registry {
	r := &Registry{store: st, log: log, runVulnScan: runVulnScan, defs: map[string]ActionDef{}}
	r.register(vulnScanAction())
	r.register(tagHostAction())
	return r
}

func (r *Registry) register(d ActionDef) { r.defs[d.Kind] = d }

// Def returns a registered action definition.
func (r *Registry) Def(kind string) (ActionDef, bool) {
	d, ok := r.defs[kind]
	return d, ok
}

// PermError signals the caller lacks the permission an action requires.
type PermError struct{ Permission string }

func (e *PermError) Error() string { return "missing permission " + e.Permission }

var (
	// ErrNotFound is returned for a missing proposal or one owned by another user.
	ErrNotFound = errors.New("action not found")
	// ErrExpired is returned when a proposal is confirmed after its window closed.
	ErrExpired = errors.New("this proposal has expired; ask again")
	// ErrNotPending is returned when a proposal was already executed/cancelled.
	ErrNotPending = errors.New("this proposal is no longer pending")
)

// Propose validates + authorizes an action and stages it as a pending proposal.
// It never mutates target state.
func (r *Registry) Propose(ctx context.Context, actor Actor, kind string, raw json.RawMessage) (*models.AssistantAction, error) {
	def, ok := r.defs[kind]
	if !ok {
		return nil, fmt.Errorf("unknown action %q", kind)
	}
	if !actor.Can(def.Permission) {
		return nil, &PermError{Permission: def.Permission}
	}
	params, preview, err := def.Prepare(ctx, r, actor, raw)
	if err != nil {
		return nil, err
	}
	return r.store.CreateAssistantAction(ctx, store.AssistantActionInput{
		UserID: actor.UserID, Kind: kind, Params: params, Preview: preview,
		Risk: def.Risk, Permission: def.Permission, TTL: 15 * time.Minute,
	})
}

// Execute runs a confirmed proposal. It enforces ownership, pending state, expiry,
// and RE-AUTHORIZES the live caller against the action's permission before running
// (permissions may have changed since the proposal was made). Execution is claimed
// atomically so a double confirm cannot run the action twice.
func (r *Registry) Execute(ctx context.Context, actor Actor, id uuid.UUID) (*models.AssistantAction, error) {
	action, err := r.store.GetAssistantAction(ctx, id)
	if err != nil || action.UserID != actor.UserID {
		return nil, ErrNotFound // don't leak another user's proposal
	}
	if action.Status != "proposed" {
		return nil, ErrNotPending
	}
	if time.Now().After(action.ExpiresAt) {
		_, _ = r.store.SetAssistantActionStatus(ctx, id, "expired", "")
		return nil, ErrExpired
	}
	def, ok := r.defs[action.Kind]
	if !ok {
		return nil, fmt.Errorf("unknown action %q", action.Kind)
	}
	// Re-authorization at execution time — the real security gate.
	if !actor.Can(def.Permission) {
		return nil, &PermError{Permission: def.Permission}
	}
	// Claim the row (proposed → executed) so a concurrent confirm can't double-run.
	claimed, err := r.store.SetAssistantActionStatus(ctx, id, "executed", "")
	if err != nil {
		return nil, err
	}
	if !claimed {
		return nil, ErrNotPending
	}

	outcome, execErr := def.Execute(ctx, r, actor, action.Params)
	status := "executed"
	if execErr != nil {
		status, outcome = "failed", execErr.Error()
		r.log.Warn("assistant action failed", "kind", action.Kind, "id", id, "err", execErr)
	}
	_ = r.store.FinishAssistantAction(ctx, id, status, clip(outcome, 1000))

	uid := actor.UserID
	_, _ = r.store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &uid, ActorName: actor.Username,
		Action: "assistant.action." + status, TargetKind: "assistant_action", TargetID: id.String(),
		Detail: map[string]any{"kind": action.Kind, "preview": action.Preview, "outcome": clip(outcome, 300)},
	})

	updated, gerr := r.store.GetAssistantAction(ctx, id)
	if gerr != nil {
		updated = action
	}
	return updated, execErr
}

// Cancel dismisses a pending proposal (owner only).
func (r *Registry) Cancel(ctx context.Context, actor Actor, id uuid.UUID) error {
	action, err := r.store.GetAssistantAction(ctx, id)
	if err != nil || action.UserID != actor.UserID {
		return ErrNotFound
	}
	ok, err := r.store.SetAssistantActionStatus(ctx, id, "cancelled", "")
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotPending
	}
	return nil
}

// List returns the caller's recent assistant actions (history).
func (r *Registry) List(ctx context.Context, actor Actor, limit int) ([]models.AssistantAction, error) {
	return r.store.ListAssistantActions(ctx, actor.UserID, limit)
}

// Expire voids proposals past their window; called from a background loop.
func (r *Registry) Expire(ctx context.Context) (int64, error) {
	return r.store.ExpireAssistantActions(ctx)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
