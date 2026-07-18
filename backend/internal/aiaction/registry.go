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
	"sort"
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
	KindVulnScan    = "scan.vulnerability"
	KindTagHost     = "host.tag"
	KindDisableUser = "user.disable"
	KindDeleteHost  = "host.delete"
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

	// Runner hooks wired from the server so this package imports neither the
	// vulnscan service nor the auth service.
	runVulnScan         func(scanID uuid.UUID, h *models.Host)
	destroyUserSessions func(ctx context.Context, userID uuid.UUID)
	// notifyApproval, if set, alerts approvers that a guarded action is pending.
	notifyApproval func(ctx context.Context, action *models.AssistantAction)
}

// New builds the registry with its runner hooks and registers the actions.
func New(st *store.Store, log *slog.Logger,
	runVulnScan func(uuid.UUID, *models.Host),
	destroyUserSessions func(context.Context, uuid.UUID),
	notifyApproval func(context.Context, *models.AssistantAction),
) *Registry {
	r := &Registry{
		store: st, log: log, defs: map[string]ActionDef{},
		runVulnScan: runVulnScan, destroyUserSessions: destroyUserSessions, notifyApproval: notifyApproval,
	}
	// Safe actions (executed on the user's own confirm).
	r.register(vulnScanAction())
	r.register(tagHostAction())
	// Destructive actions (require a second person to approve).
	r.register(disableUserAction())
	r.register(deleteHostAction())
	return r
}

func (r *Registry) register(d ActionDef) { r.defs[d.Kind] = d }

// Def returns a registered action definition.
func (r *Registry) Def(kind string) (ActionDef, bool) {
	d, ok := r.defs[kind]
	return d, ok
}

const policySettingKey = "assistant_actions"

// Policy is the admin-configurable action policy. RequireApprovalForAll forces
// even safe actions through a second-person approval; DisabledKinds turns off
// specific actions entirely.
type Policy struct {
	RequireApprovalForAll bool     `json:"requireApprovalForAll"`
	DisabledKinds         []string `json:"disabledKinds"`
}

func (p Policy) disabled(kind string) bool {
	for _, k := range p.DisabledKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Policy returns the current action policy from settings.
func (r *Registry) Policy(ctx context.Context) Policy {
	var p Policy
	if raw, err := r.store.GetSetting(ctx, policySettingKey); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &p)
	}
	return p
}

// SavePolicy persists the action policy.
func (r *Registry) SavePolicy(ctx context.Context, p Policy) error {
	return r.store.SetSetting(ctx, policySettingKey, p)
}

// ActionInfo describes a registered action for the policy UI.
type ActionInfo struct {
	Kind       string `json:"kind"`
	Risk       string `json:"risk"`
	Permission string `json:"permission"`
}

// Kinds returns the registered actions (sorted) so admins can see and configure them.
func (r *Registry) Kinds() []ActionInfo {
	out := make([]ActionInfo, 0, len(r.defs))
	for _, d := range r.defs {
		out = append(out, ActionInfo{Kind: d.Kind, Risk: d.Risk, Permission: d.Permission})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Kind < out[b].Kind })
	return out
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
	// ErrRequiresApproval is returned when a guarded action is confirmed via the
	// direct execute path instead of being routed through approval.
	ErrRequiresApproval = errors.New("this action requires approval")
	// ErrSelfApproval enforces separation of duties: the requester may not approve.
	ErrSelfApproval = errors.New("you cannot approve your own requested action")
)

// Propose validates + authorizes an action and stages it as a pending proposal.
// It never mutates target state.
func (r *Registry) Propose(ctx context.Context, actor Actor, kind string, raw json.RawMessage) (*models.AssistantAction, error) {
	def, ok := r.defs[kind]
	if !ok {
		return nil, fmt.Errorf("unknown action %q", kind)
	}
	pol := r.Policy(ctx)
	if pol.disabled(kind) {
		return nil, errors.New("this action is disabled by policy")
	}
	if !actor.Can(def.Permission) {
		return nil, &PermError{Permission: def.Permission}
	}
	params, preview, err := def.Prepare(ctx, r, actor, raw)
	if err != nil {
		return nil, err
	}
	// The stored risk is authoritative for the approval decision — policy can
	// elevate a safe action to require approval; it is captured at propose time.
	risk := def.Risk
	if pol.RequireApprovalForAll && risk == RiskSafe {
		risk = RiskGuarded
	}
	return r.store.CreateAssistantAction(ctx, store.AssistantActionInput{
		UserID: actor.UserID, Kind: kind, Params: params, Preview: preview,
		Risk: risk, Permission: def.Permission, TTL: 15 * time.Minute,
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
	// Guarded/destructive actions must not run on the requester's confirm alone —
	// they go through RequestApproval → Approve. The stored risk (which policy may
	// have elevated) is authoritative.
	if action.Risk != RiskSafe {
		return nil, ErrRequiresApproval
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

// reload re-reads an action after a status change, falling back to the prior copy.
func (r *Registry) reload(ctx context.Context, id uuid.UUID, fallback *models.AssistantAction) *models.AssistantAction {
	if a, err := r.store.GetAssistantAction(ctx, id); err == nil {
		return a
	}
	return fallback
}

// proposerActor reconstructs the action's requester as an Actor from their CURRENT
// account + permissions, so an approval re-authorizes against who they are now.
func (r *Registry) proposerActor(ctx context.Context, userID uuid.UUID) (Actor, *models.User, error) {
	u, err := r.store.GetUserByID(ctx, userID)
	if err != nil {
		return Actor{}, nil, err
	}
	perms, _ := r.store.UserPermissions(ctx, userID)
	return Actor{
		UserID: u.ID, Username: u.Username, IsSuper: u.IsSuperAdmin,
		Can: func(p string) bool { return u.IsSuperAdmin || perms["Admin.All"] || perms[p] },
	}, u, nil
}

// RequestApproval routes a proposed guarded action to a second person: it moves the
// proposal to pending_approval (owner only) and notifies approvers. The action does
// NOT run here.
func (r *Registry) RequestApproval(ctx context.Context, actor Actor, id uuid.UUID) (*models.AssistantAction, error) {
	action, err := r.store.GetAssistantAction(ctx, id)
	if err != nil || action.UserID != actor.UserID {
		return nil, ErrNotFound
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
	if action.Risk == RiskSafe {
		return nil, errors.New("this action does not require approval")
	}
	if !actor.Can(def.Permission) {
		return nil, &PermError{Permission: def.Permission}
	}
	ok, err = r.store.RequestAssistantActionApproval(ctx, id, 24*time.Hour)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotPending
	}
	updated := r.reload(ctx, id, action)
	if r.notifyApproval != nil {
		r.notifyApproval(ctx, updated)
	}
	uid := actor.UserID
	_, _ = r.store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &uid, ActorName: actor.Username,
		Action: "assistant.action.approval_requested", TargetKind: "assistant_action", TargetID: id.String(),
		Detail: map[string]any{"kind": action.Kind, "preview": action.Preview},
	})
	return updated, nil
}

// ListApprovals returns actions awaiting approval (for approvers).
func (r *Registry) ListApprovals(ctx context.Context) ([]models.AssistantAction, error) {
	return r.store.ListPendingApprovalActions(ctx, 100)
}

// Approve executes a pending action on the requester's behalf, after enforcing
// separation of duties and RE-AUTHORIZING the requester's CURRENT permission and
// account state (an approval is not a bypass — if the requester lost access or was
// disabled since proposing, it fails rather than runs).
func (r *Registry) Approve(ctx context.Context, approver Actor, id uuid.UUID) (*models.AssistantAction, error) {
	action, err := r.store.GetAssistantAction(ctx, id)
	if err != nil {
		return nil, ErrNotFound
	}
	if action.Status != "pending_approval" {
		return nil, ErrNotPending
	}
	if approver.UserID == action.UserID {
		return nil, ErrSelfApproval
	}
	if time.Now().After(action.ExpiresAt) {
		return nil, ErrExpired // the reaper transitions it to expired
	}
	def, ok := r.defs[action.Kind]
	if !ok {
		return nil, fmt.Errorf("unknown action %q", action.Kind)
	}
	pActor, pUser, perr := r.proposerActor(ctx, action.UserID)
	switch {
	case perr != nil:
		_, _ = r.store.SetAssistantActionDecision(ctx, id, "pending_approval", "failed", approver.UserID, "requester account not found")
		return r.reload(ctx, id, action), errors.New("requester account not found")
	case pUser.IsDisabled:
		_, _ = r.store.SetAssistantActionDecision(ctx, id, "pending_approval", "failed", approver.UserID, "requester account is disabled")
		return r.reload(ctx, id, action), errors.New("requester account is disabled")
	case !pActor.Can(def.Permission):
		_, _ = r.store.SetAssistantActionDecision(ctx, id, "pending_approval", "failed", approver.UserID, "requester no longer holds "+def.Permission)
		return r.reload(ctx, id, action), errors.New("requester no longer holds the required permission")
	}
	// Claim: pending_approval → executed, recording the approver.
	claimed, err := r.store.SetAssistantActionDecision(ctx, id, "pending_approval", "executed", approver.UserID, "")
	if err != nil {
		return nil, err
	}
	if !claimed {
		return nil, ErrNotPending
	}
	outcome, execErr := def.Execute(ctx, r, pActor, action.Params)
	status := "executed"
	if execErr != nil {
		status, outcome = "failed", execErr.Error()
		r.log.Warn("assistant action failed after approval", "kind", action.Kind, "id", id, "err", execErr)
	}
	_ = r.store.FinishAssistantAction(ctx, id, status, clip(outcome, 1000))
	apUID := approver.UserID
	_, _ = r.store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &apUID, ActorName: approver.Username,
		Action: "assistant.action." + status, TargetKind: "assistant_action", TargetID: id.String(),
		Detail: map[string]any{"kind": action.Kind, "preview": action.Preview, "requestedBy": pActor.Username, "approved": true, "outcome": clip(outcome, 300)},
	})
	return r.reload(ctx, id, action), execErr
}

// Deny rejects a pending action (approver only, not the requester).
func (r *Registry) Deny(ctx context.Context, approver Actor, id uuid.UUID, note string) (*models.AssistantAction, error) {
	action, err := r.store.GetAssistantAction(ctx, id)
	if err != nil {
		return nil, ErrNotFound
	}
	if action.Status != "pending_approval" {
		return nil, ErrNotPending
	}
	if approver.UserID == action.UserID {
		return nil, ErrSelfApproval
	}
	ok, err := r.store.SetAssistantActionDecision(ctx, id, "pending_approval", "denied", approver.UserID, clip(note, 500))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotPending
	}
	apUID := approver.UserID
	_, _ = r.store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &apUID, ActorName: approver.Username,
		Action: "assistant.action.denied", TargetKind: "assistant_action", TargetID: id.String(),
		Detail: map[string]any{"kind": action.Kind, "preview": action.Preview, "note": clip(note, 200)},
	})
	return r.reload(ctx, id, action), nil
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
