package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// CommandPolicy is one command-control rule.
type CommandPolicy struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	Pattern        string     `json:"pattern"`
	Action         string     `json:"action"`    // flag | block | approval
	ScopeKind      string     `json:"scopeKind"` // global | group
	ScopeGroupID   *uuid.UUID `json:"scopeGroupId,omitempty"`
	ScopeGroupName string     `json:"scopeGroupName,omitempty"`
	Enabled        bool       `json:"enabled"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

// ListCommandPolicies returns all rules (with group names) for management.
func (s *Store) ListCommandPolicies(ctx context.Context) ([]CommandPolicy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT p.id, p.name, p.pattern, p.action, p.scope_kind, p.scope_group_id,
		       COALESCE(g.name, ''), p.enabled, p.created_at, p.updated_at
		FROM command_policies p
		LEFT JOIN groups g ON g.id = p.scope_group_id
		ORDER BY p.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CommandPolicy{}
	for rows.Next() {
		var p CommandPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Pattern, &p.Action, &p.ScopeKind,
			&p.ScopeGroupID, &p.ScopeGroupName, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RulesForHost returns the enabled rules that apply to a host: every global rule
// plus rules scoped to a group the host belongs to. This is loaded once per
// terminal session, so enforcement adds no per-keystroke query.
func (s *Store) RulesForHost(ctx context.Context, hostID uuid.UUID) ([]CommandPolicy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, pattern, action, scope_kind, scope_group_id
		FROM command_policies
		WHERE enabled = true
		  AND (scope_kind = 'global'
		       OR scope_group_id IN (SELECT group_id FROM host_groups WHERE host_id = $1))
		ORDER BY created_at`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CommandPolicy{}
	for rows.Next() {
		var p CommandPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Pattern, &p.Action, &p.ScopeKind, &p.ScopeGroupID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CommandPolicyInput is the create/update payload.
type CommandPolicyInput struct {
	Name         string
	Pattern      string
	Action       string
	ScopeKind    string
	ScopeGroupID *uuid.UUID
	Enabled      bool
}

func (s *Store) CreateCommandPolicy(ctx context.Context, in CommandPolicyInput, createdBy uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO command_policies (name, pattern, action, scope_kind, scope_group_id, enabled, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		in.Name, in.Pattern, in.Action, in.ScopeKind, in.ScopeGroupID, in.Enabled, createdBy).Scan(&id)
	return id, err
}

func (s *Store) UpdateCommandPolicy(ctx context.Context, id uuid.UUID, in CommandPolicyInput) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE command_policies
		SET name=$2, pattern=$3, action=$4, scope_kind=$5, scope_group_id=$6, enabled=$7, updated_at=now()
		WHERE id=$1`,
		id, in.Name, in.Pattern, in.Action, in.ScopeKind, in.ScopeGroupID, in.Enabled)
	return err
}

func (s *Store) DeleteCommandPolicy(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM command_policies WHERE id=$1`, id)
	return err
}

// CommandApproval is a request-to-run (and, once approved, a time-boxed waiver).
type CommandApproval struct {
	ID          uuid.UUID  `json:"id"`
	PolicyID    *uuid.UUID `json:"policyId,omitempty"`
	UserID      uuid.UUID  `json:"userId"`
	Username    string     `json:"username"`
	HostID      *uuid.UUID `json:"hostId,omitempty"`
	Hostname    string     `json:"hostname"`
	Command     string     `json:"command"`
	Status      string     `json:"status"`
	RequestedAt time.Time  `json:"requestedAt"`
	DecidedAt   *time.Time `json:"decidedAt,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
}

// CreateCommandApproval records a pending approval request for a gated command.
func (s *Store) CreateCommandApproval(ctx context.Context, policyID *uuid.UUID, userID uuid.UUID, username string, hostID *uuid.UUID, hostname, command string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO command_approvals (policy_id, user_id, username, host_id, hostname, command)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		policyID, userID, username, hostID, hostname, command).Scan(&id)
	return id, err
}

// ListPendingCommandApprovals returns unresolved requests, newest first.
func (s *Store) ListPendingCommandApprovals(ctx context.Context) ([]CommandApproval, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, policy_id, user_id, username, host_id, hostname, command, status, requested_at, decided_at, expires_at
		FROM command_approvals WHERE status='pending' ORDER BY requested_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CommandApproval{}
	for rows.Next() {
		var a CommandApproval
		if err := rows.Scan(&a.ID, &a.PolicyID, &a.UserID, &a.Username, &a.HostID, &a.Hostname,
			&a.Command, &a.Status, &a.RequestedAt, &a.DecidedAt, &a.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DecideCommandApproval approves (granting a waiver valid for `ttl`) or denies a
// request. The approver must differ from the requester (separation of duties); a
// mismatch returns false without changing anything.
func (s *Store) DecideCommandApproval(ctx context.Context, id, approver uuid.UUID, approve bool, ttl time.Duration) (bool, error) {
	if !approve {
		ct, err := s.pool.Exec(ctx, `
			UPDATE command_approvals SET status='denied', approved_by=$2, decided_at=now()
			WHERE id=$1 AND status='pending'`, id, approver)
		return ct.RowsAffected() > 0, err
	}
	ct, err := s.pool.Exec(ctx, `
		UPDATE command_approvals
		SET status='approved', approved_by=$2, decided_at=now(), expires_at=now() + $3::interval
		WHERE id=$1 AND status='pending' AND user_id <> $2`,
		id, approver, ttl.String())
	return ct.RowsAffected() > 0, err
}

// ActiveWaiver reports whether the user currently holds an approved, unexpired
// waiver for a policy on a host — letting a previously-gated command run.
func (s *Store) ActiveWaiver(ctx context.Context, userID, hostID uuid.UUID, policyID *uuid.UUID) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM command_approvals
		WHERE status='approved' AND user_id=$1 AND host_id=$2
		  AND ($3::uuid IS NULL OR policy_id=$3)
		  AND expires_at > now()`, userID, hostID, policyID).Scan(&n)
	return n > 0, err
}
