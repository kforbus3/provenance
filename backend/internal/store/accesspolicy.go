package store

import (
	"context"

	"github.com/google/uuid"
)

// AccessPolicy is an ABAC rule that can deny a host connection based on host
// attributes, time of day, and subject roles. See internal/accesspolicy.
type AccessPolicy struct {
	ID            uuid.UUID  `json:"id"`
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	Enabled       bool       `json:"enabled"`
	Priority      int        `json:"priority"`
	Effect        string     `json:"effect"`
	Environments  []string   `json:"environments"`
	Tags          []string   `json:"tags"`
	Protocols     []string   `json:"protocols"`
	ExemptRoles   []string   `json:"exemptRoles"`
	ActiveDays    []int32    `json:"activeDays"`
	ActiveStart   int        `json:"activeStartMin"`
	ActiveEnd     int        `json:"activeEndMin"`
	DenyMessage   string     `json:"denyMessage"`
	CreatedBy     *uuid.UUID `json:"-"`
	CreatedByName string     `json:"createdBy"`
	CreatedAt     string     `json:"createdAt"`
	UpdatedAt     string     `json:"updatedAt"`
}

const accessPolicyCols = `p.id, p.name, p.description, p.enabled, p.priority, p.effect,
	p.environments, p.tags, p.protocols, p.exempt_roles, p.active_days, p.active_start_min,
	p.active_end_min, p.deny_message, p.created_by, COALESCE(u.username,''),
	p.created_at::text, p.updated_at::text`

func scanAccessPolicy(row interface{ Scan(...any) error }) (*AccessPolicy, error) {
	var p AccessPolicy
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &p.Priority, &p.Effect,
		&p.Environments, &p.Tags, &p.Protocols, &p.ExemptRoles, &p.ActiveDays, &p.ActiveStart,
		&p.ActiveEnd, &p.DenyMessage, &p.CreatedBy, &p.CreatedByName, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// ListAccessPolicies returns all policies, ordered for management (priority, then name).
func (s *Store) ListAccessPolicies(ctx context.Context) ([]AccessPolicy, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+accessPolicyCols+`
		FROM access_policies p LEFT JOIN users u ON u.id = p.created_by
		ORDER BY p.priority, p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessPolicy
	for rows.Next() {
		p, err := scanAccessPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// EnabledAccessPolicies returns only enabled policies, priority-ordered — the set the
// enforcer evaluates at connect time.
func (s *Store) EnabledAccessPolicies(ctx context.Context) ([]AccessPolicy, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+accessPolicyCols+`
		FROM access_policies p LEFT JOIN users u ON u.id = p.created_by
		WHERE p.enabled = true ORDER BY p.priority, p.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessPolicy
	for rows.Next() {
		p, err := scanAccessPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// AccessPolicyInput is the payload to create or update a policy.
type AccessPolicyInput struct {
	Name         string
	Description  string
	Enabled      bool
	Priority     int
	Environments []string
	Tags         []string
	Protocols    []string
	ExemptRoles  []string
	ActiveDays   []int32
	ActiveStart  int
	ActiveEnd    int
	DenyMessage  string
	CreatedBy    uuid.UUID
}

func (s *Store) CreateAccessPolicy(ctx context.Context, in AccessPolicyInput) (*AccessPolicy, error) {
	var id uuid.UUID
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO access_policies
		  (name, description, enabled, priority, environments, tags, protocols, exempt_roles,
		   active_days, active_start_min, active_end_min, deny_message, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`,
		in.Name, in.Description, in.Enabled, in.Priority, arr(in.Environments), arr(in.Tags),
		arr(in.Protocols), arr(in.ExemptRoles), iarr(in.ActiveDays), in.ActiveStart, in.ActiveEnd,
		in.DenyMessage, in.CreatedBy).Scan(&id); err != nil {
		return nil, err
	}
	return s.GetAccessPolicy(ctx, id)
}

func (s *Store) UpdateAccessPolicy(ctx context.Context, id uuid.UUID, in AccessPolicyInput) (*AccessPolicy, error) {
	if _, err := s.pool.Exec(ctx, `
		UPDATE access_policies SET name=$2, description=$3, enabled=$4, priority=$5, environments=$6,
		  tags=$7, protocols=$8, exempt_roles=$9, active_days=$10, active_start_min=$11,
		  active_end_min=$12, deny_message=$13, updated_at=now()
		WHERE id=$1`,
		id, in.Name, in.Description, in.Enabled, in.Priority, arr(in.Environments), arr(in.Tags),
		arr(in.Protocols), arr(in.ExemptRoles), iarr(in.ActiveDays), in.ActiveStart, in.ActiveEnd,
		in.DenyMessage); err != nil {
		return nil, err
	}
	return s.GetAccessPolicy(ctx, id)
}

func (s *Store) GetAccessPolicy(ctx context.Context, id uuid.UUID) (*AccessPolicy, error) {
	return scanAccessPolicy(s.pool.QueryRow(ctx, `SELECT `+accessPolicyCols+`
		FROM access_policies p LEFT JOIN users u ON u.id = p.created_by WHERE p.id=$1`, id))
}

func (s *Store) DeleteAccessPolicy(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM access_policies WHERE id=$1`, id)
	return err
}

// (UserRoleNames is defined in rbac.go and reused here for ABAC exemption matching.)

// arr/iarr normalize a possibly-nil slice to a non-nil empty slice so the NOT NULL
// array columns never receive NULL.
func arr(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func iarr(s []int32) []int32 {
	if s == nil {
		return []int32{}
	}
	return s
}
