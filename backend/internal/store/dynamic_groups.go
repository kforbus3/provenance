package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

// SetGroupRule stores (or clears, when rule is nil/empty) a group's dynamic
// membership rule. Setting a rule makes the group rule-managed.
func (s *Store) SetGroupRule(ctx context.Context, groupID uuid.UUID, rule *models.GroupRule) error {
	if rule.Empty() {
		_, err := s.pool.Exec(ctx, `UPDATE groups SET rule=NULL WHERE id=$1`, groupID)
		return err
	}
	raw, err := json.Marshal(rule)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE groups SET rule=$2 WHERE id=$1`, groupID, raw)
	return err
}

// HostIDsMatchingRule returns the ids of hosts that satisfy the rule. An empty
// rule matches nothing (never "all hosts").
func (s *Store) HostIDsMatchingRule(ctx context.Context, rule *models.GroupRule) ([]uuid.UUID, error) {
	if rule.Empty() {
		return nil, nil
	}
	conds := []string{}
	args := []any{}
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if rule.Environment != "" {
		add("h.environment = $%d", rule.Environment)
	}
	if len(rule.TagsAll) > 0 {
		add("h.tags @> $%d", rule.TagsAll) // contains all
	}
	if len(rule.TagsAny) > 0 {
		add("h.tags && $%d", rule.TagsAny) // overlaps
	}
	if rule.OSContains != "" {
		add("i.os_name ILIKE '%%'||$%d||'%%'", rule.OSContains)
	}
	if rule.HostnameContains != "" {
		add("h.hostname ILIKE '%%'||$%d||'%%'", rule.HostnameContains)
	}
	where := conds[0]
	for _, c := range conds[1:] {
		where += " AND " + c
	}
	rows, err := s.pool.Query(ctx,
		`SELECT h.id FROM hosts h LEFT JOIN host_inventory i ON i.host_id=h.id WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// RecomputeGroup re-evaluates a dynamic group's rule and materializes the matched
// hosts into host_groups (replacing the prior set in one transaction). Returns the
// resulting member count. A no-op for a group with no rule.
func (s *Store) RecomputeGroup(ctx context.Context, groupID uuid.UUID) (int, error) {
	g, err := s.GetGroup(ctx, groupID)
	if err != nil {
		return 0, err
	}
	if g.Rule == nil {
		return 0, nil
	}
	ids, err := s.HostIDsMatchingRule(ctx, g.Rule)
	if err != nil {
		return 0, err
	}
	err = s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM host_groups WHERE group_id=$1`, groupID); err != nil {
			return err
		}
		for _, hid := range ids {
			if _, err := tx.Exec(ctx,
				`INSERT INTO host_groups (host_id, group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
				hid, groupID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(ids), nil
}

// ReconcileDynamicGroups recomputes every dynamic group. Run on a timer so host,
// tag, and inventory changes are reflected in membership without per-change hooks.
func (s *Store) ReconcileDynamicGroups(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT id FROM groups WHERE rule IS NOT NULL`)
	if err != nil {
		return err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, err := s.RecomputeGroup(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// GroupIsDynamic reports whether a group is rule-managed (so manual host
// membership edits must be refused).
func (s *Store) GroupIsDynamic(ctx context.Context, groupID uuid.UUID) (bool, error) {
	var has bool
	err := s.pool.QueryRow(ctx, `SELECT rule IS NOT NULL FROM groups WHERE id=$1`, groupID).Scan(&has)
	if err != nil {
		return false, mapNotFound(err)
	}
	return has, nil
}
