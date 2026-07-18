package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

// CreateAccessReview creates a campaign and snapshots the in-scope access grants
// (user↔group memberships and direct user↔host grants) into review items.
func (s *Store) CreateAccessReview(ctx context.Context, name, description string, scope models.ReviewScope, createdBy uuid.UUID, dueAt *time.Time) (*models.AccessReview, error) {
	scopeJSON, err := json.Marshal(scope)
	if err != nil {
		return nil, err
	}
	var id uuid.UUID
	err = s.tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO access_reviews (name, description, scope, created_by, due_at)
			VALUES ($1,$2,$3,$4,$5) RETURNING id`,
			name, description, scopeJSON, createdBy, dueAt).Scan(&id); err != nil {
			return err
		}
		return snapshotGrants(ctx, tx, id, scope)
	})
	if err != nil {
		return nil, err
	}
	return s.GetAccessReview(ctx, id)
}

// snapshotGrants inserts one review item per in-scope grant edge.
func snapshotGrants(ctx context.Context, tx pgx.Tx, reviewID uuid.UUID, scope models.ReviewScope) error {
	// group memberships
	gm := `SELECT user_id, group_id FROM user_groups`
	dh := `SELECT user_id, host_id FROM host_users`
	args := []any{}
	switch scope.Type {
	case "group":
		if scope.GroupID == nil {
			return fmt.Errorf("group scope requires groupId")
		}
		args = append(args, *scope.GroupID)
		gm += " WHERE group_id=$1"
		dh = "" // a group scope reviews only that group's memberships
	case "user":
		if len(scope.UserIDs) == 0 {
			return fmt.Errorf("user scope requires userIds")
		}
		args = append(args, scope.UserIDs)
		gm += " WHERE user_id = ANY($1)"
		dh += " WHERE user_id = ANY($1)"
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO access_review_items (review_id, subject_user_id, grant_kind, resource_kind, resource_id)
		SELECT $1, g.user_id, 'group_membership', 'group', g.group_id FROM (`+gm+`) g`,
		append([]any{reviewID}, args...)...); err != nil {
		return err
	}
	if dh != "" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO access_review_items (review_id, subject_user_id, grant_kind, resource_kind, resource_id)
			SELECT $1, d.user_id, 'direct_host', 'host', d.host_id FROM (`+dh+`) d`,
			append([]any{reviewID}, args...)...); err != nil {
			return err
		}
	}
	return nil
}

const accessReviewCols = `ar.id, ar.name, ar.description, ar.scope, ar.status, COALESCE(cu.username::text,''),
	ar.created_at, ar.due_at, ar.completed_at,
	(SELECT count(*) FROM access_review_items i WHERE i.review_id=ar.id),
	(SELECT count(*) FROM access_review_items i WHERE i.review_id=ar.id AND i.decision='pending'),
	(SELECT count(*) FROM access_review_items i WHERE i.review_id=ar.id AND i.decision='keep'),
	(SELECT count(*) FROM access_review_items i WHERE i.review_id=ar.id AND i.decision='revoke')`

func scanAccessReview(row interface{ Scan(...any) error }) (*models.AccessReview, error) {
	var r models.AccessReview
	var scope []byte
	if err := row.Scan(&r.ID, &r.Name, &r.Description, &scope, &r.Status, &r.CreatedBy,
		&r.CreatedAt, &r.DueAt, &r.CompletedAt, &r.Total, &r.Pending, &r.Kept, &r.Revoked); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(scope, &r.Scope)
	return &r, nil
}

// ListAccessReviews returns all campaigns, newest first.
func (s *Store) ListAccessReviews(ctx context.Context) ([]models.AccessReview, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+accessReviewCols+` FROM access_reviews ar
		 LEFT JOIN users cu ON cu.id=ar.created_by ORDER BY ar.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AccessReview{}
	for rows.Next() {
		r, err := scanAccessReview(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// GetAccessReview returns one campaign.
func (s *Store) GetAccessReview(ctx context.Context, id uuid.UUID) (*models.AccessReview, error) {
	r, err := scanAccessReview(s.pool.QueryRow(ctx,
		`SELECT `+accessReviewCols+` FROM access_reviews ar
		 LEFT JOIN users cu ON cu.id=ar.created_by WHERE ar.id=$1`, id))
	if err != nil {
		return nil, mapNotFound(err)
	}
	return r, nil
}

// AccessReviewItems returns a campaign's items with subject/resource names resolved.
func (s *Store) AccessReviewItems(ctx context.Context, reviewID uuid.UUID) ([]models.AccessReviewItem, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT i.id, COALESCE(u.username::text,''), COALESCE(u.is_service_account,false), i.grant_kind, i.resource_kind,
		       COALESCE(CASE WHEN i.resource_kind='group' THEN g.name ELSE h.hostname END, '(deleted)'),
		       i.decision, i.note, COALESCE(du.username::text,''), i.decided_at
		FROM access_review_items i
		LEFT JOIN users u ON u.id=i.subject_user_id
		LEFT JOIN groups g ON g.id=i.resource_id AND i.resource_kind='group'
		LEFT JOIN hosts h ON h.id=i.resource_id AND i.resource_kind='host'
		LEFT JOIN users du ON du.id=i.decided_by
		WHERE i.review_id=$1
		ORDER BY u.username, i.resource_kind`, reviewID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AccessReviewItem{}
	for rows.Next() {
		var it models.AccessReviewItem
		if err := rows.Scan(&it.ID, &it.SubjectUser, &it.SubjectIsSvc, &it.GrantKind, &it.ResourceKind,
			&it.ResourceName, &it.Decision, &it.Note, &it.DecidedBy, &it.DecidedAt); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// DecideReviewItem records a keep/revoke decision and, on revoke, removes the
// underlying grant. Idempotent per item.
func (s *Store) DecideReviewItem(ctx context.Context, reviewID, itemID, decidedBy uuid.UUID, decision, note string) error {
	if decision != "keep" && decision != "revoke" {
		return fmt.Errorf("invalid decision")
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		var subject, resource uuid.UUID
		var grantKind string
		if err := tx.QueryRow(ctx,
			`SELECT subject_user_id, grant_kind, resource_id FROM access_review_items
			 WHERE id=$1 AND review_id=$2`, itemID, reviewID).Scan(&subject, &grantKind, &resource); err != nil {
			return mapNotFound(err)
		}
		if decision == "revoke" {
			var q string
			switch grantKind {
			case "group_membership":
				q = `DELETE FROM user_groups WHERE user_id=$1 AND group_id=$2`
			case "direct_host":
				q = `DELETE FROM host_users WHERE user_id=$1 AND host_id=$2`
			default:
				return fmt.Errorf("unknown grant kind")
			}
			if _, err := tx.Exec(ctx, q, subject, resource); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx,
			`UPDATE access_review_items SET decision=$3, note=$4, decided_by=$5, decided_at=now()
			 WHERE id=$1 AND review_id=$2`, itemID, reviewID, decision, note, decidedBy)
		return err
	})
}

// CompleteAccessReview closes a campaign (its items become the evidence record).
func (s *Store) CompleteAccessReview(ctx context.Context, id, by uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE access_reviews SET status='completed', completed_at=now(), completed_by=$2
		 WHERE id=$1 AND status='open'`, id, by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ExportAccessReview returns a campaign's decisions as a report table (CSV evidence).
func (s *Store) ExportAccessReview(ctx context.Context, id uuid.UUID) (*ReportTable, error) {
	items, err := s.AccessReviewItems(ctx, id)
	if err != nil {
		return nil, err
	}
	t := &ReportTable{Columns: []string{
		"user", "service_account", "grant", "resource_type", "resource", "decision", "decided_by", "decided_at", "note"}}
	for _, it := range items {
		t.Rows = append(t.Rows, []string{it.SubjectUser, fmt.Sprint(it.SubjectIsSvc), it.GrantKind,
			it.ResourceKind, it.ResourceName, it.Decision, it.DecidedBy, rfcPtr(it.DecidedAt), it.Note})
	}
	return t, nil
}
