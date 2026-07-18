package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

// AssistantActionInput is the payload for staging a proposed assistant action.
type AssistantActionInput struct {
	UserID     uuid.UUID
	Kind       string
	Params     json.RawMessage
	Preview    string
	Risk       string
	Permission string
	TTL        time.Duration
}

const assistantActionCols = `id, user_id, kind, params, preview, risk, permission, status, outcome, created_at, expires_at, executed_at`

func scanAssistantAction(row interface{ Scan(...any) error }) (*models.AssistantAction, error) {
	var a models.AssistantAction
	if err := row.Scan(&a.ID, &a.UserID, &a.Kind, &a.Params, &a.Preview, &a.Risk, &a.Permission,
		&a.Status, &a.Outcome, &a.CreatedAt, &a.ExpiresAt, &a.ExecutedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

// CreateAssistantAction stages a proposed action, returning the persisted record.
func (s *Store) CreateAssistantAction(ctx context.Context, in AssistantActionInput) (*models.AssistantAction, error) {
	params := in.Params
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	risk := in.Risk
	if risk == "" {
		risk = "safe"
	}
	ttl := in.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO assistant_actions (user_id, kind, params, preview, risk, permission, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6, now() + $7::interval)
		RETURNING `+assistantActionCols,
		in.UserID, in.Kind, params, in.Preview, risk, in.Permission, ttl.String())
	return scanAssistantAction(row)
}

// GetAssistantAction returns one proposal by id.
func (s *Store) GetAssistantAction(ctx context.Context, id uuid.UUID) (*models.AssistantAction, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+assistantActionCols+` FROM assistant_actions WHERE id=$1`, id)
	return scanAssistantAction(row)
}

// ListAssistantActions returns a user's recent assistant actions, newest first.
func (s *Store) ListAssistantActions(ctx context.Context, userID uuid.UUID, limit int) ([]models.AssistantAction, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `SELECT `+assistantActionCols+`
		FROM assistant_actions WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AssistantAction
	for rows.Next() {
		a, err := scanAssistantAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// SetAssistantActionStatus transitions a proposal, stamping executed_at when it
// moves to executed. It only advances rows still in 'proposed' state, so a
// concurrent execute/cancel/expire cannot double-apply (returns false if no row
// changed).
func (s *Store) SetAssistantActionStatus(ctx context.Context, id uuid.UUID, status, outcome string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE assistant_actions
		SET status=$2, outcome=$3, executed_at = CASE WHEN $2='executed' THEN now() ELSE executed_at END
		WHERE id=$1 AND status='proposed'`, id, status, outcome)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// FinishAssistantAction records the terminal status + outcome of an action the
// caller has already claimed (via SetAssistantActionStatus to 'executed'). Unlike
// SetAssistantActionStatus it is not guarded on 'proposed', so the executor can
// downgrade a claimed row to 'failed' and attach the outcome.
func (s *Store) FinishAssistantAction(ctx context.Context, id uuid.UUID, status, outcome string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE assistant_actions SET status=$2, outcome=$3, executed_at=COALESCE(executed_at, now())
		WHERE id=$1`, id, status, outcome)
	return err
}

// ExpireAssistantActions marks proposals past their expiry as expired.
func (s *Store) ExpireAssistantActions(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE assistant_actions SET status='expired'
		WHERE status='proposed' AND expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
