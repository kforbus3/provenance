package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

// approvalCols selects an approval request joined with the requester's username
// and the human-readable target name (host hostname or group name).
const approvalCols = `ar.id, ar.requester_id, COALESCE(u.username,''), ar.target_kind,
	ar.host_id, ar.group_id, COALESCE(h.hostname, g.name, ''),
	ar.reason, ar.ticket_ref, ar.requested_secs, ar.status,
	ar.decided_by, COALESCE(d.username,''), ar.decided_at, ar.decision_note, ar.granted_secs, ar.created_at`

const approvalFrom = `approval_requests ar
	JOIN users u ON u.id = ar.requester_id
	LEFT JOIN users d ON d.id = ar.decided_by
	LEFT JOIN hosts h ON h.id = ar.host_id
	LEFT JOIN groups g ON g.id = ar.group_id`

func scanApprovalRequest(row pgx.Row) (*models.ApprovalRequest, error) {
	var a models.ApprovalRequest
	err := row.Scan(&a.ID, &a.RequesterID, &a.Requester, &a.TargetKind, &a.HostID, &a.GroupID,
		&a.TargetName, &a.Reason, &a.TicketRef, &a.RequestedSecs, &a.Status,
		&a.DecidedBy, &a.DecidedByName, &a.DecidedAt, &a.DecisionNote, &a.GrantedSecs, &a.CreatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &a, nil
}

// ApprovalRequestInput carries fields for a new just-in-time access request.
type ApprovalRequestInput struct {
	RequesterID   uuid.UUID
	TargetKind    string
	HostID        *uuid.UUID
	GroupID       *uuid.UUID
	Reason        string
	TicketRef     string
	RequestedSecs int64
}

// CreateApprovalRequest inserts a pending approval request.
func (s *Store) CreateApprovalRequest(ctx context.Context, in ApprovalRequestInput) (*models.ApprovalRequest, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO approval_requests (requester_id, target_kind, host_id, group_id, reason, ticket_ref, requested_secs)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		in.RequesterID, in.TargetKind, in.HostID, in.GroupID, in.Reason, in.TicketRef, in.RequestedSecs).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetApprovalRequest(ctx, id)
}

// SetApprovalTicketRef attaches an ITSM ticket reference to an approval request
// (best-effort, set after an external ticket is opened).
func (s *Store) SetApprovalTicketRef(ctx context.Context, id uuid.UUID, ref string) error {
	_, err := s.pool.Exec(ctx, `UPDATE approval_requests SET ticket_ref=$2 WHERE id=$1`, id, ref)
	return err
}

// GetApprovalRequest loads a single approval request by id.
func (s *Store) GetApprovalRequest(ctx context.Context, id uuid.UUID) (*models.ApprovalRequest, error) {
	return scanApprovalRequest(s.pool.QueryRow(ctx, `SELECT `+approvalCols+` FROM `+approvalFrom+` WHERE ar.id=$1`, id))
}

// ListApprovalRequests returns approval requests, optionally filtered by status
// and/or requester. Pass an empty status and nil requester for no filtering.
func (s *Store) ListApprovalRequests(ctx context.Context, status string, requesterID *uuid.UUID) ([]models.ApprovalRequest, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+approvalCols+` FROM `+approvalFrom+`
		WHERE ($1='' OR ar.status=$1) AND ($2::uuid IS NULL OR ar.requester_id=$2)
		ORDER BY ar.created_at DESC`, status, requesterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ApprovalRequest
	for rows.Next() {
		a, err := scanApprovalRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// DecideApprovalRequest records an approve/deny decision on a pending request. On
// approval it atomically inserts a temporary_permissions grant whose lifetime is
// grantedSecs seconds from now.
func (s *Store) DecideApprovalRequest(ctx context.Context, id, decidedBy uuid.UUID, status, note string, grantedSecs int64) (*models.ApprovalRequest, error) {
	var a *models.ApprovalRequest
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var gs *int64
		if status == "approved" {
			gs = &grantedSecs
		}
		var (
			requesterID     uuid.UUID
			targetKind      string
			hostID, groupID *uuid.UUID
		)
		err := tx.QueryRow(ctx, `
			UPDATE approval_requests
			SET status=$2, decided_by=$3, decided_at=now(), decision_note=$4, granted_secs=$5
			WHERE id=$1 AND status='pending'
			RETURNING requester_id, target_kind, host_id, group_id`,
			id, status, decidedBy, note, gs).Scan(&requesterID, &targetKind, &hostID, &groupID)
		if err != nil {
			return mapNotFound(err)
		}
		if status == "approved" {
			if _, err := tx.Exec(ctx, `
				INSERT INTO temporary_permissions (request_id, user_id, host_id, group_id, expires_at)
				VALUES ($1,$2,$3,$4, now() + make_interval(secs => $5))`,
				id, requesterID, hostID, groupID, grantedSecs); err != nil {
				return err
			}
		}
		a, err = scanApprovalRequest(tx.QueryRow(ctx, `SELECT `+approvalCols+` FROM `+approvalFrom+` WHERE ar.id=$1`, id))
		return err
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

const tempPermCols = `id, request_id, user_id, host_id, group_id, granted_at, expires_at, revoked_at`

func scanTempPerm(row pgx.Row) (*models.TemporaryPermission, error) {
	var t models.TemporaryPermission
	err := row.Scan(&t.ID, &t.RequestID, &t.UserID, &t.HostID, &t.GroupID,
		&t.GrantedAt, &t.ExpiresAt, &t.RevokedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &t, nil
}

// ListTemporaryPermissions returns a user's currently active (not revoked, not
// expired) time-boxed grants, soonest to expire first.
func (s *Store) ListTemporaryPermissions(ctx context.Context, userID uuid.UUID) ([]models.TemporaryPermission, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+tempPermCols+` FROM temporary_permissions
		WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now()
		ORDER BY expires_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.TemporaryPermission
	for rows.Next() {
		t, err := scanTempPerm(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// ActiveGrant is a fleet-wide active temporary permission enriched with the
// grantee and target names, for the assistant's "who has elevated access right
// now" view.
type ActiveGrant struct {
	Username   string    `json:"username"`
	UserID     uuid.UUID `json:"userId"`
	TargetKind string    `json:"targetKind"` // host|group
	TargetName string    `json:"targetName"`
	GrantedAt  time.Time `json:"grantedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// ActiveTemporaryPermissions returns every currently active (not revoked, not
// expired) time-boxed grant across all users, soonest to expire first — the
// fleet-wide just-in-time access view.
func (s *Store) ActiveTemporaryPermissions(ctx context.Context) ([]ActiveGrant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT u.username, tp.user_id,
		       CASE WHEN tp.host_id IS NOT NULL THEN 'host' ELSE 'group' END,
		       COALESCE(h.hostname, g.name, ''),
		       tp.granted_at, tp.expires_at
		FROM temporary_permissions tp
		JOIN users u ON u.id = tp.user_id
		LEFT JOIN hosts h ON h.id = tp.host_id
		LEFT JOIN groups g ON g.id = tp.group_id
		WHERE tp.revoked_at IS NULL AND tp.expires_at > now()
		ORDER BY tp.expires_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActiveGrant{}
	for rows.Next() {
		var a ActiveGrant
		if err := rows.Scan(&a.Username, &a.UserID, &a.TargetKind, &a.TargetName, &a.GrantedAt, &a.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ExpireTemporaryPermissions revokes any grants whose lifetime has elapsed and
// marks the originating approval requests 'expired'. It returns the number of
// grants expired in this pass.
func (s *Store) ExpireTemporaryPermissions(ctx context.Context) ([]models.ExpiredGrant, error) {
	rows, err := s.pool.Query(ctx, `
		WITH expired AS (
			UPDATE temporary_permissions SET revoked_at=now()
			WHERE revoked_at IS NULL AND expires_at<=now()
			RETURNING request_id, user_id, host_id, group_id
		), bumped AS (
			UPDATE approval_requests SET status='expired'
			WHERE id IN (SELECT request_id FROM expired WHERE request_id IS NOT NULL)
			  AND status='approved'
			RETURNING id
		)
		SELECT e.request_id, e.user_id, COALESCE(u.username,''), COALESCE(u.email,''),
		       CASE WHEN e.host_id IS NOT NULL THEN 'host'
		            WHEN e.group_id IS NOT NULL THEN 'group' ELSE '' END,
		       COALESCE(h.hostname, g.name, '')
		FROM expired e
		JOIN users u ON u.id = e.user_id
		LEFT JOIN hosts h ON h.id = e.host_id
		LEFT JOIN groups g ON g.id = e.group_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ExpiredGrant
	for rows.Next() {
		var g models.ExpiredGrant
		if err := rows.Scan(&g.RequestID, &g.UserID, &g.Username, &g.UserEmail,
			&g.TargetKind, &g.TargetName); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ApprovalSummaries fetches approval requests by id (with the requester's username
// and the human-readable target name joined), for enriching approval-targeted
// audit events so old and new events both show who/what.
func (s *Store) ApprovalSummaries(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]models.ApprovalRequest, error) {
	out := map[uuid.UUID]models.ApprovalRequest{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT `+approvalCols+` FROM `+approvalFrom+` WHERE ar.id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		a, err := scanApprovalRequest(rows)
		if err != nil {
			return nil, err
		}
		out[a.ID] = *a
	}
	return out, rows.Err()
}
