package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

// AppendAudit writes a tamper-evident audit event. Each event's hash chains to
// the previous event's hash: hash = SHA256(prev_hash || canonical(event)).
// The insert is serialized with a transaction + advisory lock so the chain stays
// strictly ordered even under concurrency.
func (s *Store) AppendAudit(ctx context.Context, e models.AuditEvent) (*models.AuditEvent, error) {
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}
	var out models.AuditEvent
	err := s.tx(ctx, func(tx pgx.Tx) error {
		// Serialize appends so prev_hash is read consistently.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('fleet_audit_chain'))`); err != nil {
			return err
		}
		var prev string
		err := tx.QueryRow(ctx, `SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&prev)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		detailJSON, _ := json.Marshal(e.Detail)
		// Canonical record bound into the hash (excludes server-assigned seq).
		canonical := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
			nilUUID(e.ActorID), e.ActorName, e.Action, e.TargetKind, e.TargetID, e.IP, string(detailJSON))
		sum := sha256.Sum256([]byte(prev + "|" + canonical))
		hash := hex.EncodeToString(sum[:])

		row := tx.QueryRow(ctx, `
			INSERT INTO audit_events
				(actor_id, actor_name, action, target_kind, target_id, ip, detail, prev_hash, hash)
			VALUES ($1, NULLIF($2,'')::citext, $3, $4, $5, NULLIF($6,'')::inet, $7, $8, $9)
			RETURNING seq, id, action, target_kind, target_id, prev_hash, hash, created_at`,
			e.ActorID, e.ActorName, e.Action, e.TargetKind, e.TargetID, e.IP, detailJSON, prev, hash)
		return row.Scan(&out.Seq, &out.ID, &out.Action, &out.TargetKind, &out.TargetID,
			&out.PrevHash, &out.Hash, &out.CreatedAt)
	})
	if err != nil {
		return nil, err
	}
	// Forward to syslog/SIEM (best-effort, off the request path). Merge the
	// input fields the INSERT didn't return so the forwarded event is complete.
	if s.auditSink != nil {
		out.ActorID, out.ActorName, out.IP, out.Detail = e.ActorID, e.ActorName, e.IP, e.Detail
		ev := out
		go s.auditSink(ev)
	}
	return &out, nil
}

// AuditFilter narrows an audit query.
type AuditFilter struct {
	Action string
	// ActorID matches an actor exactly; ActorName matches by (case-insensitive)
	// substring so the UI can filter by a name a human actually knows.
	ActorID   *uuid.UUID
	ActorName string
	// From/To bound created_at (inclusive); nil means unbounded on that end.
	From   *time.Time
	To     *time.Time
	Limit  int
	Offset int
}

// ListAudit returns audit events matching the filter, newest first.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]models.AuditEvent, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	rows, err := s.pool.Query(ctx, `
		SELECT seq, id, actor_id, COALESCE(actor_name,''), action, target_kind, target_id,
		       COALESCE(host(ip),''), detail, prev_hash, hash, created_at
		FROM audit_events
		WHERE ($1='' OR action=$1)
		  AND ($2::uuid IS NULL OR actor_id=$2)
		  AND ($3='' OR actor_name ILIKE '%'||$3||'%')
		  AND ($6::timestamptz IS NULL OR created_at >= $6)
		  AND ($7::timestamptz IS NULL OR created_at <= $7)
		ORDER BY seq DESC LIMIT $4 OFFSET $5`,
		f.Action, f.ActorID, f.ActorName, f.Limit, f.Offset, f.From, f.To)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AuditEvent
	for rows.Next() {
		var e models.AuditEvent
		if err := rows.Scan(&e.Seq, &e.ID, &e.ActorID, &e.ActorName, &e.Action, &e.TargetKind,
			&e.TargetID, &e.IP, &e.Detail, &e.PrevHash, &e.Hash, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DistinctAuditActions returns the set of action values present in the log,
// sorted, so the UI can offer them as a filter dropdown instead of free text.
func (s *Store) DistinctAuditActions(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT action FROM audit_events ORDER BY action`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// VerifyAuditChain recomputes the hash chain and reports the first seq where it
// breaks (0 = intact). This makes tampering with any historical row detectable.
func (s *Store) VerifyAuditChain(ctx context.Context) (intact bool, brokenAtSeq int64, err error) {
	rows, qerr := s.pool.Query(ctx, `
		SELECT seq, actor_id, COALESCE(actor_name,''), action, target_kind, target_id,
		       COALESCE(host(ip),''), detail, prev_hash, hash
		FROM audit_events ORDER BY seq ASC`)
	if qerr != nil {
		return false, 0, qerr
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var (
			seq                                      int64
			actorID                                  *uuid.UUID
			actorName, action, tk, tid, ip, prevH, h string
			detail                                   map[string]any
		)
		if err := rows.Scan(&seq, &actorID, &actorName, &action, &tk, &tid, &ip, &detail, &prevH, &h); err != nil {
			return false, 0, err
		}
		detailJSON, _ := json.Marshal(detail)
		canonical := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
			nilUUID(actorID), actorName, action, tk, tid, ip, string(detailJSON))
		sum := sha256.Sum256([]byte(prev + "|" + canonical))
		want := hex.EncodeToString(sum[:])
		if prevH != prev || h != want {
			return false, seq, nil
		}
		prev = h
	}
	return true, 0, rows.Err()
}

func nilUUID(u *uuid.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func jsonOrEmpty(m map[string]any) []byte {
	if m == nil {
		return []byte("{}")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return []byte("{}")
	}
	return b
}
