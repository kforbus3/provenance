package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kforbus3/Moorgate/backend/internal/models"
	"github.com/kforbus3/Moorgate/backend/internal/tenant"
)

// providerTenantID is the seeded Provider tenant; audit events for background/system
// work (no request tenant) belong to it. Kept as a local literal so the store layer
// need not import auth (which imports store).
const providerTenantID = "00000000-0000-0000-0000-000000000001"

// Audit hash-chain algorithms, recorded per row in audit_events.hash_alg so a mixed
// chain (pre- and post-upgrade rows) stays verifiable.
//
//	auditAlgLegacy: keyless SHA-256 over the OLD canonical record. This is what every
//	                row written before 0076 used; it EXCLUDES seq, created_at and
//	                tenant_id. Verified WITHOUT a key so historical chains still pass.
//	auditAlgHMAC:   HMAC-SHA256(AuditHMACKey) over the NEW canonical record, which
//	                additionally binds seq, created_at and tenant_id. Written for every
//	                new row once a key is configured, and tamper-evident against a party
//	                with DB write access (they cannot forge the MAC without the key).
const (
	auditAlgLegacy int16 = 1
	auditAlgHMAC   int16 = 2
)

// auditHMACKey holds the server-wide key that keys the audit chain. It is process
// state (a *Store field would be cleaner, but the Store struct and its constructor
// live in another agent's file); there is one Store per process, so a package-level
// key set once at startup is equivalent. Guarded because appends run concurrently.
var (
	auditHMACKeyMu   sync.RWMutex
	auditHMACKey     []byte
	auditKeylessWarn sync.Once
)

// SetAuditHMACKey installs the key that keys the audit hash chain (HMAC-SHA256).
// Call once at startup, before serving, with cfg.AuditHMACKey. An empty key keeps
// the legacy keyless behavior: new rows are written with hash_alg=1 and a warning is
// logged on the first append so the operator knows the chain is not tamper-evident
// against a party with DB write access. Copies the key so the caller may reuse it.
func SetAuditHMACKey(key []byte) {
	auditHMACKeyMu.Lock()
	defer auditHMACKeyMu.Unlock()
	if len(key) == 0 {
		auditHMACKey = nil
		return
	}
	auditHMACKey = append([]byte(nil), key...)
}

func currentAuditHMACKey() []byte {
	auditHMACKeyMu.RLock()
	defer auditHMACKeyMu.RUnlock()
	return auditHMACKey
}

// auditRowTenant resolves the tenant_id column value for an audit event from the
// request context: the caller's tenant when scoped to one, else the Provider tenant
// for cross-tenant/background/unscoped work. This tags the row for tenant-scoped
// audit READS; with the keyed chain (hash_alg=2) it is ALSO bound into the MAC so it
// can no longer be rewritten without invalidating the row.
func auditRowTenant(ctx context.Context) string {
	if v := tenant.GUCValue(ctx); v != "" && v != tenant.Bypass {
		if _, err := uuid.Parse(v); err == nil {
			return v
		}
	}
	return providerTenantID
}

// auditCanonicalLegacy is the pre-HMAC canonical record (hash_alg=1). It EXCLUDES
// seq, created_at and tenant_id. Kept verbatim so rows written before the upgrade
// keep verifying.
func auditCanonicalLegacy(actorID, actorName, action, tk, tid, ip string, detailJSON []byte) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		actorID, actorName, action, tk, tid, ip, string(detailJSON))
}

// auditCanonicalHMAC is the keyed canonical record (hash_alg=2). It binds seq,
// created_at (UTC, RFC3339Nano) and tenant_id in addition to the event fields, so
// none of those columns can be rewritten without invalidating the MAC.
func auditCanonicalHMAC(seq int64, createdAt time.Time, tenantID, actorID, actorName, action, tk, tid, ip string, detailJSON []byte) string {
	return fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		seq, createdAt.UTC().Format(time.RFC3339Nano), tenantID,
		actorID, actorName, action, tk, tid, ip, string(detailJSON))
}

// auditMAC computes the chained hash for a row: keyed HMAC-SHA256 for alg=2, plain
// (keyless) SHA-256 for the legacy alg=1.
func auditMAC(alg int16, key []byte, prev, canonical string) string {
	data := []byte(prev + "|" + canonical)
	if alg == auditAlgHMAC {
		m := hmac.New(sha256.New, key)
		m.Write(data)
		return hex.EncodeToString(m.Sum(nil))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// AppendAudit writes a tamper-evident audit event. Each event's hash chains to the
// previous event's hash. With a configured AuditHMACKey the hash is
// HMAC-SHA256(key, prev_hash || canonical(event)) over a canonical record that binds
// seq, created_at and tenant_id (hash_alg=2); without a key it falls back to the
// legacy keyless SHA-256 (hash_alg=1). The insert is serialized with a transaction +
// advisory lock so the chain stays strictly ordered under concurrency.
//
// The row is inserted with a placeholder hash and the server-assigned seq/created_at
// (and the normalized column values) are read back, so the MAC is computed over
// EXACTLY what VerifyAuditChain later re-reads from the row; the real hash is then
// written in the same transaction.
func (s *Store) AppendAudit(ctx context.Context, e models.AuditEvent) (*models.AuditEvent, error) {
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}
	// The hash chain is a SINGLE GLOBAL sequence (ordered by seq across all tenants).
	// Resolve the event's tenant from the request context BEFORE bypassing, then run the
	// chain-critical section under RLS bypass: otherwise, under multi-tenancy, the
	// prev_hash read is RLS-filtered and an event written while acting inside a customer
	// tenant chains to that tenant's last visible hash — corrupting the global chain and
	// defeating tamper-evidence. The row's tenant_id is inserted EXPLICITLY (the RLS
	// default under bypass would mis-tag it) and, for hash_alg=2, is also bound into the MAC.
	rowTenant := auditRowTenant(ctx)
	bctx := tenant.WithBypass(ctx)

	key := currentAuditHMACKey()
	alg := auditAlgLegacy
	if len(key) > 0 {
		alg = auditAlgHMAC
	} else {
		auditKeylessWarn.Do(func() {
			slog.Warn("audit chain is UNKEYED: no AuditHMACKey configured; new audit rows use the legacy keyless SHA-256 chain (hash_alg=1) and are not tamper-evident against a party with DB write access. Set cfg.AuditHMACKey to key the chain.")
		})
	}

	var out models.AuditEvent
	err := s.tx(bctx, func(tx pgx.Tx) error {
		// Serialize appends so prev_hash is read consistently.
		if _, err := tx.Exec(bctx, `SELECT pg_advisory_xact_lock(hashtext('fleet_audit_chain'))`); err != nil {
			return err
		}
		var prev string
		if err := tx.QueryRow(bctx, `SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&prev); err != nil && err != pgx.ErrNoRows {
			return err
		}
		detailJSON, _ := json.Marshal(e.Detail)

		var (
			seq        int64
			id         uuid.UUID
			tenantID   string
			actorID    *uuid.UUID
			actorName  string
			action, tk string
			tid, ipOut string
			detailBack map[string]any
			createdAt  time.Time
		)
		row := tx.QueryRow(bctx, `
			INSERT INTO audit_events
				(tenant_id, actor_id, actor_name, action, target_kind, target_id, ip, detail, prev_hash, hash, hash_alg)
			VALUES ($1::uuid, $2, NULLIF($3,'')::citext, $4, $5, $6, NULLIF($7,'')::inet, $8, $9, '', $10)
			RETURNING seq, id, tenant_id::text, actor_id, COALESCE(actor_name,''), action,
			          target_kind, target_id, COALESCE(host(ip),''), detail, prev_hash, created_at`,
			rowTenant, e.ActorID, e.ActorName, e.Action, e.TargetKind, e.TargetID, e.IP, detailJSON, prev, alg)
		if err := row.Scan(&seq, &id, &tenantID, &actorID, &actorName, &action, &tk, &tid, &ipOut,
			&detailBack, &out.PrevHash, &createdAt); err != nil {
			return err
		}

		// Marshal the read-back detail so the MAC is over exactly what verify re-reads.
		canonDetail, _ := json.Marshal(detailBack)
		var canonical string
		if alg == auditAlgHMAC {
			canonical = auditCanonicalHMAC(seq, createdAt, tenantID,
				nilUUID(actorID), actorName, action, tk, tid, ipOut, canonDetail)
		} else {
			canonical = auditCanonicalLegacy(nilUUID(actorID), actorName, action, tk, tid, ipOut, canonDetail)
		}
		hash := auditMAC(alg, key, out.PrevHash, canonical)

		if _, err := tx.Exec(bctx, `UPDATE audit_events SET hash=$1 WHERE seq=$2`, hash, seq); err != nil {
			return err
		}
		out.Seq, out.ID, out.Action, out.TargetKind, out.TargetID, out.Hash, out.CreatedAt =
			seq, id, action, tk, tid, hash, createdAt
		return nil
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
// breaks (0 = intact). This makes tampering with any historical row detectable. Each
// row is re-derived with its own hash_alg: legacy rows keyless, keyed rows with the
// configured AuditHMACKey. NOTE: verifying keyed (hash_alg=2) rows requires the same
// AuditHMACKey to be configured; with no key those rows report as broken.
func (s *Store) VerifyAuditChain(ctx context.Context) (intact bool, brokenAtSeq int64, err error) {
	key := currentAuditHMACKey()
	rows, qerr := s.pool.Query(ctx, `
		SELECT seq, tenant_id::text, actor_id, COALESCE(actor_name,''), action, target_kind, target_id,
		       COALESCE(host(ip),''), detail, prev_hash, hash, created_at, hash_alg
		FROM audit_events ORDER BY seq ASC`)
	if qerr != nil {
		return false, 0, qerr
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var (
			seq             int64
			tenantID        string
			actorID         *uuid.UUID
			actorName       string
			action, tk, tid string
			ip, prevH, h    string
			createdAt       time.Time
			alg             int16
			detail          map[string]any
		)
		if err := rows.Scan(&seq, &tenantID, &actorID, &actorName, &action, &tk, &tid, &ip,
			&detail, &prevH, &h, &createdAt, &alg); err != nil {
			return false, 0, err
		}
		detailJSON, _ := json.Marshal(detail)
		var canonical string
		if alg == auditAlgHMAC {
			canonical = auditCanonicalHMAC(seq, createdAt, tenantID,
				nilUUID(actorID), actorName, action, tk, tid, ip, detailJSON)
		} else {
			canonical = auditCanonicalLegacy(nilUUID(actorID), actorName, action, tk, tid, ip, detailJSON)
		}
		want := auditMAC(alg, key, prev, canonical)
		// Constant-time compare on the hash; prev_hash linkage must also match.
		if prevH != prev || !hmac.Equal([]byte(h), []byte(want)) {
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
