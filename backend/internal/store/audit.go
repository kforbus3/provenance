package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/tenant"
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

// auditExpectedHash is the hash a stored row must carry if nothing about it has
// changed: the MAC of the previous row's hash and this row's canonical record, in
// whichever algorithm the row itself names.
//
// It is shared by every walk of the chain rather than written out at each one.
// Verification and enumeration disagreeing about how a row hashes would be the
// worst possible bug here — one of them would call an untouched row altered, or an
// altered row fine — and the only way to be sure they agree is for there to be one
// of it.
func auditExpectedHash(key []byte, prev string, alg int16, seq int64, createdAt time.Time,
	tenantID, actorID, actorName, action, tk, tid, ip string, detailJSON []byte) string {
	var canonical string
	if alg == auditAlgHMAC {
		canonical = auditCanonicalHMAC(seq, createdAt, tenantID,
			actorID, actorName, action, tk, tid, ip, detailJSON)
	} else {
		canonical = auditCanonicalLegacy(actorID, actorName, action, tk, tid, ip, detailJSON)
	}
	return auditMAC(alg, key, prev, canonical)
}

// AuditChainIsKeyed reports whether this chain already contains a keyed row.
//
// It exists so a process can refuse to append a KEYLESS row to a chain that has
// moved past that. Each row names its own algorithm and the verifier re-derives
// hash_alg=1 rows with plain SHA-256, so a keyless row after keying verifies -- and
// permanently marks the tail as not tamper-evident from that sequence on.
//
// That is not a hypothetical either. On one production chain, sequence 3389 is a
// single keyless row: `create-admin` run from the CLI without PROV_AUDIT_HMAC_KEY in
// its environment, between two keyed rows written by the backend. The same command
// run later WITH the key in the environment produced a keyed row. One missing
// variable, one permanently weakened chain, and the only signal at the time was a
// warning on the CLI's stderr.
func (s *Store) AuditChainIsKeyed(ctx context.Context) (bool, error) {
	var keyed bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM audit_events WHERE hash_alg = $1)`, auditAlgHMAC).Scan(&keyed)
	return keyed, err
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
		if _, err := tx.Exec(bctx, `SELECT pg_advisory_xact_lock(hashtext('prov_audit_chain'))`); err != nil {
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
	r, verr := s.VerifyAuditChainDetail(ctx)
	if verr != nil {
		return false, 0, verr
	}
	// Kept for callers that only ask "was anything altered". A weak link is not an
	// alteration; it is a row that could be altered undetectably, which
	// VerifyAuditChainDetail reports separately so a permanent weak link cannot
	// mask a later real break.
	return r.BrokenAtSeq == 0, r.BrokenAtSeq, nil
}

// AuditChainResult separates "something was altered" from "something could be
// altered without this noticing".
//
// They need separating because only the FIRST problem is reported. A weak link
// that cannot be repaired -- rewriting it would mean rewriting every hash after
// it, which is the operation the chain exists to make impossible -- would sit at
// the head of the report forever and hide every genuine break behind it.
type AuditChainResult struct {
	// BrokenAtSeq is the first UNACKNOWLEDGED row whose hash or prev_hash does not
	// match: a real alteration nobody has accounted for. 0 when the chain is sound.
	BrokenAtSeq int64
	// Acknowledged are breaks somebody has investigated and recorded. They are still
	// breaks — the data is still altered or missing and always will be — but they are
	// not news, and verification continues past them so a LATER break is still
	// visible. A chain that can only ever say BROKEN is one people stop reading.
	Acknowledged []AcknowledgedBreak
	// AcknowledgedRanges are bulk acknowledgements: one investigated event that broke
	// many rows at once, recorded once instead of once per row. Like Acknowledged they
	// repair nothing and are reported for ever, with the count they cover.
	AcknowledgedRanges []AcknowledgedRange
	// WeakFromSeq is the first keyless row written AFTER the chain was keyed. From
	// there the tail is not tamper-evident: a party with database write access can
	// append or rebuild keyless rows and they verify, because each row names its
	// own algorithm. 0 when there is none.
	WeakFromSeq int64
	// WeakCount is how many such rows there are.
	WeakCount int
}

// AcknowledgedRange is a bulk acknowledgement covering every break in a span of
// sequence numbers that carries one known signature. See migration 0107.
type AcknowledgedRange struct {
	FromSeq int64 `json:"fromSeq"`
	ToSeq   int64 `json:"toSeq"`
	// Covered is how many breaks it actually accounts for right now, and CoveredCount
	// is how many were there when it was investigated. The acknowledgement stops being
	// honoured if Covered ever exceeds CoveredCount, so the two being equal is part of
	// the report rather than an internal detail.
	Covered      int       `json:"covered"`
	CoveredCount int       `json:"coveredCount"`
	By           string    `json:"by"`
	Note         string    `json:"note"`
	At           time.Time `json:"at"`
}

// AcknowledgedBreak is a break in the chain that was investigated and recorded.
type AcknowledgedBreak struct {
	BrokenAtSeq int64     `json:"brokenAtSeq"`
	By          string    `json:"by"`
	Note        string    `json:"note"`
	At          time.Time `json:"at"`
}

// VerifyAuditChainDetail recomputes the chain and reports both conditions.
func (s *Store) VerifyAuditChainDetail(ctx context.Context) (AuditChainResult, error) {
	var out AuditChainResult
	key := currentAuditHMACKey()
	// Acknowledgements are loaded first, but honoured only where the audit event that
	// recorded one is itself present and verifies further down the chain. A party with
	// database write access can insert into audit_chain_breaks; they cannot forge the
	// chained event it points at without the key. See the migration.
	acks := map[int64]AcknowledgedBreak{}
	evidence := map[int64]int64{} // evidence seq -> the break it accounts for
	if ar, aerr := s.pool.Query(ctx, `
		SELECT broken_at_seq, evidence_seq, COALESCE(acknowledged_name,''), COALESCE(note,''), acknowledged_at
		FROM audit_chain_breaks`); aerr == nil {
		for ar.Next() {
			var b AcknowledgedBreak
			var ev int64
			if ar.Scan(&b.BrokenAtSeq, &ev, &b.By, &b.Note, &b.At) == nil {
				acks[b.BrokenAtSeq] = b
				evidence[ev] = b.BrokenAtSeq
			}
		}
		ar.Close()
	}
	// Range acknowledgements, loaded the same way and honoured under the same rule:
	// only while the chained event that recorded one is present and verifies.
	type ackRange struct {
		id           int64
		from, to     int64
		coveredCount int
		evidenceSeq  int64
		by, note     string
		at           time.Time
	}
	var ranges []ackRange
	rangeEvidence := map[int64]int64{} // evidence seq -> range id
	if rr, rerr := s.pool.Query(ctx, `
		SELECT id, from_seq, to_seq, covered_count, evidence_seq,
		       COALESCE(acknowledged_name,''), COALESCE(note,''), acknowledged_at
		FROM audit_chain_break_ranges ORDER BY from_seq`); rerr == nil {
		for rr.Next() {
			var g ackRange
			if rr.Scan(&g.id, &g.from, &g.to, &g.coveredCount, &g.evidenceSeq,
				&g.by, &g.note, &g.at) == nil {
				ranges = append(ranges, g)
				rangeEvidence[g.evidenceSeq] = g.id
			}
		}
		rr.Close()
	}
	rangeHits := map[int64]int{}    // range id -> breaks it covered on this walk
	rangeFirst := map[int64]int64{} // range id -> lowest such break
	verifiedRangeEvidence := map[int64]bool{}

	// A break is only reported as acknowledged once its evidence row has been walked
	// and verified, so this collects them and they are moved across at the end.
	pending := map[int64]AcknowledgedBreak{}
	verifiedEvidence := map[int64]bool{}
	rows, qerr := s.pool.Query(ctx, `
		SELECT seq, tenant_id::text, actor_id, COALESCE(actor_name,''), action, target_kind, target_id,
		       COALESCE(host(ip),''), detail, prev_hash, hash, created_at, hash_alg
		FROM audit_events ORDER BY seq ASC`)
	if qerr != nil {
		return out, qerr
	}
	defer rows.Close()
	prev := ""
	seenKeyed := false
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
			return out, err
		}
		detailJSON, _ := json.Marshal(detail)
		want := auditExpectedHash(key, prev, alg, seq, createdAt, tenantID,
			nilUUID(actorID), actorName, action, tk, tid, ip, detailJSON)
		// Constant-time compare on the hash; prev_hash linkage must also match.
		if prevH != prev || !hmac.Equal([]byte(h), []byte(want)) {
			ack, ok := acks[seq]
			if !ok {
				// A range acknowledgement may account for it, but only if this break
				// carries the signature that range was allowed to cover: the actor id
				// gone, and the link to the previous row still intact. A row that still
				// has its actor id did not lose one, and a broken LINK means rows were
				// removed, inserted or reordered — neither looks like the defect a bulk
				// acknowledgement is for, so neither can hide inside one.
				covered := false
				if actorID == nil && prevH == prev {
					for _, g := range ranges {
						if seq >= g.from && seq <= g.to {
							rangeHits[g.id]++
							if rangeFirst[g.id] == 0 || seq < rangeFirst[g.id] {
								rangeFirst[g.id] = seq
							}
							covered = true
							break
						}
					}
				}
				if !covered {
					// Record the first unacknowledged break and keep walking.
					//
					// This used to return here. Stopping made the verdict correct and the
					// report useless: a new break meant the walk never reached the rows
					// that make existing acknowledgements trustworthy, so a chain with one
					// fresh break reported nothing about the 3,000 already accounted for,
					// and the weak-tail check silently stopped running. The verdict is the
					// same value either way — the first unacknowledged break — so there is
					// nothing to lose by finishing the walk.
					if out.BrokenAtSeq == 0 {
						out.BrokenAtSeq = seq
					}
				}
			} else {
				// Accounted for: resume from this row's own recorded hash and keep
				// checking. Nothing here is repaired — the row stays exactly as it is and
				// this break is reported for ever — but the rows after it are still
				// verified, so a new break cannot hide behind an old one.
				pending[seq] = ack
			}
			prev = h
			if alg == auditAlgHMAC {
				seenKeyed = true
			}
			continue
		}
		if rid, ok := rangeEvidence[seq]; ok {
			// Same rule as below, for a range: the acknowledgement is trustworthy only
			// because the event recording it verifies as part of this chain.
			verifiedRangeEvidence[rid] = true
		}
		if b, ok := evidence[seq]; ok {
			// This row IS an acknowledgement, and it has just verified as part of the
			// chain. That is what makes the acknowledgement trustworthy.
			verifiedEvidence[b] = true
		}
		// No downgrade once the chain is keyed.
		//
		// Each row names its own algorithm, and anything that is not hash_alg=2 is
		// re-derived with keyless SHA-256 -- which is what lets rows written before
		// the key existed still verify. The attacker also writes that column. So a
		// party with only database write access could read the tail hash, append
		// events of their choosing tagged hash_alg=1, hash them with plain SHA-256,
		// and this function would report the chain intact. The same move rebuilds a
		// whole tail, erasing what it replaces.
		//
		// Demonstrated, not theorised: TestAuditChainRejectsKeylessRowAfterKeying
		// forges exactly that row and this used to return intact=true.
		//
		// Once a keyed row exists, every later row must be keyed. The attacker
		// cannot produce hash_alg=2 without the key, so they cannot move the
		// boundary forward, and anything keyless after it is refused.
		if alg == auditAlgHMAC {
			seenKeyed = true
		} else if seenKeyed {
			if out.WeakFromSeq == 0 {
				out.WeakFromSeq = seq
			}
			out.WeakCount++
		}
		prev = h
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	// Only acknowledgements whose own audit event verified are honoured. One without
	// it is a row somebody wrote directly into the database, and the break it claims to
	// account for is reported as though it had never been acknowledged.
	for seq, ack := range pending {
		if verifiedEvidence[seq] {
			out.Acknowledged = append(out.Acknowledged, ack)
			continue
		}
		if out.BrokenAtSeq == 0 || seq < out.BrokenAtSeq {
			out.BrokenAtSeq = seq
		}
	}
	sort.Slice(out.Acknowledged, func(i, j int) bool {
		return out.Acknowledged[i].BrokenAtSeq < out.Acknowledged[j].BrokenAtSeq
	})
	// Ranges are honoured only if their evidence verified AND they are covering no more
	// breaks than were investigated. The count is the safeguard that stops a range
	// becoming an open licence: a break that appears inside an already-acknowledged span
	// after the fact pushes the total past what was recorded, and the whole
	// acknowledgement stops being honoured rather than quietly absorbing it.
	for _, g := range ranges {
		hits := rangeHits[g.id]
		if hits == 0 {
			continue
		}
		if !verifiedRangeEvidence[g.id] || hits > g.coveredCount {
			if out.BrokenAtSeq == 0 || rangeFirst[g.id] < out.BrokenAtSeq {
				out.BrokenAtSeq = rangeFirst[g.id]
			}
			continue
		}
		out.AcknowledgedRanges = append(out.AcknowledgedRanges, AcknowledgedRange{
			FromSeq: g.from, ToSeq: g.to, Covered: hits, CoveredCount: g.coveredCount,
			By: g.by, Note: g.note, At: g.at,
		})
	}
	sort.Slice(out.AcknowledgedRanges, func(i, j int) bool {
		return out.AcknowledgedRanges[i].FromSeq < out.AcknowledgedRanges[j].FromSeq
	})
	return out, nil
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

// AcknowledgeAuditChainBreak records that a break was investigated.
//
// It repairs nothing. The altered or missing rows stay exactly as they are and the
// break is reported for ever — as reviewed rather than as news — and verification
// carries on past it so a later break is still visible.
//
// evidenceSeq is the audit event that recorded this acknowledgement, written by the
// caller through the ordinary audited path so that it is part of the chain. The
// verifier honours an acknowledgement only when that event verifies, which is what
// stops a party with database write access from simply inserting one here.
// AcknowledgeAuditChainRange records a bulk acknowledgement. See migration 0107 for
// why one exists and what keeps it honest; coveredCount is the safeguard, and the
// caller must have counted it from the same walk the verifier performs.
func (s *Store) AcknowledgeAuditChainRange(ctx context.Context, fromSeq, toSeq int64,
	coveredCount int, evidenceSeq int64, by *uuid.UUID, byName, note string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_chain_break_ranges
			(from_seq, to_seq, covered_count, evidence_seq, acknowledged_by, acknowledged_name, note)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		fromSeq, toSeq, coveredCount, evidenceSeq, by, byName, note)
	return err
}

func (s *Store) AcknowledgeAuditChainBreak(ctx context.Context, brokenAtSeq, evidenceSeq int64,
	by *uuid.UUID, byName, note string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_chain_breaks (broken_at_seq, evidence_seq, acknowledged_by, acknowledged_name, note)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (broken_at_seq) DO UPDATE
		   SET evidence_seq = EXCLUDED.evidence_seq,
		       acknowledged_by = EXCLUDED.acknowledged_by,
		       acknowledged_name = EXCLUDED.acknowledged_name,
		       note = EXCLUDED.note,
		       acknowledged_at = now()`,
		brokenAtSeq, evidenceSeq, by, byName, note)
	return err
}

// LatestAuditSeq is the sequence number of the most recent audit event, used to point
// an acknowledgement at the event that recorded it.
func (s *Store) LatestAuditSeq(ctx context.Context) (int64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(seq),0) FROM audit_events`).Scan(&seq)
	return seq, err
}
