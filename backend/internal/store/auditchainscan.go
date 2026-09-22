package store

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Enumerating the breaks in the chain, rather than reporting only the first.
//
// VerifyAuditChainDetail answers the question an operator asks every day — "has
// anything been altered?" — and stops at the first unacknowledged break, because for
// that question the answer is already no.
//
// It is the wrong shape for the question asked once, after the answer is yes: how
// much, where, and does it look like one event or many? Answering that by
// acknowledging breaks one at a time to see what surfaces next is not a diagnosis,
// it is 3,000 attestations; and each acknowledgement appends an audit event, so the
// chain grows while being investigated.
//
// So this walks the whole chain read-only and reports every break at once. It
// acknowledges nothing and writes nothing.
type AuditChainScan struct {
	// Rows is how many events were walked.
	Rows int64
	// Breaks is every break found, oldest first, capped at scanBreakSample. The
	// counts below are exact regardless of the cap.
	Breaks []AuditChainBreak
	// BreakCount is the total number of rows that did not verify.
	BreakCount int
	// LostAttributionCount is how many of those are CONSISTENT with the
	// ON DELETE SET NULL defect fixed in migration 0106: the account was deleted and
	// the foreign key nulled actor_id, a column the hash covers. Those rows were not
	// altered by anybody — they lost a field — but a hash cannot tell the difference
	// and never will.
	//
	// It is a consistency test, not proof, and must not be described as proof. The
	// original actor_id is gone, so no recomputation can show what it was; anyone who
	// could edit a row could also null its actor_id and land in this count. What makes
	// it worth reporting is the converse: a break that is NOT consistent with it has
	// no innocent explanation on offer at all.
	LostAttributionCount int
	// UnlinkedCount is how many breaks have a prev_hash that does not match the
	// previous row — exact, not sampled.
	//
	// This is the part that is evidence rather than inference. Nulling a field breaks
	// a row's own hash and nothing else; removing, inserting or reordering rows breaks
	// the LINKS. Zero unlinked breaks across thousands of rows says the sequence is
	// whole, whatever happened to the columns inside it.
	UnlinkedCount int
	// AcknowledgedCount is how many breaks already carry an acknowledgement.
	AcknowledgedCount int
	// FirstSeq and LastSeq bound the breaks found.
	FirstSeq, LastSeq int64
	// Truncated says the Breaks sample is shorter than BreakCount.
	Truncated bool
	// WeakFromSeq and WeakCount carry the same meaning as in AuditChainResult.
	WeakFromSeq int64
	WeakCount   int
}

// AuditChainBreak is one row that did not verify.
type AuditChainBreak struct {
	Seq       int64     `json:"seq"`
	Action    string    `json:"action"`
	ActorName string    `json:"actorName"`
	At        time.Time `json:"at"`
	// LostAttribution marks the migration-0106 fingerprint described above.
	LostAttribution bool `json:"lostAttribution"`
	// Unlinked means prev_hash does not match the previous row's hash, as opposed to
	// only this row's own hash being wrong. A run of rows where just the hash is
	// wrong looks like fields going missing; a broken link looks like rows being
	// removed or reordered.
	Unlinked     bool `json:"unlinked"`
	Acknowledged bool `json:"acknowledged"`

	// The remainder is forensic detail for diagnosing an unexplained break, and is
	// deliberately not serialised: the API reports where and how many, while working
	// out WHY a specific row does not hash is a job for an operator at the CLI.
	Alg          int16             `json:"-"`
	DetailJSON   string            `json:"-"`
	StoredHash   string            `json:"-"`
	ComputedHash string            `json:"-"`
	Fields       map[string]string `json:"-"`
}

// scanBreakSample caps the sample so a chain that is broken from end to end cannot
// turn a diagnostic into a memory problem.
const scanBreakSample = 200

// ScanAuditChain walks the entire chain and reports every break. It is read-only.
func (s *Store) ScanAuditChain(ctx context.Context) (AuditChainScan, error) {
	return s.scanAuditChain(ctx, 0, 0)
}

// ScanAuditChainRange reports only the breaks between fromSeq and toSeq inclusive.
//
// The walk still starts at the first event whatever the range, because a row's hash
// covers the previous row's: beginning in the middle would mean inventing the hash
// the first row chains to, and every row in the range would look broken.
func (s *Store) ScanAuditChainRange(ctx context.Context, fromSeq, toSeq int64) (AuditChainScan, error) {
	return s.scanAuditChain(ctx, fromSeq, toSeq)
}

func (s *Store) scanAuditChain(ctx context.Context, fromSeq, toSeq int64) (AuditChainScan, error) {
	var out AuditChainScan
	key := currentAuditHMACKey()

	acked := map[int64]bool{}
	if ar, aerr := s.pool.Query(ctx, `SELECT broken_at_seq FROM audit_chain_breaks`); aerr == nil {
		for ar.Next() {
			var seq int64
			if ar.Scan(&seq) == nil {
				acked[seq] = true
			}
		}
		ar.Close()
	}

	rows, qerr := s.pool.Query(ctx, `
		SELECT seq, tenant_id::text, actor_id, COALESCE(actor_name,''), action, target_kind, target_id,
		       COALESCE(host(ip),''), detail, prev_hash, hash, created_at, hash_alg
		FROM audit_events ORDER BY seq ASC`)
	if qerr != nil {
		return out, qerr
	}
	defer rows.Close()

	// Same boundary rule as VerifyAuditChainDetail: a declared retention prune is not
	// a break. See prunedBoundary.
	prev := s.prunedBoundary(ctx)
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
		out.Rows++
		detailJSON, _ := json.Marshal(detail)
		want := auditExpectedHash(key, prev, alg, seq, createdAt, tenantID,
			nilUUID(actorID), actorName, action, tk, tid, ip, detailJSON)

		if prevH != prev || !hmac.Equal([]byte(h), []byte(want)) {
			// Outside the range asked about: still resume from the stored hash, so the
			// rows inside the range are judged against the same chain the verifier sees,
			// but do not count it.
			if fromSeq != 0 && (seq < fromSeq || seq > toSeq) {
				prev = h
				if alg == auditAlgHMAC {
					seenKeyed = true
				}
				continue
			}
			b := AuditChainBreak{
				Seq: seq, Action: action, ActorName: actorName, At: createdAt,
				Unlinked:     prevH != prev,
				Acknowledged: acked[seq],
				// The fingerprint is a missing actor id, and nothing more.
				//
				// It first also required an actor_name, on the reasoning that a row
				// written by the system or a CLI has neither and hashes correctly with
				// an empty actor id. That misclassified 136 of 3,054 real cases in the
				// first production chain it met: host.enroll and host.enroll_failed
				// record an actor_id and no actor_name at all, so losing the id left
				// them with neither, and they were reported as unexplained breaks with
				// an identical cause. Surviving rows of those same actions still carry
				// an actor_id with no name, which is what showed it.
				LostAttribution: actorID == nil,
				Alg:             alg,
				DetailJSON:      string(detailJSON),
				StoredHash:      h,
				ComputedHash:    want,
				Fields: map[string]string{
					"tenant_id": tenantID, "actor_id": nilUUID(actorID), "actor_name": actorName,
					"target_kind": tk, "target_id": tid, "ip": ip,
					"created_at": createdAt.Format(time.RFC3339Nano),
				},
			}
			out.BreakCount++
			if b.LostAttribution {
				out.LostAttributionCount++
			}
			if b.Unlinked {
				out.UnlinkedCount++
			}
			if b.Acknowledged {
				out.AcknowledgedCount++
			}
			if out.FirstSeq == 0 {
				out.FirstSeq = seq
			}
			out.LastSeq = seq
			if len(out.Breaks) < scanBreakSample {
				out.Breaks = append(out.Breaks, b)
			} else {
				out.Truncated = true
			}
			// Resume from the row's own stored hash, exactly as verification does for an
			// acknowledged break. Carrying the recomputed hash forward instead would
			// report every subsequent row as broken too, turning one altered field into
			// a chain that is broken from there to the end.
			prev = h
			if alg == auditAlgHMAC {
				seenKeyed = true
			}
			continue
		}
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
	return out, rows.Err()
}
