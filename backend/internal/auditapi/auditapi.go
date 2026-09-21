// Package auditapi exposes read-only access to the tamper-evident audit log:
// listing, chain verification, and full-export streaming. All routes are gated
// by authentication plus audit permissions.
package auditapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
	"github.com/kforbus3/provenance/backend/internal/tenant"
)

// Mount attaches audit routes to r, gated by authentication and permissions.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)

		pr.With(d.Auth.RequirePermission("Audit.View")).Get("/audit", h.list)
		pr.With(d.Auth.RequirePermission("Audit.View")).Get("/audit/actions", h.actions)
		pr.With(d.Auth.RequirePermission("Audit.View")).Get("/audit/verify", h.verify)
		// Acknowledging a break needs more than reading the log: it is a statement
		// that somebody investigated an integrity failure, so it sits behind the
		// permission that governs the instance rather than Audit.View.
		pr.With(d.Auth.RequirePermission("System.Configure")).Post("/audit/verify/acknowledge", h.acknowledgeBreak)
		// Diagnosis, and the bulk acknowledgement it exists to inform. The scan reads
		// nothing the verdict does not already expose — where the breaks are and how
		// many — but it walks the whole chain, so it sits behind the same permission as
		// acknowledging rather than beside plain reading.
		pr.With(d.Auth.RequirePermission("System.Configure")).Get("/audit/verify/scan", h.scanChain)
		pr.With(d.Auth.RequirePermission("System.Configure")).Post("/audit/verify/acknowledge-range", h.acknowledgeRange)
		pr.With(d.Auth.RequirePermission("Audit.Export")).Get("/audit/export", h.export)
	})
}

type handler struct{ d *app.Deps }

// enrichApprovalEvents fills in the requester + target resource on approval-
// targeted audit events, resolved from the approval request that still exists in
// the DB. This makes older events (recorded before the detail was captured
// inline) readable — "approval:<uuid>" alone doesn't say who or what. It only
// fills missing keys, so newer events that already carry the detail are untouched.
// Display-only: it mutates the response copy, never the hash-chained rows.
func enrichApprovalEvents(r *http.Request, h *handler, events []models.AuditEvent) {
	var ids []uuid.UUID
	for _, e := range events {
		if e.TargetKind == "approval" {
			if id, err := uuid.Parse(e.TargetID); err == nil {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return
	}
	summ, err := h.d.Store.ApprovalSummaries(r.Context(), ids)
	if err != nil {
		return
	}
	put := func(m map[string]any, k, v string) {
		if v == "" {
			return
		}
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
	for i := range events {
		if events[i].TargetKind != "approval" {
			continue
		}
		id, err := uuid.Parse(events[i].TargetID)
		if err != nil {
			continue
		}
		ar, ok := summ[id]
		if !ok {
			continue // request row was deleted; nothing to resolve
		}
		if events[i].Detail == nil {
			events[i].Detail = map[string]any{}
		}
		put(events[i].Detail, "requester", ar.Requester)
		put(events[i].Detail, "targetKind", ar.TargetKind)
		put(events[i].Detail, "targetName", ar.TargetName)
	}
}

// enrichEntityEvents resolves user and host UUIDs — in an event's target and in
// its detail values — to their usernames and hostnames, so the audit log reads
// "user: alice · hostId: web-01" instead of bare UUIDs. It sets TargetName for a
// user/host target and rewrites any detail value that is a UUID naming a known
// user or host. Display-only: it mutates the response copy fetched for the UI,
// never the hash-chained rows (and is not applied to the machine-readable export).
func enrichEntityEvents(r *http.Request, h *handler, events []models.AuditEvent) {
	// Collect every UUID referenced: the target id and any UUID-valued detail entry.
	seen := map[uuid.UUID]bool{}
	add := func(s string) {
		if id, err := uuid.Parse(s); err == nil {
			seen[id] = true
		}
	}
	for i := range events {
		add(events[i].TargetID)
		for _, v := range events[i].Detail {
			if s, ok := v.(string); ok {
				add(s)
			}
		}
	}
	if len(seen) == 0 {
		return
	}
	ids := make([]uuid.UUID, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	users, _ := h.d.Store.UsernamesByIDs(r.Context(), ids)
	hosts, _ := h.d.Store.HostnamesByIDs(r.Context(), ids)
	// name resolves a UUID to a display name, preferring a user then a host.
	name := func(s string) string {
		id, err := uuid.Parse(s)
		if err != nil {
			return ""
		}
		if n, ok := users[id]; ok {
			return n
		}
		if n, ok := hosts[id]; ok {
			return n
		}
		return ""
	}
	applyEntityNames(events, name)
}

// applyEntityNames is the pure rewrite step of enrichEntityEvents: it sets a
// user/host target's TargetName and replaces UUID-valued detail entries with the
// name `resolve` returns (empty string = leave as-is). Split out so it is testable
// without a database.
func applyEntityNames(events []models.AuditEvent, resolve func(string) string) {
	for i := range events {
		if events[i].TargetName == "" {
			if n := resolve(events[i].TargetID); n != "" {
				events[i].TargetName = n
			}
		}
		for k, v := range events[i].Detail {
			if s, ok := v.(string); ok {
				if n := resolve(s); n != "" {
					//nolint:gosec // i is the index from `for i := range events`, always in bounds; Detail[k] is a map write to an existing key
					events[i].Detail[k] = n
				}
			}
		}
	}
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	f := store.AuditFilter{
		Action:    r.URL.Query().Get("action"),
		ActorName: r.URL.Query().Get("actorName"),
		Limit:     limit,
		Offset:    offset,
	}
	// `actor` (an exact UUID) remains supported for programmatic callers; the UI
	// filters by `actorName` (substring) instead.
	if actor := r.URL.Query().Get("actor"); actor != "" {
		id, err := uuid.Parse(actor)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid actor id")
			return
		}
		f.ActorID = &id
	}
	// from/to bound created_at; accept RFC3339 timestamps.
	if from := r.URL.Query().Get("from"); from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid from timestamp (want RFC3339)")
			return
		}
		f.From = &t
	}
	if to := r.URL.Query().Get("to"); to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid to timestamp (want RFC3339)")
			return
		}
		f.To = &t
	}
	events, err := h.d.Store.ListAudit(r.Context(), f)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list audit events")
		return
	}
	if events == nil {
		events = []models.AuditEvent{}
	}
	enrichApprovalEvents(r, h, events)
	enrichEntityEvents(r, h, events)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"events": events, "count": len(events)})
}

// actions lists the distinct action values in the log so the UI can present a
// filter dropdown rather than a free-text box.
func (h *handler) actions(w http.ResponseWriter, r *http.Request) {
	actions, err := h.d.Store.DistinctAuditActions(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list audit actions")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

func (h *handler) verify(w http.ResponseWriter, r *http.Request) {
	// Verify under bypass: the hash chain is a single global sequence across all
	// tenants, so a tenant-scoped read would hide rows and falsely report a break.
	res, err := h.d.Store.VerifyAuditChainDetail(tenant.WithBypass(r.Context()))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify audit chain")
		return
	}
	// "intact" answers only "was anything altered". Weak links are reported beside
	// it rather than folded into it: a weak link cannot be repaired -- rewriting
	// that row means rewriting every hash after it, the exact operation this chain
	// exists to make impossible -- so folding it in would leave the report saying
	// "broken" forever and hide every genuine break behind it.
	body := map[string]any{"intact": res.BrokenAtSeq == 0, "brokenAtSeq": res.BrokenAtSeq}
	// Acknowledged breaks are reported beside the verdict, never folded into it. They
	// are permanent facts about this chain — the rows are still altered or missing —
	// and hiding them would be the forgery the chain exists to prevent. What they
	// change is only whether the break is NEWS.
	if len(res.Acknowledged) > 0 {
		body["acknowledgedBreaks"] = res.Acknowledged
	}
	if len(res.AcknowledgedRanges) > 0 {
		body["acknowledgedRanges"] = res.AcknowledgedRanges
	}
	if res.WeakFromSeq != 0 {
		body["weakFromSeq"] = res.WeakFromSeq
		body["weakCount"] = res.WeakCount
		body["weakReason"] = "keyless rows written after the chain was keyed; from this " +
			"sequence the tail is not tamper-evident against a party with database write access"
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

// export streams the entire audit log as a JSON array, paging through the store
// so the full chain can be exported without loading it all into memory at once.
func (h *handler) export(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-export.json"`)
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	_, _ = w.Write([]byte("["))
	first := true
	const page = 1000
	for offset := 0; ; offset += page {
		events, err := h.d.Store.ListAudit(r.Context(), store.AuditFilter{Limit: page, Offset: offset})
		if err != nil {
			return
		}
		for i := range events {
			if !first {
				_, _ = w.Write([]byte(","))
			}
			first = false
			_ = enc.Encode(events[i])
		}
		if len(events) < page {
			break
		}
	}
	_, _ = w.Write([]byte("]"))
}

// acknowledgeBreak records that a detected break in the audit chain was investigated.
//
// It does not repair anything, and cannot: the rows stay as they are, and verification
// reports the break for ever. What changes is that verification CONTINUES past it, so a
// later break is visible instead of hiding behind a permanent red light nobody reads.
//
// The acknowledgement is written as an ordinary audit event first, and that event's
// sequence number is what the record points at. The verifier honours an acknowledgement
// only when its event is present and verifies as part of the chain — so an entry
// inserted straight into the database, without the key needed to produce a chained
// event, accounts for nothing.
func (h *handler) acknowledgeBreak(w http.ResponseWriter, r *http.Request) {
	var rq struct {
		BrokenAtSeq int64  `json:"brokenAtSeq"`
		Note        string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if rq.BrokenAtSeq <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "brokenAtSeq is required")
		return
	}
	if strings.TrimSpace(rq.Note) == "" {
		// The note is the whole value of the record. An acknowledgement with no
		// account of what was found is indistinguishable from dismissing the alarm.
		httpx.WriteError(w, http.StatusBadRequest,
			"a note is required: record what was investigated and what was found")
		return
	}
	ctx := tenant.WithBypass(r.Context())

	// Confirm the break is real and unacknowledged before recording anything. Allowing
	// an acknowledgement for a sequence that does not break would let somebody
	// pre-authorise a future alteration.
	res, err := h.d.Store.VerifyAuditChainDetail(ctx)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify audit chain")
		return
	}
	if res.BrokenAtSeq != rq.BrokenAtSeq {
		httpx.WriteError(w, http.StatusConflict, fmt.Sprintf(
			"the chain does not currently break at %d (the first unacknowledged break is %d). "+
				"Acknowledging a sequence that does not break would pre-authorise a future alteration",
			rq.BrokenAtSeq, res.BrokenAtSeq))
		return
	}

	p := auth.MustPrincipal(r)
	// Written through the ordinary audited path, so it is chained like everything else
	// — which is exactly what makes it usable as evidence.
	ev := models.AuditEvent{
		Action:     "audit.chain_break_acknowledged",
		TargetKind: "audit_chain",
		TargetID:   fmt.Sprint(rq.BrokenAtSeq),
		Detail:     map[string]any{"brokenAtSeq": rq.BrokenAtSeq, "note": rq.Note},
	}
	httpx.Audit(r, h.d.Store, ev)
	// The event just written is the evidence this record points at.
	evidence, err := h.d.Store.LatestAuditSeq(ctx)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the audit sequence")
		return
	}
	var by *uuid.UUID
	name := ""
	if p != nil {
		by = &p.UserID
		name = p.Username
	}
	if err := h.d.Store.AcknowledgeAuditChainBreak(ctx, rq.BrokenAtSeq, evidence, by, name, rq.Note); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not record the acknowledgement")
		return
	}
	after, _ := h.d.Store.VerifyAuditChainDetail(ctx)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"acknowledged": rq.BrokenAtSeq,
		"evidenceSeq":  evidence,
		"intact":       after.BrokenAtSeq == 0,
		"brokenAtSeq":  after.BrokenAtSeq,
		"note": "the break is permanent and will always be reported; verification now " +
			"continues past it, so a later break is still visible",
	})
}

// scanChain enumerates every break in the chain instead of stopping at the first.
//
// The daily verdict answers "has anything been altered". Once that answer is yes,
// the next questions are how much, where, and whether it looks like one event or
// many — and the only honest way to answer them is to walk the whole chain at once.
// Acknowledging breaks one at a time to see what surfaces behind them is not a
// diagnosis; on the first production chain examined this way it would have been
// 3,054 attestations, each appending an audit event of its own.
func (h *handler) scanChain(w http.ResponseWriter, r *http.Request) {
	scan, err := h.d.Store.ScanAuditChain(tenant.WithBypass(r.Context()))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not scan audit chain")
		return
	}
	body := map[string]any{
		"rows":              scan.Rows,
		"breakCount":        scan.BreakCount,
		"acknowledgedCount": scan.AcknowledgedCount,
		"firstSeq":          scan.FirstSeq,
		"lastSeq":           scan.LastSeq,
		"breaks":            scan.Breaks,
		"truncated":         scan.Truncated,
		// Named for what it is: consistency with a known cause, not proof of one. The
		// original actor id is gone, so nothing can show what it was.
		"noActorCount":  scan.LostAttributionCount,
		"unlinkedCount": scan.UnlinkedCount,
	}
	if scan.BreakCount > 0 {
		body["unexplainedCount"] = scan.BreakCount - scan.LostAttributionCount
	}
	if scan.WeakFromSeq != 0 {
		body["weakFromSeq"] = scan.WeakFromSeq
		body["weakCount"] = scan.WeakCount
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

// acknowledgeRange records that one investigated event accounts for every break in a
// span. See migration 0107; the safeguards live here and in the verifier.
func (h *handler) acknowledgeRange(w http.ResponseWriter, r *http.Request) {
	var rq struct {
		FromSeq int64  `json:"fromSeq"`
		ToSeq   int64  `json:"toSeq"`
		Note    string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if rq.FromSeq <= 0 || rq.ToSeq < rq.FromSeq {
		httpx.WriteError(w, http.StatusBadRequest, "fromSeq and toSeq are required, with toSeq >= fromSeq")
		return
	}
	if strings.TrimSpace(rq.Note) == "" {
		httpx.WriteError(w, http.StatusBadRequest,
			"a note is required: record what was investigated and what was found")
		return
	}
	ctx := tenant.WithBypass(r.Context())

	// The count is measured here, never taken from the request. It is the safeguard
	// that stops the acknowledgement absorbing a break that arrives later, so a caller
	// who could inflate it could defeat the whole mechanism.
	scan, err := h.d.Store.ScanAuditChainRange(ctx, rq.FromSeq, rq.ToSeq)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not scan audit chain")
		return
	}
	if scan.BreakCount == 0 {
		httpx.WriteError(w, http.StatusConflict, fmt.Sprintf(
			"no break in the chain between %d and %d. Acknowledging a span that does not "+
				"break would pre-authorise a future alteration", rq.FromSeq, rq.ToSeq))
		return
	}
	// A bulk acknowledgement covers ONE signature. Anything else in the span is a
	// separate finding and has to be dealt with as one, so the tool for the known
	// cause cannot be pointed at an unknown one.
	if bad := scan.BreakCount - scan.LostAttributionCount; bad > 0 {
		httpx.WriteError(w, http.StatusConflict, fmt.Sprintf(
			"%d break(s) between %d and %d still have an actor_id, so they were not caused by "+
				"the deleted-user defect this covers; acknowledge those individually",
			bad, rq.FromSeq, rq.ToSeq))
		return
	}
	if scan.UnlinkedCount > 0 {
		httpx.WriteError(w, http.StatusConflict, fmt.Sprintf(
			"%d break(s) between %d and %d have a broken prev_hash link, which means rows were "+
				"removed, inserted or reordered rather than a column being lost; that cannot be "+
				"acknowledged in bulk", scan.UnlinkedCount, rq.FromSeq, rq.ToSeq))
		return
	}

	p := auth.MustPrincipal(r)
	ev := models.AuditEvent{
		Action:     "audit.chain_break_range_acknowledged",
		TargetKind: "audit_chain",
		TargetID:   fmt.Sprintf("%d-%d", rq.FromSeq, rq.ToSeq),
		Detail: map[string]any{
			"fromSeq": rq.FromSeq, "toSeq": rq.ToSeq,
			"coveredCount": scan.BreakCount, "note": rq.Note,
		},
	}
	httpx.Audit(r, h.d.Store, ev)
	evidence, err := h.d.Store.LatestAuditSeq(ctx)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not record the acknowledgement")
		return
	}
	var by *uuid.UUID
	var byName string
	if p != nil {
		by = &p.UserID
		byName = p.Username
	}
	if err := h.d.Store.AcknowledgeAuditChainRange(ctx, rq.FromSeq, rq.ToSeq,
		scan.BreakCount, evidence, by, byName, strings.TrimSpace(rq.Note)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not record the acknowledgement")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"fromSeq": rq.FromSeq, "toSeq": rq.ToSeq, "coveredCount": scan.BreakCount,
		"evidenceSeq": evidence,
	})
}
