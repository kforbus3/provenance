import { api } from "./client";

// Read-only access to the tamper-evident audit chain (/audit, /audit/verify).

export interface AuditEvent {
  seq: number;
  id: string;
  actorId?: string;
  actorName?: string;
  action: string;
  targetKind?: string;
  targetId?: string;
  targetName?: string;
  ip?: string;
  detail?: Record<string, unknown>;
  prevHash: string;
  hash: string;
  createdAt: string;
}

export interface AuditFilter {
  action?: string;
  // Case-insensitive substring match on the actor's name (friendlier than the
  // raw actor UUID the API also accepts via `actor`).
  actorName?: string;
  // RFC3339 timestamps bounding created_at (inclusive).
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

// A break somebody investigated and recorded. It is STILL a break — the row is
// altered or missing and always will be — but it is not news, and verification
// continues past it so a later break is still visible.
export interface AcknowledgedBreak {
  brokenAtSeq: number;
  by: string;
  note: string;
  at: string;
}

// One investigated event that broke many rows at once, recorded once. `covered` is
// how many breaks it accounts for now and `coveredCount` how many were there when it
// was investigated; if the first ever exceeds the second the acknowledgement stops
// being honoured, so both are reported.
export interface AcknowledgedRange {
  fromSeq: number;
  toSeq: number;
  covered: number;
  coveredCount: number;
  by: string;
  note: string;
  at: string;
}

export interface VerifyResult {
  // `intact` answers only "is there an UNEXPLAINED alteration". A chain with
  // acknowledged breaks is intact by this measure and still contains rows that do not
  // verify, so anything showing a verdict has to look at the acknowledgements too.
  intact: boolean;
  brokenAtSeq: number;
  acknowledgedBreaks?: AcknowledgedBreak[];
  acknowledgedRanges?: AcknowledgedRange[];
  // Keyless rows written after the chain was keyed: from here the tail is not
  // tamper-evident against a party with database write access.
  weakFromSeq?: number;
  weakCount?: number;
  weakReason?: string;
}

// One break from the diagnostic scan.
export interface ChainBreak {
  seq: number;
  action: string;
  actorName: string;
  at: string;
  // Consistent with the deleted-user defect (a lost actor_id), not proof of it.
  lostAttribution: boolean;
  // The link to the previous row is broken: rows removed, inserted or reordered.
  unlinked: boolean;
  acknowledged: boolean;
}

export interface ChainScan {
  rows: number;
  breakCount: number;
  acknowledgedCount: number;
  firstSeq: number;
  lastSeq: number;
  breaks: ChainBreak[];
  truncated: boolean;
  noActorCount: number;
  unlinkedCount: number;
  unexplainedCount?: number;
  weakFromSeq?: number;
  weakCount?: number;
}

export async function listAudit(filter: AuditFilter = {}): Promise<AuditEvent[]> {
  const { data } = await api.get<{ events: AuditEvent[] }>("/api/v1/audit", {
    params: filter,
  });
  return data.events;
}

export async function listAuditActions(): Promise<string[]> {
  const { data } = await api.get<{ actions: string[] }>("/api/v1/audit/actions");
  return data.actions ?? [];
}

export async function verifyAudit(): Promise<VerifyResult> {
  const { data } = await api.get<VerifyResult>("/api/v1/audit/verify");
  return data;
}

// Walk the whole chain and report every break, rather than stopping at the first.
// Answers "how much, where, and does it look like one event or many" — the questions
// that only arise once the verdict is already "broken".
export async function scanAuditChain(): Promise<ChainScan> {
  const { data } = await api.get<ChainScan>("/api/v1/audit/verify/scan");
  return data;
}

// Record that one investigated event accounts for every break in a span. Repairs
// nothing: the rows stay as they are and are reported for ever, with this note.
export async function acknowledgeChainRange(
  fromSeq: number, toSeq: number, note: string,
): Promise<{ fromSeq: number; toSeq: number; coveredCount: number; evidenceSeq: number }> {
  const { data } = await api.post("/api/v1/audit/verify/acknowledge-range",
    { fromSeq, toSeq, note });
  return data;
}
