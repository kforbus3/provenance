import { api } from "./client";

// Just-in-time access workflow (/approvals, /approvals/mine,
// /approvals/{id}/decide).

export interface ApprovalRequest {
  id: string;
  requesterId: string;
  requester?: string;
  targetKind: string; // host|group
  hostId?: string;
  groupId?: string;
  targetName?: string;
  reason: string;
  ticketRef?: string;
  requestedSecs: number;
  status: string; // pending|approved|denied
  decidedBy?: string;
  decidedByName?: string;
  decidedAt?: string;
  decisionNote?: string;
  grantedSecs?: number;
  createdAt: string;
}

export interface CreateApprovalInput {
  reason: string;
  targetKind: "host" | "group";
  hostId?: string;
  groupId?: string;
  requestedSecs: number;
  ticketRef?: string;
}

export interface DecideInput {
  decision: "approve" | "deny";
  note?: string;
  grantedSecs?: number;
}

export interface RequestTarget {
  id: string;
  name: string;
  environment?: string;
}

// Server-side search for the access-request picker. Returns up to ~50 matching
// hosts or groups (by name), already excluding ones the requester can reach.
export async function searchRequestTargets(
  kind: "host" | "group",
  q: string,
): Promise<RequestTarget[]> {
  const { data } = await api.get<{ targets: RequestTarget[] }>("/api/v1/approvals/targets", {
    params: { kind, q: q || undefined },
  });
  return data.targets ?? [];
}

export async function listApprovals(status?: string): Promise<ApprovalRequest[]> {
  const { data } = await api.get<{ approvals: ApprovalRequest[] }>("/api/v1/approvals", {
    params: status ? { status } : undefined,
  });
  return data.approvals;
}

export async function listMyApprovals(status?: string): Promise<ApprovalRequest[]> {
  const { data } = await api.get<{ approvals: ApprovalRequest[] }>("/api/v1/approvals/mine", {
    params: status ? { status } : undefined,
  });
  return data.approvals;
}

export async function createApproval(input: CreateApprovalInput): Promise<ApprovalRequest> {
  const { data } = await api.post<ApprovalRequest>("/api/v1/approvals", input);
  return data;
}

export async function decideApproval(id: string, input: DecideInput): Promise<ApprovalRequest> {
  const { data } = await api.post<ApprovalRequest>(`/api/v1/approvals/${id}/decide`, input);
  return data;
}
