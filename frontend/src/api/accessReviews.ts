import { api } from "./client";

// Access certification: snapshot the current access grants, keep or revoke each,
// and produce evidence. Gated by AccessReview.Manage.

export interface ReviewScope {
  type: "all" | "group" | "user";
  groupId?: string;
  userIds?: string[];
}

export interface AccessReview {
  id: string;
  name: string;
  description: string;
  scope: ReviewScope;
  status: "open" | "completed";
  createdBy?: string;
  createdAt: string;
  dueAt?: string;
  completedAt?: string;
  total: number;
  pending: number;
  kept: number;
  revoked: number;
}

export interface AccessReviewItem {
  id: string;
  subjectUser: string;
  subjectIsServiceAccount: boolean;
  grantKind: "group_membership" | "direct_host";
  resourceKind: "group" | "host";
  resourceName: string;
  decision: "pending" | "keep" | "revoke";
  note?: string;
  decidedBy?: string;
  decidedAt?: string;
}

export async function listAccessReviews(): Promise<AccessReview[]> {
  const { data } = await api.get<{ reviews: AccessReview[] }>("/api/v1/access-reviews");
  return data.reviews ?? [];
}

export async function createAccessReview(input: {
  name: string; description: string; scope: ReviewScope; dueInDays?: number;
}): Promise<AccessReview> {
  const { data } = await api.post<AccessReview>("/api/v1/access-reviews", input);
  return data;
}

export async function getAccessReview(id: string): Promise<{ review: AccessReview; items: AccessReviewItem[] }> {
  const { data } = await api.get<{ review: AccessReview; items: AccessReviewItem[] }>(`/api/v1/access-reviews/${id}`);
  return data;
}

export async function decideReviewItem(id: string, itemId: string, decision: "keep" | "revoke", note = ""): Promise<void> {
  await api.post(`/api/v1/access-reviews/${id}/items/${itemId}/decide`, { decision, note });
}

export async function completeAccessReview(id: string): Promise<void> {
  await api.post(`/api/v1/access-reviews/${id}/complete`);
}

export async function downloadAccessReview(id: string): Promise<void> {
  const { data, headers } = await api.get(`/api/v1/access-reviews/${id}/export.csv`, { responseType: "blob" });
  const blob = new Blob([data as BlobPart], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const cd = (headers["content-disposition"] as string | undefined) ?? "";
  a.download = cd.match(/filename="?([^"]+)"?/)?.[1] || `access-review-${id}.csv`;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}
