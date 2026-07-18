import { api } from "./client";

// Compliance evidence exports (CSV). Downloads flow through axios so the bearer
// token is sent; the response blob is saved via a temporary object URL.

export type ReportKind = "access" | "audit" | "certificates" | "scans";

export async function downloadReport(kind: ReportKind, from: string, to: string): Promise<void> {
  const { data, headers } = await api.get(`/api/v1/reports/${kind}.csv`, {
    params: { from, to },
    responseType: "blob",
  });
  const blob = new Blob([data as BlobPart], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const cd = (headers["content-disposition"] as string | undefined) ?? "";
  const match = cd.match(/filename="?([^"]+)"?/);
  a.download = match?.[1] || `fleet-${kind}-${from}-${to}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
