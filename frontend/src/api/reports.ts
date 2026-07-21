import { api } from "./client";

// Compliance evidence exports (CSV). Downloads flow through axios so the bearer
// token is sent; the response blob is saved via a temporary object URL.

export type ReportKind = "access" | "audit" | "certificates" | "scans" | "vulnerabilities";

export async function downloadReport(kind: ReportKind, from: string, to: string): Promise<void> {
  const { data, headers } = await api.get(`/api/v1/reports/${kind}.csv`, {
    params: { from, to },
    responseType: "blob",
  });
  saveBlob(data as BlobPart, "text/csv", headers["content-disposition"] as string | undefined,
    `fleet-${kind}-${from}-${to}.csv`);
}

// downloadEvidencePack fetches the single-file PDF compliance evidence pack (cover +
// audit-integrity attestation + summary statistics) for the date range and saves it.
export async function downloadEvidencePack(from: string, to: string): Promise<void> {
  const { data, headers } = await api.get(`/api/v1/reports/evidence-pack.pdf`, {
    params: { from, to },
    responseType: "blob",
  });
  saveBlob(data as BlobPart, "application/pdf", headers["content-disposition"] as string | undefined,
    `fleet-evidence-pack-${from}-${to}.pdf`);
}

function saveBlob(data: BlobPart, type: string, contentDisposition: string | undefined, fallback: string) {
  const blob = new Blob([data], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const match = (contentDisposition ?? "").match(/filename="?([^"]+)"?/);
  a.download = match?.[1] || fallback;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
