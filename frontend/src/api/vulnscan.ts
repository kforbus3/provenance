import { api } from "./client";

// Vulnerability scanning: match a host's installed packages against a CVE database
// (Anchore Grype) and report findings with CVSS scores.
//
// Scan counts are DISTINCT CVEs; findings are per CVE-on-package, so a scan's
// findings list is normally longer than its total.

// Whether a fix exists at all — an absent fixedVersion covers both "not fixed yet"
// and "will never be fixed", which triage treats very differently.
export type FixState = "fixed" | "not-fixed" | "wont-fix" | "unknown";

export interface VulnScan {
  id: string;
  hostId: string;
  hostname?: string;
  requester: string;
  scheduled: boolean;
  status: string; // pending|running|completed|failed
  error?: string;
  dbBuiltAt?: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  negligible: number;
  unknown: number;
  fixable: number;
  wontFix: number;
  maxCvss: number;
  startedAt?: string;
  finishedAt?: string;
  createdAt: string;
}

export interface VulnFinding {
  cve: string;
  package: string;
  installedVersion: string;
  fixedVersion?: string;
  fixState?: FixState;
  severity: string;
  cvssScore: number;
  cvssVector?: string;
  dataSource?: string;
  description?: string;
  // How to fix this finding on the host: "update" (apt/dnf upgrade), "remove" (orphaned
  // package installed but in no repo — purge it), "unavailable" (fix exists upstream but
  // not offered here: held / no-DSA / needs OS upgrade), or "" (undetermined).
  remediation?: string;
}

export async function triggerVulnScan(
  target: { hostId?: string; groupId?: string; hostIds?: string[] },
): Promise<string[]> {
  const { data } = await api.post<{ scanIds: string[] }>("/api/v1/vuln-scans", target);
  return data.scanIds ?? [];
}

export async function listVulnScans(hostId?: string): Promise<VulnScan[]> {
  const { data } = await api.get<{ scans: VulnScan[] }>("/api/v1/vuln-scans", {
    params: hostId ? { hostId } : undefined,
  });
  return data.scans ?? [];
}

export async function clearFailedVulnScans(): Promise<number> {
  const { data } = await api.delete<{ deleted: number }>("/api/v1/vuln-scans/failed");
  return data.deleted ?? 0;
}

export async function latestVulnScans(): Promise<VulnScan[]> {
  const { data } = await api.get<{ scans: VulnScan[] }>("/api/v1/vuln-scans/latest");
  return data.scans ?? [];
}

export async function getVulnScan(id: string): Promise<{ scan: VulnScan; findings: VulnFinding[] }> {
  const { data } = await api.get<{ scan: VulnScan; findings: VulnFinding[] }>(`/api/v1/vuln-scans/${id}`);
  return data;
}

export async function vulnDbStatus(): Promise<string> {
  const { data } = await api.get<{ status: string }>("/api/v1/vuln-scans/db");
  return data.status ?? "";
}

export async function vulnDbUpdate(): Promise<string> {
  const { data } = await api.post<{ output: string }>("/api/v1/vuln-scans/db/update");
  return data.output ?? "";
}

export async function vulnDbImport(file: File): Promise<string> {
  const { data } = await api.post<{ output: string }>("/api/v1/vuln-scans/db/import", file, {
    headers: { "Content-Type": "application/gzip" },
  });
  return data.output ?? "";
}

// --- MSRC (Windows CVE mapping) ---

export interface MsrcStatus {
  count: number;
  releases: number;
  latestRelease?: string;
  importedAt?: string;
}

export async function msrcStatus(): Promise<MsrcStatus> {
  const { data } = await api.get<MsrcStatus>("/api/v1/vuln-scans/msrc");
  return data;
}

export async function msrcUpdate(): Promise<number> {
  const { data } = await api.post<{ entries: number }>("/api/v1/vuln-scans/msrc/update");
  return data.entries ?? 0;
}

export async function msrcImport(file: File): Promise<number> {
  const { data } = await api.post<{ entries: number }>("/api/v1/vuln-scans/msrc/import", file, {
    headers: { "Content-Type": "application/octet-stream" },
  });
  return data.entries ?? 0;
}
