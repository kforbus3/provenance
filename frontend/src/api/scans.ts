import { api } from "./client";

// OpenSCAP security/compliance scans per host (/hosts/{id}/scan*, /scans/{id}).

export interface HostScan {
  id: string;
  hostId: string;
  requester?: string;
  profile?: string;
  profileTitle?: string;
  benchmark?: string;
  status: string; // pending|running|completed|failed
  score?: number;
  passCount: number;
  failCount: number;
  otherCount: number;
  totalRules: number;
  error?: string;
  skipRules?: string[];
  scheduled?: boolean;
  startedAt?: string;
  finishedAt?: string;
  createdAt: string;
}

export interface ScanProfile {
  id: string;
  title: string;
}

export interface ScanProfilesResponse {
  installed: boolean;
  exact: boolean; // datastream matches the host's exact OS version
  installing: boolean;
  datastream: string;
  profiles: ScanProfile[];
}

// Discover the SCAP profiles available on a host (no install; may be slow as it
// reaches the host over SSH).
export async function listScanProfiles(hostId: string): Promise<ScanProfilesResponse> {
  const { data } = await api.get<ScanProfilesResponse>(`/api/v1/hosts/${hostId}/scan/profiles`);
  return {
    installed: data.installed, exact: data.exact, installing: data.installing,
    datastream: data.datastream, profiles: data.profiles ?? [],
  };
}

// Install the scanner + SCAP content on a host in the background so the profile
// picker can populate before the first scan.
export async function prepareScan(hostId: string): Promise<void> {
  await api.post(`/api/v1/hosts/${hostId}/scan/prepare`, {});
}

// Start a scan. Empty profile -> the host's standard/baseline profile.
export interface StartScanOptions {
  skipExpensiveFsRules?: boolean;
  skipRules?: string[];
}

export async function startScan(hostId: string, profile?: string, opts?: StartScanOptions): Promise<HostScan> {
  const { data } = await api.post<HostScan>(`/api/v1/hosts/${hostId}/scan`, {
    profile: profile ?? "",
    skipExpensiveFsRules: opts?.skipExpensiveFsRules ?? false,
    skipRules: opts?.skipRules ?? [],
  });
  return data;
}

export async function listHostScans(hostId: string): Promise<HostScan[]> {
  const { data } = await api.get<{ scans: HostScan[] }>(`/api/v1/hosts/${hostId}/scans`);
  return data.scans ?? [];
}

export async function getScan(id: string): Promise<HostScan> {
  const { data } = await api.get<HostScan>(`/api/v1/scans/${id}`);
  return data;
}

// URL for the stored HTML report (token-authenticated). Used for direct download
// (download=1 forces an attachment). For in-app viewing we fetch the HTML and
// render it via iframe srcdoc instead of framing this URL, so reverse-proxy
// X-Frame-Options can't block it.
export function scanReportUrl(id: string, token: string, download = false): string {
  const q = new URLSearchParams({ token });
  if (download) q.set("download", "1");
  return `/api/v1/scans/${id}/report?${q.toString()}`;
}

export interface ScanFinding {
  ruleId: string;
  title: string;
  severity?: string;
  result: string;
  accessImpacting: boolean;
}

export interface HostRemediation {
  id: string;
  scanId: string;
  hostId: string;
  requester?: string;
  ruleIds: string[];
  status: string; // pending|running|completed|failed
  exitCode?: number;
  output?: string;
  rescanId?: string;
  error?: string;
  createdAt: string;
}

export interface FindingsResult {
  findings: ScanFinding[];
  // controlPlane is true when this host is one of Fleet's own control-plane
  // hosts (jump host, or tagged/declared), where remediation is extra-dangerous.
  controlPlane: boolean;
}

export async function listFindings(scanId: string): Promise<FindingsResult> {
  const { data } = await api.get<{ findings: ScanFinding[]; controlPlane?: boolean }>(
    `/api/v1/scans/${scanId}/findings`,
  );
  return { findings: data.findings ?? [], controlPlane: Boolean(data.controlPlane) };
}

export async function previewRemediation(scanId: string, ruleIds: string[]): Promise<string> {
  const { data } = await api.post<{ script: string }>(`/api/v1/scans/${scanId}/remediation/preview`, { ruleIds });
  return data.script ?? "";
}

export async function remediate(
  scanId: string,
  ruleIds: string[],
  confirmAccessImpacting: boolean,
  confirmControlPlane: boolean,
): Promise<HostRemediation> {
  const { data } = await api.post<HostRemediation>(`/api/v1/scans/${scanId}/remediate`, {
    ruleIds,
    confirmAccessImpacting,
    confirmControlPlane,
  });
  return data;
}

export async function remediationStatus(id: string): Promise<HostRemediation> {
  const { data } = await api.get<HostRemediation>(`/api/v1/remediations/${id}`);
  return data;
}

// Fetch the report HTML for in-app (sandboxed srcdoc) viewing.
export async function fetchScanReport(id: string, token: string): Promise<string> {
  const { data } = await api.get<string>(`/api/v1/scans/${id}/report`, {
    params: { token }, responseType: "text",
  });
  return data;
}
