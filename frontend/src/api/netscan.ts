import { api } from "./client";

// Network vulnerability scanning: the half of vulnerability scanning grype cannot
// see. A package scan reports what is INSTALLED; a network scan reports what a host
// EXPOSES -- which ports answer, from which path, what is serving on them, and
// whether that service is vulnerable or misconfigured.
//
// A managed host is scanned on each path it has: its LAN address (what its network
// can reach) and its overlay address (what the jump host can reach). Range scans
// cover devices Provenance does not manage.

export type NetPath = "lan" | "overlay" | "range";

// "unreachable" is its own state, never "completed with nothing found": an address
// that did not answer was not assessed.
export type NetScanStatus = "pending" | "running" | "completed" | "unreachable" | "failed";

export interface NetListener {
  proto: string;
  address: string;
  port: number;
  process?: string;
  pid?: number;
  exe?: string;
  package?: string;
  libPackages?: string[];
  exposed: boolean;
}

export interface NetDetection {
  templateId: string;
  name: string;
  port?: number;
}

export interface NetService {
  port: number;
  proto: string;
  service?: string;
  product?: string;
  version?: string;
  tls: boolean;
  cpes?: string[];
  detections?: NetDetection[];
  process?: string;
  // Reachable, but the host's own listener list has no socket on this port.
  unexpected: boolean;
}

export type Corroboration = "confirmed" | "banner-only" | "";

export interface NetFinding {
  id: string;
  templateId: string;
  name: string;
  severity: string; // critical|high|medium|low|unknown
  port: number;
  proto: string;
  matchedAt?: string;
  cves?: string[];
  cwes?: string[];
  cvssScore: number;
  cvssVector?: string;
  description?: string;
  remediation?: string;
  references?: string[];
  extracted?: string[];
  tags?: string[];
  // Against the host's package scan: "confirmed" when it reports the same CVE;
  // "banner-only" when it -- knowing the real, possibly backported, version -- does
  // not, which usually means a false positive.
  corroboration?: Corroboration;
}

export interface NetScan {
  id: string;
  runId: string;
  hostId?: string;
  hostname?: string;
  rangeId?: string;
  rangeName?: string;
  target: string;
  path: NetPath;
  requester: string;
  scheduled: boolean;
  status: NetScanStatus;
  error?: string;
  reason?: string;
  templatesVersion?: string;
  openPorts: number;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unexpected: number;
  listeners?: NetListener[];
  // Whether the host's own listener list was collected. Without it nothing can be
  // called unexpected, and "not listening" cannot be told from "not asked".
  listenersKnown: boolean;
  warnings?: string[];
  durationSec: number;
  startedAt?: string;
  finishedAt?: string;
  createdAt: string;
  services?: NetService[];
  findings?: NetFinding[];
}

export interface ExposedService {
  scanId: string;
  hostId?: string;
  hostname?: string;
  target: string;
  path: NetPath;
  scannedAt: string;
  port: number;
  proto: string;
  service?: string;
  product?: string;
  version?: string;
  tls: boolean;
  process?: string;
  unexpected: boolean;
  findings: number;
  worstSeverity?: string;
}

export interface NetScanRange {
  id: string;
  name: string;
  cidr: string;
  note: string;
  enabled: boolean;
  createdAt: string;
  lastScan?: string;
  lastLive: number;
}

export interface TemplatesStatus {
  present: boolean;
  version?: string;
  source?: string;
  updatedAt?: string;
  excludedCredentialTemplates: number;
}

export interface NetScanStatusInfo {
  configured: boolean;
  health?: { ok: boolean; overlay: "ok" | "no-route" | "not-configured"; templates: boolean };
  healthError?: string;
  templates?: TemplatesStatus;
  templatesError?: string;
  templatesStale: boolean;
}

export interface StartedRun {
  hostId: string;
  hostname: string;
  runId: string;
  scanIds: string[];
}

export interface SkippedHost {
  hostId: string;
  hostname: string;
  reason: string;
}

export async function triggerNetScan(
  target: { hostId?: string; groupId?: string; hostIds?: string[] },
): Promise<{ started: StartedRun[]; skipped: SkippedHost[] }> {
  const { data } = await api.post<{ started: StartedRun[]; skipped: SkippedHost[] }>("/api/v1/net-scans", target);
  return { started: data.started ?? [], skipped: data.skipped ?? [] };
}

export async function listNetScans(filter: { hostId?: string; rangeId?: string } = {}): Promise<NetScan[]> {
  const { data } = await api.get<{ scans: NetScan[] }>("/api/v1/net-scans", { params: filter });
  return data.scans ?? [];
}

export async function latestNetScans(): Promise<NetScan[]> {
  const { data } = await api.get<{ scans: NetScan[] }>("/api/v1/net-scans/latest");
  return data.scans ?? [];
}

export async function exposedServices(): Promise<ExposedService[]> {
  const { data } = await api.get<{ services: ExposedService[] }>("/api/v1/net-scans/exposed");
  return data.services ?? [];
}

export async function hostNetScans(hostId: string): Promise<NetScan[]> {
  const { data } = await api.get<{ scans: NetScan[] }>(`/api/v1/net-scans/hosts/${hostId}`);
  return data.scans ?? [];
}

export async function getNetScan(id: string): Promise<NetScan> {
  const { data } = await api.get<{ scan: NetScan }>(`/api/v1/net-scans/${id}`);
  return data.scan;
}

export async function netScanStatus(): Promise<NetScanStatusInfo> {
  const { data } = await api.get<NetScanStatusInfo>("/api/v1/net-scans/status");
  return data;
}

export async function clearFailedNetScans(): Promise<number> {
  const { data } = await api.delete<{ deleted: number }>("/api/v1/net-scans/failed");
  return data.deleted ?? 0;
}

export async function netTemplatesUpdate(): Promise<TemplatesStatus> {
  // A template download takes minutes; the backend detaches from its own request
  // deadline, so the client must not give up first either.
  const { data } = await api.post<TemplatesStatus>("/api/v1/net-scans/templates/update", null, { timeout: 25 * 60_000 });
  return data;
}

export async function netTemplatesImport(file: File, version?: string): Promise<TemplatesStatus> {
  const { data } = await api.post<TemplatesStatus>("/api/v1/net-scans/templates/import", file, {
    headers: { "Content-Type": "application/gzip" },
    params: version ? { version } : undefined,
    timeout: 25 * 60_000,
  });
  return data;
}

export async function listNetScanRanges(): Promise<NetScanRange[]> {
  const { data } = await api.get<{ ranges: NetScanRange[] }>("/api/v1/net-scan-ranges");
  return data.ranges ?? [];
}

export interface RangeInput {
  name: string;
  cidr: string;
  note: string;
  enabled: boolean;
}

export async function createNetScanRange(r: RangeInput): Promise<NetScanRange> {
  const { data } = await api.post<NetScanRange>("/api/v1/net-scan-ranges", r);
  return data;
}

export async function updateNetScanRange(id: string, r: RangeInput): Promise<NetScanRange> {
  const { data } = await api.put<NetScanRange>(`/api/v1/net-scan-ranges/${id}`, r);
  return data;
}

export async function deleteNetScanRange(id: string): Promise<void> {
  await api.delete(`/api/v1/net-scan-ranges/${id}`);
}

export async function scanNetScanRange(id: string): Promise<string> {
  const { data } = await api.post<{ runId: string }>(`/api/v1/net-scan-ranges/${id}/scan`);
  return data.runId;
}

// --- presentation helpers (pure; tested) ---------------------------------------------

export const NET_SEV_ORDER = ["critical", "high", "medium", "low", "unknown"];

export function netSevColor(sev?: string): "error" | "warning" | "info" | "default" {
  switch ((sev ?? "").toLowerCase()) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "info";
    default:
      return "default";
  }
}

export function pathLabel(p: NetPath | string): string {
  switch (p) {
    case "lan":
      return "LAN";
    case "overlay":
      return "Overlay";
    case "range":
      return "Range";
    default:
      return p;
  }
}

// overlayOnly finds services a host exposes on its overlay path but not on its LAN
// path: something the host trusts the jump host -- and so whoever controls it --
// with, which its own network cannot reach. Only for hosts scanned on BOTH paths;
// a host with no LAN scan says nothing about what its LAN exposes.
export function overlayOnly(services: ExposedService[]): Set<string> {
  const lan = new Map<string, Set<string>>();
  const hasOverlay = new Set<string>();
  for (const s of services) {
    const host = s.hostId ?? s.target;
    if (s.path === "lan") {
      if (!lan.has(host)) lan.set(host, new Set());
      lan.get(host)!.add(`${s.proto}/${s.port}`);
    } else if (s.path === "overlay") {
      hasOverlay.add(host);
    }
  }
  const out = new Set<string>();
  for (const s of services) {
    const host = s.hostId ?? s.target;
    if (s.path === "overlay" && hasOverlay.has(host) && lan.has(host) && !lan.get(host)!.has(`${s.proto}/${s.port}`)) {
      out.add(`${s.scanId}:${s.proto}/${s.port}`);
    }
  }
  return out;
}

// listeningNotReachable is the host's exposed sockets that no scan path reached --
// the firewall doing its job, shown so "not in the exposure list" is not mistaken
// for "not listening".
export function listeningNotReachable(scan: NetScan, allScans: NetScan[]): NetListener[] {
  if (!scan.listenersKnown || !scan.listeners) return [];
  const reached = new Set<string>();
  for (const s of allScans) {
    if (s.hostId !== scan.hostId || s.status !== "completed") continue;
    for (const sv of s.services ?? []) reached.add(`${sv.proto}/${sv.port}`);
  }
  const seen = new Set<string>();
  return scan.listeners.filter((l) => {
    const k = `${l.proto}/${l.port}`;
    if (!l.exposed || reached.has(k) || seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
