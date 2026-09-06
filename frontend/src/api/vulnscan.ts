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
  // The severity breakdown of the fixable subset — the roll-up's headline numbers.
  // critical/high/medium above count every fix state, so they stay high on a fully
  // patched host and cannot be read as outstanding work.
  fixableCritical: number;
  fixableHigh: number;
  fixableMedium: number;
  // Worst CVSS among fixable CVEs; 0 when nothing is fixable. maxCvss is 10.0 on
  // virtually every Linux host and so tells you nothing.
  fixableMaxCvss: number;
  startedAt?: string;
  finishedAt?: string;
  createdAt: string;
}

export interface VulnFinding {
  cve: string;
  package: string;
  // The source package the CVE was matched against. Distro CVE trackers key on the
  // source, so one source repeats its CVEs across every binary it builds — grouping
  // on this reports components rather than package rows. Absent on scans recorded
  // before it was captured, and on CPE/Windows matches with no upstream.
  sourcePackage?: string;
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

// --- Component attribution ----------------------------------------------
//
// Distro CVE trackers key on the SOURCE package, so grype resolves a binary to its
// source before matching. Two consequences the UI has to handle:
//
//  - One source fans its CVEs out across every binary it builds, so the findings
//    list repeats each CVE per binary. Grouping on the source reports components.
//  - Debian ships the kernel's userspace helpers (cpupower, headers, kbuild,
//    libc-dev) from the `linux` source that kernel CVEs are tracked under, so the
//    entire kernel CVE list arrives attributed to those helpers — while the actual
//    linux-image-* packages match nothing, because Debian's signed images build
//    from linux-signed-amd64, which the tracker does not key on. The findings are
//    real; the attribution is not.

const KERNEL_SOURCES = new Set([
  "linux", "linux-signed", "linux-signed-amd64", "linux-signed-arm64", "linux-latest",
  "kernel", "kernel-rt",
]);

// The binary packages that ARE the kernel, as opposed to helpers built beside it.
const KERNEL_BINARY_PREFIXES = ["linux-image", "kernel-core", "kernel-modules", "kernel-uek"];

// isKernelSourceFinding reports whether a finding is a kernel CVE that landed on a
// non-kernel binary package. Mirrors models.IsKernelSourceFinding on the backend.
export function isKernelSourceFinding(f: VulnFinding): boolean {
  const src = (f.sourcePackage ?? "").trim().toLowerCase();
  if (!KERNEL_SOURCES.has(src)) return false;
  const pkg = (f.package ?? "").trim().toLowerCase();
  return !KERNEL_BINARY_PREFIXES.some((p) => pkg.startsWith(p));
}

// vulnComponent is the name a finding should be reported under: its source package
// when known, else the binary package (scans predating source capture, CPE matches).
export function vulnComponent(f: VulnFinding): string {
  const src = (f.sourcePackage ?? "").trim();
  return src !== "" ? src : f.package;
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

// kernelRelease is the host's running kernel (from its inventory), sent alongside
// the findings because kernel CVEs arrive attributed to whichever userspace helper
// shares the kernel's source package — at THAT package's version, which need not be
// the kernel the host booted. Empty when the host has no collected inventory.
export async function getVulnScan(
  id: string,
): Promise<{ scan: VulnScan; findings: VulnFinding[]; kernelRelease?: string }> {
  const { data } = await api.get<{ scan: VulnScan; findings: VulnFinding[]; kernelRelease?: string }>(
    `/api/v1/vuln-scans/${id}`,
  );
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

// --- SBOM ---------------------------------------------------------------

// downloadHostSbom fetches a host's most recent software bill of materials as a
// CycloneDX 1.5 document.
//
// The filename comes from the server's Content-Disposition so it carries the
// hostname and the collection timestamp — an SBOM is evidence, and one that
// cannot be tied back to a machine and a moment is not much use in a review.
export async function downloadHostSbom(hostId: string, hostname?: string): Promise<void> {
  const { data, headers } = await api.get(
    `/api/v1/vuln-scans/latest/sbom?hostId=${encodeURIComponent(hostId)}`,
    { responseType: "blob" },
  );
  saveSbom(data as BlobPart, headers, `${hostname || hostId}-sbom.cdx.json`);
}

// downloadScanSbom fetches the bill of materials a specific scan collected,
// which is what you want when comparing a host against its own past state.
export async function downloadScanSbom(scanId: string): Promise<void> {
  const { data, headers } = await api.get(`/api/v1/vuln-scans/${scanId}/sbom`, {
    responseType: "blob",
  });
  saveSbom(data as BlobPart, headers, `scan-${scanId}-sbom.cdx.json`);
}

function saveSbom(data: BlobPart, headers: Record<string, unknown>, fallback: string) {
  const blob = new Blob([data], { type: "application/vnd.cyclonedx+json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const cd = (headers["content-disposition"] as string | undefined) ?? "";
  a.download = cd.match(/filename="?([^"]+)"?/)?.[1] || fallback;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}
