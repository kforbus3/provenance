import { api } from "./client";

// Host inventory types mirror backend/internal/models/models.go (camelCase JSON).
export interface HostInventory {
  osName: string;
  osVersion: string;
  kernelVersion: string;
  architecture: string;
  sshVersion: string;
  cpuCount: number;
  memoryMb: number;
  collectedAt?: string;
  updatesAvailable?: number;
  securityUpdates?: number;
  updatesCheckedAt?: string;
}

export interface HostStatus {
  status: string; // online|offline|unknown
  sshOk: boolean;
  wgOk: boolean;
  latencyMs?: number;
  uptimeSeconds?: number;
  lastSuccessAt?: string;
  lastFailureAt?: string;
  lastError?: string;
  checkedAt?: string;
}

export interface DiskFS {
  mount: string;
  sizeBytes: number;
  usedBytes: number;
  availBytes: number;
  usePct: number;
}

export interface NetInterface {
  name: string;
  addrs: string[];
}

export interface HostNetwork {
  interfaces?: NetInterface[];
  primaryIp?: string;
  defaultGateway?: string;
  defaultIface?: string;
}

export interface HostMetrics {
  disk?: DiskFS[];
  minDiskFreePct?: number;
  memTotalMb: number;
  memAvailableMb: number;
  memUsedPct?: number;
  load1?: number;
  load5?: number;
  load15?: number;
  loadPerCore?: number;
  network?: HostNetwork;
  primaryIp?: string;
  collectedAt?: string;
}

export interface Host {
  id: string;
  hostname: string;
  description: string;
  environment: string;
  owner: string;
  address?: string;
  wgAddress?: string;
  sshPort: number;
  sshUser: string;
  tags: string[];
  authMethod: string; // fleet_cert | vault_password | vault_ssh_key
  credentialId?: string | null;
  protocol: string; // ssh | rdp
  rdpPort: number;
  rdpOptions?: RDPOptions;
  enrolled: boolean;
  createdAt: string;
  updatedAt: string;
  maintenanceUntil?: string;
  groups?: string[];
  inventory?: HostInventory;
  status?: HostStatus;
  metrics?: HostMetrics;
}

export interface HostListResponse {
  hosts: Host[];
  count: number;
}

// HostInput is the create/update payload accepted by the backend.
export interface HostInput {
  hostname: string;
  description: string;
  environment: string;
  owner: string;
  address: string;
  wgAddress: string;
  sshPort: number;
  sshUser: string;
  tags: string[];
  authMethod?: string;
  credentialId?: string | null;
  protocol?: string;
  rdpPort?: number;
  rdpOptions?: RDPOptions;
}

// RDPOptions are per-host display/security and clipboard settings for RDP hosts.
// Zero/empty values mean "use guacd defaults". Clipboard is off unless opted in.
export interface RDPOptions {
  security?: string; // any | nla | tls | rdp | vmconnect
  colorDepth?: number; // 0 | 8 | 16 | 24 | 32
  width?: number; // 0 = fit to the browser window
  height?: number;
  dpi?: number; // 0 = default (96)
  disableAudio?: boolean;
  enableTheming?: boolean; // wallpaper + theming + font smoothing
  domain?: string;
  clipboardCopy?: boolean; // allow remote -> local
  clipboardPaste?: boolean; // allow local -> remote
  enableDrive?: boolean; // expose a virtual drive for file transfer
  driveUpload?: boolean; // allow browser -> drive
  driveDownload?: boolean; // allow drive -> browser
}

export async function listHosts(): Promise<HostListResponse> {
  const { data } = await api.get<HostListResponse>("/api/v1/hosts");
  return data;
}

export async function getHost(id: string): Promise<Host> {
  const { data } = await api.get<Host>(`/api/v1/hosts/${id}`);
  return data;
}

export async function createHost(input: HostInput): Promise<Host> {
  const { data } = await api.post<Host>("/api/v1/hosts", input);
  return data;
}

export async function updateHost(id: string, input: HostInput): Promise<Host> {
  const { data } = await api.put<Host>(`/api/v1/hosts/${id}`, input);
  return data;
}

export async function deleteHost(id: string): Promise<void> {
  await api.delete(`/api/v1/hosts/${id}`);
}

export interface NextWG {
  nextWgAddress: string;
  subnet: string;
  jumpEndpoint: string;
  exhausted?: boolean;
}

// nextWGAddress returns what auto-assignment would pick from the overlay pool.
export async function nextWGAddress(): Promise<NextWG> {
  const { data } = await api.get<NextWG>("/api/v1/hosts/wg/next");
  return data;
}

export type HostStatusStats = Record<string, number>;

export interface WindowsSoftware {
  name: string;
  version?: string;
  publisher?: string;
  collectedAt: string;
}

export async function listHostSoftware(id: string): Promise<WindowsSoftware[]> {
  const { data } = await api.get<{ software: WindowsSoftware[] }>(`/api/v1/hosts/${id}/software`);
  return data.software ?? [];
}

export async function refreshHostFacts(id: string): Promise<void> {
  await api.post(`/api/v1/hosts/${id}/refresh`);
}

export async function setHostMaintenance(id: string, minutes: number): Promise<{ maintenanceUntil: string }> {
  const { data } = await api.post<{ maintenanceUntil: string }>(`/api/v1/hosts/${id}/maintenance`, { minutes });
  return data;
}

export async function clearHostMaintenance(id: string): Promise<void> {
  await api.delete(`/api/v1/hosts/${id}/maintenance`);
}

// maintenanceActive reports whether a host is currently in a maintenance window.
export function maintenanceActive(h: { maintenanceUntil?: string }): boolean {
  return !!h.maintenanceUntil && new Date(h.maintenanceUntil).getTime() > Date.now();
}

// Bulk actions over an ad-hoc host selection. Each returns the number of hosts the
// action was applied to (the server filters to hosts the caller can access).
export async function bulkRefreshHosts(hostIds: string[]): Promise<number> {
  const { data } = await api.post<{ applied: number }>("/api/v1/hosts/bulk/refresh", { hostIds });
  return data.applied;
}
export async function bulkHostMaintenance(hostIds: string[], minutes: number): Promise<number> {
  // minutes <= 0 clears the maintenance window on every selected host.
  const { data } = await api.post<{ applied: number }>("/api/v1/hosts/bulk/maintenance", { hostIds, minutes });
  return data.applied;
}
export async function bulkHostTags(
  hostIds: string[], tags: { add?: string[]; remove?: string[] },
): Promise<number> {
  const { data } = await api.post<{ applied: number }>("/api/v1/hosts/bulk/tags", { hostIds, ...tags });
  return data.applied;
}

export async function getHostStatusStats(): Promise<HostStatusStats> {
  const { data } = await api.get<HostStatusStats>("/api/v1/hosts/stats/status");
  return data;
}

// --- Host access management (groups + direct users) ---

export interface HostAccessUser {
  id: string;
  username: string;
  displayName?: string;
  email?: string;
}

export interface HostAccess {
  groups: string[];
  users: HostAccessUser[];
}

export async function getHostAccess(id: string): Promise<HostAccess> {
  const { data } = await api.get<HostAccess>(`/api/v1/hosts/${id}/access`);
  return { groups: data.groups ?? [], users: data.users ?? [] };
}

export async function addHostUser(hostId: string, userId: string): Promise<void> {
  await api.post(`/api/v1/hosts/${hostId}/users/${userId}`);
}

export async function removeHostUser(hostId: string, userId: string): Promise<void> {
  await api.delete(`/api/v1/hosts/${hostId}/users/${userId}`);
}

export async function addHostGroup(hostId: string, groupId: string): Promise<void> {
  await api.post(`/api/v1/hosts/${hostId}/groups/${groupId}`);
}

export async function removeHostGroup(hostId: string, groupId: string): Promise<void> {
  await api.delete(`/api/v1/hosts/${hostId}/groups/${groupId}`);
}

export interface EnrollmentStep {
  name: string;
  status: string;
  detail?: string;
  timestamp: string;
}

export interface EnrollmentResult {
  job: { id: string; status: string; steps: EnrollmentStep[]; error?: string };
  wgAddress: string;
  hostPublicKey: string;
}

export interface EnrollParams {
  // "password" bootstraps a host with no prior setup (installs CA trust +
  // WireGuard over an SSH password); "key" bootstraps using an existing SSH
  // private key already trusted in the host's authorized_keys (for hosts with
  // password auth disabled); "trusted" uses the session certificate on a host
  // that already trusts the Fleet CA.
  method: "password" | "key" | "agent" | "trusted";
  bootstrapUser?: string;
  password?: string;
  // PEM private key + optional passphrase, for the "key" method.
  privateKey?: string;
  keyPassphrase?: string;
  // sudo password, when the bootstrap user has password-required sudo.
  sudoPassword?: string;
  // jump host's public WireGuard endpoint (host:port) the managed host dials.
  wgEndpoint?: string;
  // Route the bootstrap SSH connection through the jump host (for hosts the
  // backend can't reach directly but the jump host can).
  viaJump?: boolean;
  // Skip WireGuard: the host is directly reachable from the jump host (same LAN,
  // or the host that runs Fleet itself), so no overlay is set up.
  skipWireGuard?: boolean;
  // VPN overlay transport for this host: "" / undefined = deployment default,
  // otherwise wireguard | openvpn | strongswan. openvpn/strongswan are the FIPS
  // (certificate-authenticated) overlays.
  overlay?: "" | "wireguard" | "openvpn" | "strongswan";
}

// Enroll installs CA trust + WireGuard on the host (when bootstrapping), sets up
// the tunnel + jump-host peer, and validates per-user certificate login.
export async function enrollHost(id: string, params: EnrollParams): Promise<EnrollmentResult> {
  const { data } = await api.post<EnrollmentResult>(`/api/v1/hosts/${id}/enroll`, params);
  return data;
}

// finishEnroll completes the no-install (ssh-pipe) flow: the operator ran the
// bootstrap script through their own ssh and pastes the host's WireGuard public
// key here; the backend adds the jump-host peer and verifies certificate login.
export async function finishEnroll(id: string, hostPublicKey: string): Promise<EnrollmentResult> {
  const { data } = await api.post<EnrollmentResult>(`/api/v1/hosts/${id}/enroll/finish`, { hostPublicKey });
  return data;
}
