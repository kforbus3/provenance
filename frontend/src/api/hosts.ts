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
  enrolled: boolean;
  createdAt: string;
  updatedAt: string;
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
