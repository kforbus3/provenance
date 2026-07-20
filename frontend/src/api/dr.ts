import { api } from "./client";

export interface DRConfig {
  role: "standalone" | "primary" | "standby";
  peerUrl: string;
  failoverWebhook: string;
  failbackWebhook: string;
}

export interface DRReplica {
  clientAddr: string;
  state: string;
  syncState: string;
  lagBytes: number | null;
}

export interface DBReplication {
  inRecovery: boolean;
  replayLagSeconds: number | null;
  replicas: DRReplica[];
}

export interface PeerStatus {
  configured: boolean;
  reachable: boolean;
  detail: string;
}

export interface DRStatus {
  config: DRConfig;
  replication: DBReplication;
  peer: PeerStatus;
}

export interface DRActionResult {
  ok: boolean;
  steps: { step: string; ok: boolean; error?: string; skipped?: string }[];
}

export interface DRMode {
  standby: boolean;
  inRecovery?: boolean;
  replayLagSeconds?: number | null;
  promotionEnabled?: boolean;
}

// getDRMode is called on app load (unauthenticated) to detect whether this instance
// is a read-only DR standby, so the SPA can show the break-glass console instead of
// attempting a normal login the replica database can't service.
export async function getDRMode(): Promise<DRMode> {
  const { data } = await api.get<DRMode>("/api/v1/dr/mode");
  return data;
}

// standbyPromote promotes the standby's database to primary (break-glass; requires
// the DR token). The instance then restarts into normal mode.
export async function standbyPromote(token: string): Promise<{ ok: boolean; message: string }> {
  const { data } = await api.post<{ ok: boolean; message: string }>("/api/v1/dr/standby/promote", { token });
  return data;
}

export async function getDRStatus(): Promise<DRStatus> {
  const { data } = await api.get<DRStatus>("/api/v1/dr/status");
  return data;
}

export async function setDRConfig(cfg: DRConfig): Promise<void> {
  await api.put("/api/v1/dr/config", cfg);
}

export async function drFailover(promoteLocalDb: boolean): Promise<DRActionResult> {
  const { data } = await api.post<DRActionResult>("/api/v1/dr/failover", { promoteLocalDb });
  return data;
}

export async function drFailback(promoteLocalDb: boolean): Promise<DRActionResult> {
  const { data } = await api.post<DRActionResult>("/api/v1/dr/failback", { promoteLocalDb });
  return data;
}

export async function drPromote(): Promise<{ ok: boolean }> {
  const { data } = await api.post<{ ok: boolean }>("/api/v1/dr/promote");
  return data;
}
