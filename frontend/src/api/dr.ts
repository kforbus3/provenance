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
