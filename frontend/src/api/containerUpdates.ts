import { api } from "./client";

// What registries say is available for the images the fleet is running.
//
// Two independent signals, and they answer different questions:
//   latestTag — a newer version tag exists in the repository
//   a moved digest — the tag a host runs points at different bytes than the
//     host has, which is what a base-image rebuild looks like
//
// A tool that reported only the first would call a host current while it runs a
// months-old build of the same version number.

export interface ImageUpdateHost {
  hostId: string;
  hostname: string;
  digest?: string;
  container?: string;
  // Per host, not per image: mid-rollout some hosts have the new bytes and some
  // do not, and an image-level flag would hide exactly that.
  stale: boolean;
}

export interface ImageUpdate {
  repository: string;
  tag: string;
  // What the tag points at in the registry now.
  digest?: string;
  // A newer tag, when one was found AND could be ordered confidently. Empty is a
  // real answer; `note` says whether that means "nothing newer" or "these tags
  // cannot be ordered", which are different and must not look the same.
  latestTag?: string;
  note?: string;
  error?: string;
  checkedAt: string;
  // Nullable, not just empty: Go marshals a nil slice as `null`. An image no host
  // runs any more is ordinary — the tags an upgrade just replaced keep their rows
  // until the next check pass prunes them — so the type says so and callers go
  // through hostsOf().
  hosts: ImageUpdateHost[] | null;
}

export async function listContainerUpdates(): Promise<ImageUpdate[]> {
  const { data } = await api.get<{ updates: ImageUpdate[] }>("/api/v1/container-updates");
  return data.updates ?? [];
}

export async function checkContainerUpdates(): Promise<{ status: string; note?: string }> {
  const { data } = await api.post<{ status: string; note?: string }>(
    "/api/v1/container-updates/check");
  return data;
}

// --- staged rollouts ---------------------------------------------------------

// An operator says "move nginx:1.24 to 1.27, one host first, then five at a
// time, and stop if two fail". The same pacing rules image rollouts obey.

export interface UpdateRolloutHost {
  hostId: string;
  hostname?: string;
  // pending | applying | verified | failed | skipped
  state: string;
  error?: string;
  attempts: number;
  changedAt: string;
}

export interface UpdateRollout {
  id: string;
  repository: string;
  fromTag: string;
  // Equal to fromTag when only the DIGEST moved — a rebuild of the same version,
  // which is a real update with nothing to rewrite in the compose file.
  toTag: string;
  targetDigest?: string;
  // running | paused | halted | completed | cancelled
  state: string;
  haltReason?: string;
  canary: number;
  batchSize: number;
  soakSeconds: number;
  maxFailures: number;
  windowStart?: string;
  windowEnd?: string;
  windowDays?: number[];
  canaryDoneAt?: string;
  createdAt: string;
  createdBy?: string;
  hosts?: UpdateRolloutHost[];
  counts?: Record<string, number>;
}

export interface CreateRolloutRequest {
  repository: string;
  fromTag: string;
  toTag: string;
  targetDigest?: string;
  // Empty means every host currently running the image. Resolved once, when the
  // rollout is created — a rollout whose membership changed underneath it could
  // never be complete.
  hosts?: string[];
  canary: number;
  batchSize: number;
  soakSeconds: number;
  maxFailures: number;
  windowStart?: string;
  windowEnd?: string;
  windowDays?: number[];
}

export async function listRollouts(): Promise<UpdateRollout[]> {
  const { data } = await api.get<{ rollouts: UpdateRollout[] }>(
    "/api/v1/container-update-rollouts");
  return data.rollouts ?? [];
}

export async function getRollout(id: string): Promise<UpdateRollout> {
  const { data } = await api.get<UpdateRollout>(`/api/v1/container-update-rollouts/${id}`);
  return data;
}

export async function createRollout(req: CreateRolloutRequest): Promise<UpdateRollout> {
  const { data } = await api.post<UpdateRollout>("/api/v1/container-update-rollouts", req);
  return data;
}

export async function rolloutAction(
  id: string, action: "pause" | "resume" | "cancel",
): Promise<{ state: string }> {
  const { data } = await api.post<{ state: string }>(
    `/api/v1/container-update-rollouts/${id}/${action}`);
  return data;
}
