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
  // Part of Provenance itself on this host. Shown — what the instance runs, and
  // what is wrong with those images, is exactly what an operator should see —
  // but never offered for a rollout: this application is upgraded by signed
  // bundle, which verifies the signature, backs up the database, applies
  // migrations and keeps a rollback.
  protected?: boolean;
}

export interface ImageUpdate {
  repository: string;
  tag: string;
  // True when this tag comes from a compose file rather than a running
  // container. The two behave in opposite ways: a rollout of a running :latest
  // whose compose names a version can only skip, while a rollout of the declared
  // row rewrites the file and recreates the container.
  declared?: boolean;
  // What the tag points at in the registry now.
  digest?: string;
  // A newer tag, when one was found AND could be ordered confidently. Empty is a
  // real answer; `note` says whether that means "nothing newer" or "these tags
  // cannot be ordered", which are different and must not look the same.
  latestTag?: string;
  note?: string;
  error?: string;
  // Empty when no registry has been asked about this image yet — it is running,
  // but the check has not reached it. Not the same as a check that found nothing.
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

// Forced by default: somebody pressing the button is asking because they believe
// the answer has changed, usually because they just changed it. Pass force=false
// for a pass that respects the twelve-hour freshness window, which is what a
// script polling this should do.
export async function checkContainerUpdates(force = true): Promise<{ status: string; note?: string }> {
  const { data } = await api.post<{ status: string; note?: string }>(
    "/api/v1/container-updates/check", null, { params: force ? undefined : { force: 0 } });
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
  images?: RolloutImage[];
  // The list carries only the count; the detail view carries the images.
  imageCount?: number;
  createdAt: string;
  createdBy?: string;
  hosts?: UpdateRolloutHost[];
  counts?: Record<string, number>;
}

export interface RolloutImage {
  repository: string;
  fromTag: string;
  toTag: string;
  targetDigest?: string;
}

export interface CreateRolloutRequest {
  repository?: string;
  fromTag?: string;
  toTag?: string;
  targetDigest?: string;
  // Several images in one rollout, paced as one operation. Ten separate rollouts
  // would each pace themselves, so a canary of one would mean ten hosts taking
  // an unproven update at the same time — which is not a canary.
  images?: RolloutImage[];
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

// Clears finished rollouts from the history. The containers they updated are
// unaffected — this removes the record, not the state.
//
// One request rather than a delete per id: clearing thirty rollouts should not
// be thirty requests that can half-fail and leave the list in a state nobody
// asked for.
export async function clearFinishedRollouts(): Promise<{ deleted: number }> {
  const { data } = await api.delete<{ deleted: number }>(
    "/api/v1/container-update-rollouts");
  return data;
}

export async function deleteRollout(id: string): Promise<void> {
  await api.delete(`/api/v1/container-update-rollouts/${id}`);
}

export async function rolloutAction(
  id: string, action: "pause" | "resume" | "cancel",
): Promise<{ state: string }> {
  const { data } = await api.post<{ state: string }>(
    `/api/v1/container-update-rollouts/${id}/${action}`);
  return data;
}
