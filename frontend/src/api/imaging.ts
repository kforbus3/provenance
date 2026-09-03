import { api } from "./client";

// Flipside: OS images, signed update bundles, and staged rollouts, driven
// through Moorgate so that its roles, host-access rules and audit log apply
// (see docs/imaging.md). Everything here goes to Moorgate's own /imaging/*
// routes, never to Flipside directly — the Flipside operator token stays in the
// backend, because a browser holding it would be a second, weaker way in.

export interface ImagingStatus {
  configured: boolean;
  url?: string;
  nudge?: boolean;
  reachable?: boolean;
  version?: string;
  error?: string;
}

export interface ImageMeta {
  distro?: string;
  suite?: string;
  arch?: string;
  profile?: string;
  version?: string;
  encrypted?: boolean;
  secure_boot?: boolean;
  packages?: number;
  created?: string;
}

export interface Image {
  name: string;
  size: number;
  created: string;
  sha256?: string;
  meta?: ImageMeta;
}

export interface Bundle {
  name: string;
  version?: string;
  compatible?: string;
  source?: string;
  description?: string;
  size: number;
  created: string;
  is_latest?: boolean;
}

export interface Machine {
  id: string;
  hostname?: string;
  address?: string;
  slot?: string;
  version?: string;
  image?: string;
  groups?: string[];
  label?: string;
  paused?: boolean;
  presence: "online" | "stale" | "offline" | "unknown";
  health?: string;
  update_state?: string;
  update_error?: string;
  last_seen?: number;
}

export interface FleetRow {
  hostId?: string;
  hostname: string;
  environment?: string;
  tags?: string[];
  enrolled: boolean;
  machineId?: string;
  linkedBy: "linked" | "hostname" | "none";
  machine?: Machine;
  reachable: boolean;
}

export interface RolloutStrategy {
  canary: number;
  batch_size: number;
  soak_seconds: number;
  max_failures: number;
}

export interface Rollout {
  id: string;
  bundle: string;
  version: string;
  bundle_url?: string;
  state: "running" | "paused" | "halted" | "completed" | "cancelled";
  halt_reason?: string;
  created: number;
  created_by?: string;
  total: number;
  done: number;
  counts: Record<string, number>;
  machines: Record<string, { state: string; error?: string }>;
  target: { groups: string[]; hosts: string[]; all: boolean };
  strategy: RolloutStrategy;
}

export interface FleetGroup {
  name: string;
  description?: string;
  hosts: number;
}

export async function imagingStatus(): Promise<ImagingStatus> {
  const { data } = await api.get("/api/v1/imaging/status");
  return data;
}

export async function listImages(): Promise<Image[]> {
  const { data } = await api.get("/api/v1/imaging/images");
  return data.images ?? [];
}

export async function listBundles(): Promise<{ bundles: Bundle[]; running_versions: Record<string, number> }> {
  const { data } = await api.get("/api/v1/imaging/bundles");
  return { bundles: data.bundles ?? [], running_versions: data.running_versions ?? {} };
}

export async function listFleetGroups(): Promise<FleetGroup[]> {
  const { data } = await api.get("/api/v1/imaging/groups");
  return data.groups ?? [];
}

export interface FleetView {
  rows: FleetRow[];
  counts: Record<string, number>;
  versions: Record<string, number>;
  interval: number;
  controlUrl: string;
}

export async function imagingFleet(): Promise<FleetView> {
  const { data } = await api.get("/api/v1/imaging/fleet");
  return {
    rows: data.rows ?? [],
    counts: data.counts ?? {},
    versions: data.versions ?? {},
    interval: data.interval ?? 300,
    controlUrl: data.controlUrl ?? "",
  };
}

export async function listRollouts(): Promise<Rollout[]> {
  const { data } = await api.get("/api/v1/imaging/rollouts");
  return data.rollouts ?? [];
}

export interface NewRollout {
  bundle: string;
  groups?: string[];
  hosts?: string[];
  all?: boolean;
  strategy?: Partial<RolloutStrategy>;
  window?: { start: string; end: string; days?: number[] } | null;
}

export async function createRollout(body: NewRollout): Promise<Rollout> {
  const { data } = await api.post("/api/v1/imaging/rollouts", body);
  return data;
}

export async function steerRollout(id: string, verb: "pause" | "resume" | "cancel") {
  await api.post(`/api/v1/imaging/rollouts/${encodeURIComponent(id)}/${verb}`);
}

export async function linkHost(hostId: string, machineId: string) {
  await api.put(`/api/v1/imaging/hosts/${hostId}/link`, { machineId });
}

export interface ActionResult {
  ok: boolean;
  output?: string;
  error?: string;
  note?: string;
}

// Make a machine check in with Flipside now rather than on its own timer. This
// is the whole of the "push" Moorgate adds: the agent then does exactly what it
// would have done minutes later, and Flipside applies the rollout's rules
// unchanged.
export async function nudgeHost(hostId: string): Promise<ActionResult> {
  const { data } = await api.post(`/api/v1/imaging/hosts/${hostId}/nudge`);
  return data;
}

// Write a bundle to a host directly, for machines that cannot reach Flipside
// at all.
export async function installOnHost(hostId: string, bundleUrl: string): Promise<ActionResult> {
  const { data } = await api.post(`/api/v1/imaging/hosts/${hostId}/install`, { bundleUrl });
  return data;
}
