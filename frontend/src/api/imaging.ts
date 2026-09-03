import { api } from "./client";

// Imaging: OS images, signed update bundles, and staged rollouts.
//
// These are this server's own routes, not a proxy to anything. The imager, the
// rollout engine and the fleet manager are one program, so a rollout targets the
// same host groups everything else does, host access decides what is visible,
// and every action lands in the same audit log (see docs/imaging.md).

export interface Image {
  name: string;
  size: number;
  created: string;
  sha256?: string;
  distro?: string;
  suite?: string;
  arch?: string;
  profile?: string;
  version?: string;
  encrypted: boolean;
  secureBoot: boolean;
  packages?: number;
  hasSbom: boolean;
}

export interface Bundle {
  name: string;
  size: number;
  created: string;
  version?: string;
  compatible?: string;
  source?: string;
  description?: string;
  isLatest: boolean;
  hasSbom: boolean;
}

export type Presence = "online" | "stale" | "offline" | "unknown";

// Machine is one machine as the imaging system knows it — keyed by what the
// imager saw (usually a MAC), because a machine exists before it is a host: it
// is imaged on the provisioning switch and only later enrolled.
export interface Machine {
  id: string;
  hostId?: string;
  hostname: string;
  address?: string;
  slot?: string;
  version: string;
  image?: string;
  arch?: string;
  agentVersion?: string;
  bootId?: string;
  health?: string;
  updateState: string;
  updateError?: string;
  updateRollout?: string;
  // Who last said this and how they knew: a machine's own check-in, or
  // something reporting what it read off the host over SSH.
  reportedBy?: string;
  reportSource: "agent" | "observed";
  label?: string;
  held: boolean;
  firstSeen: string;
  lastSeen?: string;
  imagedAt?: string;
  bootedAt?: string;
  presence: Presence;
  hostName?: string;
  environment?: string;
  tags?: string[];
  // Whether this server can reach the paired host right now, which is the
  // difference between an update that lands in minutes and one that lands
  // whenever the machine next asks.
  reachable: boolean;
}

export interface RolloutProgress {
  state: string;
  error?: string;
  attempts: number;
  changedAt: string;
}

export interface Rollout {
  id: string;
  bundle: string;
  version: string;
  bundleUrl?: string;
  description?: string;
  state: "running" | "paused" | "halted" | "completed" | "cancelled";
  haltReason?: string;
  targetGroups: string[];
  targetHosts: string[];
  targetAll: boolean;
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
  total: number;
  done: number;
  counts?: Record<string, number>;
  machines?: Record<string, RolloutProgress>;
}

export interface MachineList {
  machines: Machine[];
  counts: Record<string, number>;
  versions: Record<string, number>;
  interval: number;
}

export async function listMachines(): Promise<MachineList> {
  const { data } = await api.get("/api/v1/imaging/machines");
  return {
    machines: data.machines ?? [],
    counts: data.counts ?? {},
    versions: data.versions ?? {},
    interval: data.interval ?? 300,
  };
}

export async function listImages(): Promise<{ images: Image[]; dir: string }> {
  const { data } = await api.get("/api/v1/imaging/images");
  return { images: data.images ?? [], dir: data.dir ?? "" };
}

export async function listBundles(): Promise<{
  bundles: Bundle[];
  runningVersions: Record<string, number>;
  controlUrl: string;
}> {
  const { data } = await api.get("/api/v1/imaging/bundles");
  return {
    bundles: data.bundles ?? [],
    runningVersions: data.runningVersions ?? {},
    controlUrl: data.controlUrl ?? "",
  };
}

export async function listRollouts(): Promise<Rollout[]> {
  const { data } = await api.get("/api/v1/imaging/rollouts");
  return data.rollouts ?? [];
}

export async function getRollout(id: string): Promise<Rollout> {
  const { data } = await api.get(`/api/v1/imaging/rollouts/${encodeURIComponent(id)}`);
  return data;
}

export interface NewRollout {
  bundle: string;
  bundleUrl?: string;
  description?: string;
  groups?: string[];
  hosts?: string[];
  all?: boolean;
  canary?: number;
  batchSize?: number;
  soakSeconds?: number;
  maxFailures?: number;
  windowStart?: string;
  windowEnd?: string;
  windowDays?: number[];
}

export async function createRollout(body: NewRollout): Promise<Rollout> {
  const { data } = await api.post("/api/v1/imaging/rollouts", body);
  return data;
}

export async function steerRollout(id: string, verb: "pause" | "resume" | "cancel") {
  await api.post(`/api/v1/imaging/rollouts/${encodeURIComponent(id)}/${verb}`);
}

export async function deleteRollout(id: string) {
  await api.delete(`/api/v1/imaging/rollouts/${encodeURIComponent(id)}`);
}

// Pair a machine with the host it is, name it, or hold it back from rollouts.
// All three are an operator's word about a machine and never the machine's word
// about itself — otherwise anything on the network could put itself into a
// rollout it was never targeted by.
export async function updateMachine(
  id: string,
  body: { hostId?: string | null; label?: string; held?: boolean },
): Promise<Machine> {
  const { data } = await api.put(`/api/v1/imaging/machines/${encodeURIComponent(id)}`, body);
  return data;
}

export interface ActionResult {
  ok: boolean;
  output?: string;
  error?: string;
  note?: string;
}

// Make a machine check in now rather than on its own timer. This is the whole of
// the "push": the agent then does exactly what it would have done minutes later,
// and the rollout's rules — canary, soak, batch, window, budget — are unchanged.
export async function nudgeMachine(id: string): Promise<ActionResult> {
  const { data } = await api.post(`/api/v1/imaging/machines/${encodeURIComponent(id)}/nudge`);
  return data;
}

// Write a bundle to a machine's inactive slot over SSH, for machines with no
// route back to this server at all.
export async function installOnMachine(id: string, bundleUrl: string): Promise<ActionResult> {
  const { data } = await api.post(
    `/api/v1/imaging/machines/${encodeURIComponent(id)}/install`,
    { bundleUrl },
  );
  return data;
}
