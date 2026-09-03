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

// --- building ----------------------------------------------------------------
//
// Builds run in the builder-runner sidecar, which is the only thing in a
// deployment that touches the Docker socket. It is opt-in: a 501 from any of
// these means no runner is configured, not that something is broken.

export interface BuildJob {
  id: string;
  type: "image" | "bundle" | "imager";
  label: string;
  status: "running" | "success" | "failed" | "canceled";
  returncode?: number | null;
  started: string;
  finished?: string;
  lines: number;
  progress?: { step: number; total: number; label: string } | null;
  // Only on a single-job read.
  log?: string[];
  offset?: number;
  total?: number;
}

export interface ImageBuildRequest {
  distro?: string;
  suite?: string;
  arch?: string;
  hostname?: string;
  username?: string;
  password?: string;
  imageSize?: string;
  rootSize?: number;
  compress?: string;
  profile?: string;
  desktop?: string;
  secureBoot?: string;
  packages?: string;
  sshKey?: string;
  sshKeyOnly?: boolean;
  encrypt?: boolean;
  unlock?: string;
  luksPassphrase?: string;
  tangUrl?: string;
  stateModel?: string;
  slotPrivateUpper?: boolean;
  persistPaths?: string;
  slotPrivatePaths?: string;
  volatilePaths?: string;
  resetPaths?: string;
  keepPaths?: string;
  ownPaths?: string;
  runScript?: string;
}

export interface BundleBuildRequest {
  image: string;
  version?: string;
  description?: string;
  encrypted?: boolean;
  luksPassphrase?: string;
}

export async function startBuild(
  kind: "image" | "bundle" | "imager",
  body: ImageBuildRequest | BundleBuildRequest | { arch?: string },
): Promise<BuildJob> {
  const { data } = await api.post(`/api/v1/imaging/builds/${kind}`, body);
  return data;
}

export async function listBuilds(): Promise<BuildJob[]> {
  const { data } = await api.get("/api/v1/imaging/builds");
  return data.builds ?? [];
}

// Polled with an offset rather than streamed, so a reconnect resumes where it
// left off instead of replaying an hour of build output.
export async function buildLog(id: string, offset = 0): Promise<BuildJob> {
  const { data } = await api.get(
    `/api/v1/imaging/builds/${encodeURIComponent(id)}?offset=${offset}`,
  );
  return data;
}

export async function cancelBuild(id: string): Promise<BuildJob> {
  const { data } = await api.post(`/api/v1/imaging/builds/${encodeURIComponent(id)}/cancel`);
  return data;
}

export async function deleteImage(name: string) {
  await api.delete(`/api/v1/imaging/images/${encodeURIComponent(name)}`);
}

export async function deleteBundle(name: string) {
  await api.delete(`/api/v1/imaging/bundles/${encodeURIComponent(name)}`);
}

export interface DiskUsage {
  artifacts: number;
  free: number;
  total: number;
}

// Worth showing because of how a build fails when the volume is full: not
// cleanly, but part way through debootstrap with a loop device still attached
// and the reason two hundred lines up the log.
export async function diskUsage(): Promise<DiskUsage> {
  const { data } = await api.get("/api/v1/imaging/disk");
  return data;
}

// --- machines being imaged right now -----------------------------------------

export interface PhaseChange {
  phase: string;
  at: string;
}

// Live progress of an imaging run. Held in memory on the server and expired
// there, so this is what is happening at this moment rather than a history —
// a finished machine lingers briefly and then drops off.
export interface ImagingNow {
  id: string;
  phase: string;
  percent: number;
  detail?: string;
  disk?: string;
  image?: string;
  address?: string;
  firstSeen: string;
  lastSeen: string;
  finishedAt?: string;
  history: PhaseChange[];
  // "stalled" is not an error: writing a large image to a slow disk is a long
  // silence, and the imager reports on phase changes rather than on a timer.
  state: "active" | "stalled" | "done" | "failed";
  ageSeconds: number;
  staleSeconds: number;
}

export async function imagingNow(): Promise<{ imaging: ImagingNow[]; active: number }> {
  const { data } = await api.get("/api/v1/imaging/now");
  return { imaging: data.imaging ?? [], active: data.active ?? 0 };
}

// Drop a row for a machine that will never report again — unplugged mid-write,
// most often. It expires on its own; this is for the operator who would rather
// not look at it for the next ten minutes.
export async function forgetImaging(id: string) {
  await api.delete(`/api/v1/imaging/now/${encodeURIComponent(id)}`);
}
