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

// imagerArches travels with the image library because the two are read together:
// an image is not deployable without a netboot imager to write it, and finding
// that out from the provisioning preflight — after choosing a network and pressing
// Start — is late. The imager IS a kernel, so it is per architecture: an amd64
// imager cannot boot an arm64 machine however it is served.
export async function listImages(): Promise<{
  images: Image[];
  dir: string;
  imagerArches: Record<string, boolean>;
}> {
  const { data } = await api.get("/api/v1/imaging/images");
  return {
    images: data.images ?? [],
    dir: data.dir ?? "",
    imagerArches: data.imagerArches ?? {},
  };
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
// Forget a machine. Not a soft delete: one that still exists is recreated by its
// next heartbeat, so a deletion made in error costs a heartbeat interval rather
// than being permanent.
export async function deleteMachine(id: string): Promise<void> {
  await api.delete(`/api/v1/imaging/machines/${encodeURIComponent(id)}`);
}

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
  // The output filename. Omitted, the builder picks distro-suite-arch-ab and a
  // free suffix; given, it is honoured and refused if taken. It matters beyond
  // tidiness: the image a machine was made from is what a bundle for it must be
  // built from, and a LUKS recovery passphrase is filed under this name.
  name?: string;
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
  // How the root filesystem is unlocked at boot. The builder enrolls the
  // passphrase for recovery in every case; this decides what unlocks it
  // unattended:
  //   passphrase  typed at every boot — no unattended reboot
  //   keyfile     a key in the initramfs (default; the initramfs is unencrypted,
  //               so this protects the disk at rest, not against someone holding it)
  //   tpm2        sealed to the machine's TPM — unattended, and bound to that machine
  //   tang        released by a Tang server on the network — unattended while on it
  unlock?: "passphrase" | "keyfile" | "tpm2" | "tang";
  luksPassphrase?: string;
  tangUrl?: string;
  // Generate this build's recovery passphrase and file it before the build
  // starts, instead of typing one. It goes to the external secrets manager when
  // one is connected, otherwise into Fleet's own credential vault; either way a
  // credential record is created so it is found the same way.
  //
  // The build is refused if the passphrase cannot be stored — an encrypted image
  // whose key was never persisted looks exactly like a success.
  generatePassphrase?: boolean;
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

// A build started with generatePassphrase also reports where the recovery key
// went, so the operator is told rather than having to go looking.
export interface StartedBuild extends BuildJob {
  passphraseStoredIn?: "external" | "vault";
  passphraseStoredAt?: string;
  passphraseSecretId?: string;
  imageName?: string;
}

export async function startBuild(
  kind: "image" | "bundle" | "imager",
  body: ImageBuildRequest | BundleBuildRequest | { arch?: string },
): Promise<StartedBuild> {
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

// Drop one finished build from the history, and its log with it.
export async function forgetBuild(id: string): Promise<void> {
  await api.delete(`/api/v1/imaging/builds/${encodeURIComponent(id)}`);
}

// Drop every build that is not running.
export async function forgetFinishedBuilds(): Promise<number> {
  const { data } = await api.delete("/api/v1/imaging/builds");
  return (data?.removed ?? 0) as number;
}

export async function cancelBuild(id: string): Promise<BuildJob> {
  const { data } = await api.post(`/api/v1/imaging/builds/${encodeURIComponent(id)}/cancel`);
  return data;
}

// Downloads go through the browser as a normal navigation rather than through
// axios: an image is several gigabytes, and buffering one in JS to hand it to a
// save dialog defeats the point of streaming it. The cookie carries the auth.
export function imageDownloadUrl(name: string): string {
  return `/api/v1/imaging/images/${encodeURIComponent(name)}/download`;
}

export function imageSbomUrl(name: string): string {
  return `/api/v1/imaging/images/${encodeURIComponent(name)}/sbom`;
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

// --- The provisioning stack (PXE) --------------------------------------------
//
// The half of imaging that happens before a machine is anything at all: a NIC on
// an isolated segment, a DHCP/TFTP server confined to it, and an image to write.
// The sidecar owns the machinery; these are the controls for it.

// NetInterface is one of the host's NICs, offered so nobody has to know their own
// topology to answer "which network are the machines on".
export interface NetInterface {
  name: string;
  ip: string;
  prefixlen: number;
  network: string;
  netmask: string;
  mac: string;
  up: boolean;
  carrier: boolean;
  // Carries the host's default route — the main LAN, and the one NIC you almost
  // never want a standalone DHCP server on.
  default: boolean;
}

// A free subnet proposed for a NIC that has no address, which is the normal state
// of a dedicated provisioning port: nothing on that segment hands out addresses,
// because this server is what will.
export interface ProvisioningSuggestion {
  SERVER_IP?: string;
  prefixlen?: number;
  DHCP_NETMASK?: string;
  PROXY_SUBNET?: string;
  DHCP_RANGE_START?: string;
  DHCP_RANGE_END?: string;
}

export interface ProvisioningStatus {
  running: boolean;
  detail?: string;
}

// The whole page in one call. Status and preflight are individually useless:
// "running" means something different when preflight is reporting that something
// else on the segment is already answering DHCP.
export interface Provisioning {
  env: Record<string, string>;
  controlUrl?: string;
  status?: ProvisioningStatus;
  problems?: string[];
  interfaces?: { interfaces: NetInterface[]; suggestion: ProvisioningSuggestion };
}

export async function getProvisioning(): Promise<Provisioning> {
  const { data } = await api.get<Provisioning>("/api/v1/imaging/provisioning");
  return data;
}

// Partial: only the keys sent are changed, so a caller need not round-trip
// settings it does not understand.
export async function setProvisioningEnv(env: Record<string, string>) {
  const { data } = await api.put("/api/v1/imaging/provisioning/env", { env });
  return data as { env: Record<string, string>; controlUrl?: string };
}

export async function steerProvisioning(verb: "up" | "down"): Promise<string> {
  const { data } = await api.post(`/api/v1/imaging/provisioning/${verb}`);
  return (data?.output as string) ?? "";
}

// Per-machine targeting: a MAC gets a specific image instead of the default one.
// Machines not listed here get IMAGE_FILE.
export interface Assignment {
  mac: string;
  image?: string;
  hostname?: string;
  name?: string;
  [k: string]: unknown;
}

// A machine seen on the provisioning network in the last few minutes, as the
// PXE stack's own logs describe it. Not a database row: this is "who is waiting
// right now", and a machine that has finished and rebooted into its image drops
// off because it is no longer waiting for one.
export interface ProvisioningClient {
  mac: string;
  ip: string;
  event: string;
  last: string;
}

export async function listProvisioningClients(): Promise<ProvisioningClient[]> {
  const { data } = await api.get("/api/v1/imaging/provisioning/clients");
  return (data.clients ?? []) as ProvisioningClient[];
}

export async function listAssignments(): Promise<Assignment[]> {
  const { data } = await api.get("/api/v1/imaging/assignments");
  return (data.assignments ?? []) as Assignment[];
}

export async function saveAssignments(assignments: Assignment[]): Promise<Assignment[]> {
  const { data } = await api.put("/api/v1/imaging/assignments", { assignments });
  return (data.assignments ?? []) as Assignment[];
}

// --- Overlay files -----------------------------------------------------------
//
// Layered into an image at build time: unit files, configs, scripts. Edited here
// because the person who decides what goes into an image is not always the person
// with a shell on the machine that builds it.

export interface OverlayFile {
  path: string;
  size: number;
  // cp -a preserves the mode, so what is set here is what lands on the machine —
  // which makes it part of the file, not a detail about it.
  mode: string;
  executable: boolean;
}

export async function listOverlay(): Promise<{ files: OverlayFile[]; root: string }> {
  const { data } = await api.get("/api/v1/imaging/overlay");
  return { files: data.files ?? [], root: data.root ?? "" };
}

// editable is false for a file too large or not UTF-8 to show; `reason` says which.
export interface OverlayContent extends OverlayFile {
  editable: boolean;
  content?: string;
  reason?: string;
}

export async function readOverlayFile(path: string): Promise<OverlayContent> {
  const { data } = await api.get("/api/v1/imaging/overlay/file", { params: { path } });
  return data as OverlayContent;
}

export async function writeOverlayFile(path: string, content: string, mode?: number) {
  const body: Record<string, unknown> = { path, content };
  if (mode !== undefined) body.mode = mode;
  const { data } = await api.put("/api/v1/imaging/overlay/file", body);
  return data as OverlayFile;
}

// Uploads go base64 rather than as text, for every file and not just the ones
// that look binary: a browser reading a file cannot know whether what it holds is
// UTF-8, and guessing wrong corrupts it silently. A certificate or a compiled
// tool is exactly what the overlay is for.
export async function uploadOverlayFile(path: string, contentBase64: string, mode?: number) {
  const body: Record<string, unknown> = { path, contentBase64 };
  if (mode !== undefined) body.mode = mode;
  const { data } = await api.put("/api/v1/imaging/overlay/file", body);
  return data as OverlayFile;
}

export interface OverlayDownload {
  path: string;
  size: number;
  mode: string;
  contentBase64: string;
}

export async function downloadOverlayFile(path: string): Promise<OverlayDownload> {
  const { data } = await api.get("/api/v1/imaging/overlay/download", { params: { path } });
  return data as OverlayDownload;
}

export async function moveOverlayFile(from: string, to: string) {
  const { data } = await api.post("/api/v1/imaging/overlay/move", { from, to });
  return data as OverlayFile;
}

// Its own call because a browser cannot read a file's permissions when uploading
// one — so a folder of scripts arrives without its executable bits, and setting
// them is what makes the difference between a boot that runs them and one that
// does not.
export async function chmodOverlayFile(path: string, mode: number) {
  const { data } = await api.post("/api/v1/imaging/overlay/chmod", { path, mode });
  return data as OverlayFile;
}

// readFileAsBase64 strips the data: URL prefix FileReader adds. Kept here beside
// the upload it feeds so the two cannot drift.
export function readFileAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onerror = () => reject(fr.error ?? new Error("could not read the file"));
    fr.onload = () => {
      const result = String(fr.result ?? "");
      const comma = result.indexOf(",");
      resolve(comma >= 0 ? result.slice(comma + 1) : result);
    };
    fr.readAsDataURL(file);
  });
}

export async function deleteOverlayFile(path: string) {
  await api.delete("/api/v1/imaging/overlay/file", { params: { path } });
}

// --- imaging key backup -------------------------------------------------
//
// What the database backup cannot hold: the RAUC signing key, the MAC→hostname
// assignments, and the provisioning stack's configuration.
//
// Metadata only. There is deliberately no download: a signing key fetchable over
// HTTP is one whose custody is whoever holds a session cookie. Losing this key
// means no already-deployed machine can ever be updated again — not "until we
// re-key", ever, because they verify against a certificate baked into their own
// image. The archive stays on the host; get it off with scp, deliberately.

export interface KeyBackupItem {
  path: string;
  why: string;
  present: boolean;
  size: number;
}

export interface KeyBackupFile {
  name: string;
  size: number;
  created: string;
}

export interface KeyBackupStatus {
  items: KeyBackupItem[];
  backups: KeyBackupFile[];
  dir: string;
  haveSigningKey: boolean;
  scriptPresent: boolean;
}

export async function keyBackupStatus(): Promise<KeyBackupStatus> {
  const { data } = await api.get("/api/v1/imaging/keys");
  return {
    items: data.items ?? [], backups: data.backups ?? [], dir: data.dir ?? "",
    haveSigningKey: !!data.haveSigningKey, scriptPresent: !!data.scriptPresent,
  };
}

export interface KeyBackupResult {
  name: string;
  size: number;
  sha256: string;
  path: string;
  output?: string;
}

export async function createKeyBackup(): Promise<KeyBackupResult> {
  const { data } = await api.post("/api/v1/imaging/keys/backup");
  return data as KeyBackupResult;
}

export async function inspectKeyBackup(name: string) {
  const { data } = await api.get("/api/v1/imaging/keys/inspect", { params: { name } });
  return data as { name: string; entries: string[]; containsSigningKey: boolean };
}

// Register an already-enrolled host as an updatable A/B machine — the inverse of
// "Add as host" on the Imaging page.
//
// Rollouts select from the machine table, so a host with no machine record is
// invisible to them, including to a rollout that targets the whole fleet. That
// is right for an ordinary server and wrong for an A/B machine this deployment
// did not image: one restored from a backup, imaged by an earlier server, or
// whose record was removed. Registering reads the machine's real slot and
// version over SSH rather than assuming them, and refuses a host that has no
// ab-update rather than creating a record that can only ever fail a rollout.
export async function registerHostForUpdates(hostId: string): Promise<Machine> {
  const { data } = await api.post(
    `/api/v1/imaging/hosts/${encodeURIComponent(hostId)}/register`,
  );
  return data;
}

// Remove a finished rollout from the list.
//
// The record is history, not state: the machines it updated keep their versions
// and a new rollout for the same bundle is unaffected. The server refuses while
// one is still running -- cancel it first -- so this cannot be used to abandon a
// rollout mid-flight and leave machines half-updated with nothing tracking them.
export async function deleteRollout(id: string): Promise<void> {
  await api.delete(`/api/v1/imaging/rollouts/${encodeURIComponent(id)}`);
}
