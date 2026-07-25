import { api } from "./client";

export interface UpgradeManifest {
  version: string;
  buildDate?: string;
  minFromVersion?: string;
  components?: string[];
  migrationCompatibility: string; // "additive" | "breaking"
  notes?: string;
}

export interface UpgradeStatus {
  state: string; // idle | backing_up | dispatched | running | success | failed
  targetVersion?: string;
  step?: string;
  log?: string[];
  error?: string;
  draining?: boolean;
  startedAt?: string;
  updatedAt?: string;
}

// previewUpgrade uploads a .fleetup bundle, verifies it server-side, and returns its
// manifest WITHOUT applying — so the operator can review it before confirming.
export async function previewUpgrade(file: File): Promise<UpgradeManifest> {
  const form = new FormData();
  form.append("bundle", file);
  const { data } = await api.post<{ manifest: UpgradeManifest }>("/system/upgrade/preview", form, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data.manifest;
}

// applyUpgrade applies the currently-staged (previewed) bundle. version guards against
// applying a different bundle than was reviewed.
export async function applyUpgrade(version: string): Promise<void> {
  await api.post("/system/upgrade/apply", { version });
}

export async function getUpgradeStatus(): Promise<UpgradeStatus> {
  const { data } = await api.get<UpgradeStatus>("/system/upgrade/status");
  return data;
}

export async function setDrain(draining: boolean): Promise<void> {
  await api.post("/system/drain", { draining });
}

export interface ChannelRelease {
  version: string;
  minFromVersion?: string;
  bundleUrl: string;
  bundleSize?: number;
  migrationCompatibility: string;
  notes?: string;
  publishedAt?: string;
}

export interface ClusterMember {
  hostname: string;
  version: string;
  isLeader: boolean;
  lastHeartbeat: string;
}

export interface SiteVersion {
  name: string;
  buildVersion: string;
  status: string;
  upToDate: boolean;
}

export interface CheckResult {
  currentVersion: string;
  channelEnabled: boolean;
  updateAvailable: boolean;
  release?: ChannelRelease;
  cluster?: ClusterMember[];
  sites?: SiteVersion[];
  sitesBehind?: boolean;
}

// checkForUpdate queries the configured release channel for an available upgrade.
export async function checkForUpdate(): Promise<CheckResult> {
  const { data } = await api.get<CheckResult>("/system/upgrade/check");
  return data;
}

// pullUpdate downloads + installs a channel release (latest applicable if omitted).
export async function pullUpdate(version?: string): Promise<void> {
  await api.post("/system/upgrade/pull", { version: version || "" });
}
