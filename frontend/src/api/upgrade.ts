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
