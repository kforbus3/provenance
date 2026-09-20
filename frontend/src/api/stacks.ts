import { api } from "./client";

// Container stacks: the desired state of what a host should be running.
//
// Provenance is the source of truth, replacing a git repository plus a bot plus
// an rsync deploy. The rendered compose file is still written to the host, so
// Provenance being down stops you CHANGING what runs, not running it.

export interface ContainerStack {
  id: string;
  hostId: string;
  hostname?: string;
  name: string;
  compose?: string;
  path: string;
  revision: number;
  enabled: boolean;
  // What the host last confirmed it applied. Separate from `revision` so
  // "should be running" and "is running" cannot be read as the same thing.
  deployedRevision?: number;
  // "deploying" while a deploy is in flight, then "deployed" / "failed".
  deployState?: string;
  deployDetail?: string;
  deployedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface StackRevision {
  revision: number;
  compose?: string;
  note?: string;
  authorName?: string;
  createdAt: string;
}

export async function listStacks(hostId?: string): Promise<ContainerStack[]> {
  const { data } = await api.get<{ stacks: ContainerStack[] }>(`/api/v1/stacks`, {
    params: hostId ? { hostId } : undefined,
  });
  return data.stacks ?? [];
}

export async function getStack(id: string): Promise<ContainerStack> {
  const { data } = await api.get<ContainerStack>(`/api/v1/stacks/${id}`);
  return data;
}

export async function stackHistory(id: string): Promise<StackRevision[]> {
  const { data } = await api.get<{ revisions: StackRevision[] }>(`/api/v1/stacks/${id}/history`);
  return data.revisions ?? [];
}

// Stacks whose host is not running the revision it should be.
export async function stackDrift(): Promise<ContainerStack[]> {
  const { data } = await api.get<{ stacks: ContainerStack[] }>(`/api/v1/stacks/drift`);
  return data.stacks ?? [];
}

export interface SaveStackInput {
  hostId: string;
  name: string;
  compose: string;
  path?: string;
  note?: string;
}

// Saves the definition. Deliberately does NOT deploy: editing a compose file
// should not restart somebody's database because the editor hit save.
export async function saveStack(input: SaveStackInput): Promise<ContainerStack> {
  const { data } = await api.post<ContainerStack>(`/api/v1/stacks`, input);
  return data;
}

export async function deleteStack(id: string): Promise<void> {
  await api.delete(`/api/v1/stacks/${id}`);
}

// Starts a deploy. It does NOT wait for one.
//
// A deploy pulls images, and eight of them takes minutes — far longer than the
// 60s request timeout every route sits behind. It used to run on the request,
// get cancelled mid-pull, and fail even to record what had happened, so the
// screen went on showing the previous outcome and pressing Deploy looked like it
// had done nothing. The stack row carries the state from here on: "deploying"
// while it runs, then deployed or failed.
export async function deployStack(id: string, acknowledgeStatefulMajor = false):
  Promise<{ status: string; note?: string }> {
  const q = acknowledgeStatefulMajor ? "?acknowledgeStatefulMajor=1" : "";
  const { data } = await api.post<{ status: string; note?: string }>(`/api/v1/stacks/${id}/deploy${q}`);
  return data;
}

// A deploy refused because it would move a database image across a major version.
//
// 409 rather than a failure minutes later: the check reads the stored compose against
// the containers the host is running, so it can be answered on the request. Both
// versions and the migration are named, because the operator is the one who has to
// decide whether the data directory has already been converted.
export type StatefulMajorRefusal = {
  code: "stateful_major_bump";
  error: string;
  service: string;
  repository: string;
  from: string;
  to: string;
  migration: string;
};

export function statefulMajorRefusal(e: unknown): StatefulMajorRefusal | null {
  const r = (e as { response?: { status?: number; data?: StatefulMajorRefusal } })?.response;
  if (r?.status === 409 && r.data?.code === "stateful_major_bump") return r.data;
  return null;
}

export async function rollbackStack(id: string): Promise<{ output: string }> {
  const { data } = await api.post<{ output: string }>(`/api/v1/stacks/${id}/rollback`);
  return data;
}

// What compose projects exist on the fleet, whether or not Provenance manages
// them.
//
// This needs no setup: every compose-managed container records its own project
// and directory, so the monitor sweep already knows — wherever they live. The
// Stacks page used to list only what had been ADOPTED, which made a working
// deployment look like an empty product with a setup task attached.
export interface DiscoveredProject {
  hostId: string;
  hostname: string;
  project: string;
  dir: string;
  services: string[];
  images: number;
  // Adopted means Provenance holds the compose file, which is needed only to
  // change a version. Rebuilds work without it.
  adopted: boolean;
  stackId?: string;
}

export async function listDiscoveredProjects(): Promise<DiscoveredProject[]> {
  const { data } = await api.get<{ projects: DiscoveredProject[] }>(
    "/api/v1/stacks/discovered");
  return data.projects ?? [];
}
