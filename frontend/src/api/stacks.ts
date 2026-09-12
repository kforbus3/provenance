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

export async function deployStack(id: string): Promise<{ revision: number; output: string }> {
  const { data } = await api.post<{ revision: number; output: string }>(
    `/api/v1/stacks/${id}/deploy`);
  return data;
}

export async function rollbackStack(id: string): Promise<{ output: string }> {
  const { data } = await api.post<{ output: string }>(`/api/v1/stacks/${id}/rollback`);
  return data;
}
