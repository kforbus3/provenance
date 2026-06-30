import { api } from "./client";

// Ansible playbook management. Phase 1: author/edit playbooks and validate/lint
// them via the ansible-runner sidecar. Execution against hosts arrives later.

export interface Playbook {
  id: string;
  name: string;
  description?: string;
  content?: string;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface PlaybookVersion {
  id: string;
  playbookId: string;
  version: number;
  content?: string;
  author?: string;
  createdAt: string;
}

export interface CheckResult {
  ok: boolean;
  output: string;
}

export async function listPlaybooks(): Promise<Playbook[]> {
  const { data } = await api.get<{ playbooks: Playbook[] }>("/api/v1/playbooks");
  return data.playbooks ?? [];
}

export async function getPlaybook(id: string): Promise<Playbook> {
  const { data } = await api.get<Playbook>(`/api/v1/playbooks/${id}`);
  return data;
}

export async function createPlaybook(input: { name: string; description: string; content: string }): Promise<Playbook> {
  const { data } = await api.post<Playbook>("/api/v1/playbooks", input);
  return data;
}

export async function updatePlaybook(
  id: string,
  input: { name: string; description: string; content: string },
): Promise<Playbook> {
  const { data } = await api.put<Playbook>(`/api/v1/playbooks/${id}`, input);
  return data;
}

export async function deletePlaybook(id: string): Promise<void> {
  await api.delete(`/api/v1/playbooks/${id}`);
}

export async function listPlaybookVersions(id: string): Promise<PlaybookVersion[]> {
  const { data } = await api.get<{ versions: PlaybookVersion[] }>(`/api/v1/playbooks/${id}/versions`);
  return data.versions ?? [];
}

export async function validatePlaybook(content: string): Promise<CheckResult> {
  const { data } = await api.post<CheckResult>("/api/v1/playbooks/validate", { content });
  return data;
}

export async function lintPlaybook(content: string): Promise<CheckResult> {
  const { data } = await api.post<CheckResult>("/api/v1/playbooks/lint", { content });
  return data;
}

export async function runnerStatus(): Promise<{ available: boolean }> {
  const { data } = await api.get<{ available: boolean }>("/api/v1/playbooks/runner");
  return data;
}

// --- execution ---

export interface PlaybookRun {
  id: string;
  playbookId: string;
  playbookVersion: number;
  requester?: string;
  targetKind: string; // host|group
  targetId?: string;
  targetName?: string;
  hostCount: number;
  checkMode: boolean;
  scheduled?: boolean;
  status: string; // pending|running|completed|failed
  exitCode?: number;
  output?: string;
  error?: string;
  startedAt?: string;
  finishedAt?: string;
  createdAt: string;
}

export type RunTarget =
  | { targetKind: "host"; hostIds: string[]; checkMode: boolean }
  | { targetKind: "group"; groupId: string; checkMode: boolean };

export async function runPlaybook(id: string, input: RunTarget): Promise<PlaybookRun> {
  const { data } = await api.post<PlaybookRun>(`/api/v1/playbooks/${id}/run`, input);
  return data;
}

export async function listPlaybookRuns(id: string): Promise<PlaybookRun[]> {
  const { data } = await api.get<{ runs: PlaybookRun[] }>(`/api/v1/playbooks/${id}/runs`);
  return data.runs ?? [];
}

export async function getPlaybookRun(runId: string): Promise<PlaybookRun> {
  const { data } = await api.get<PlaybookRun>(`/api/v1/playbook-runs/${runId}`);
  return data;
}
