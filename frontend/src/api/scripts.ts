import { api } from "./client";

// PowerShell script management for Windows hosts — the Windows counterpart to
// Ansible playbooks. Author/edit/version scripts and run them on Windows hosts over
// WinRM. Mirrors the playbooks API surface (minus the ansible-only validate/lint).

export interface Script {
  id: string;
  name: string;
  description?: string;
  content?: string;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface ScriptVersion {
  id: string;
  scriptId: string;
  version: number;
  content?: string;
  author?: string;
  createdAt: string;
}

export async function listScripts(): Promise<Script[]> {
  const { data } = await api.get<{ scripts: Script[] }>("/api/v1/scripts");
  return data.scripts ?? [];
}

export async function getScript(id: string): Promise<Script> {
  const { data } = await api.get<Script>(`/api/v1/scripts/${id}`);
  return data;
}

export async function createScript(input: { name: string; description: string; content: string }): Promise<Script> {
  const { data } = await api.post<Script>("/api/v1/scripts", input);
  return data;
}

export async function updateScript(
  id: string,
  input: { name: string; description: string; content: string },
): Promise<Script> {
  const { data } = await api.put<Script>(`/api/v1/scripts/${id}`, input);
  return data;
}

export async function deleteScript(id: string): Promise<void> {
  await api.delete(`/api/v1/scripts/${id}`);
}

export async function listScriptVersions(id: string): Promise<ScriptVersion[]> {
  const { data } = await api.get<{ versions: ScriptVersion[] }>(`/api/v1/scripts/${id}/versions`);
  return data.versions ?? [];
}

// --- execution ---

export interface ScriptRun {
  id: string;
  scriptId: string;
  scriptVersion: number;
  requester?: string;
  targetKind: string; // host|group
  targetId?: string;
  targetName?: string;
  hostCount: number;
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
  | { targetKind: "host"; hostIds: string[] }
  | { targetKind: "group"; groupId: string };

export async function runScript(id: string, input: RunTarget): Promise<ScriptRun> {
  const { data } = await api.post<ScriptRun>(`/api/v1/scripts/${id}/run`, input);
  return data;
}

export async function listScriptRuns(id: string): Promise<ScriptRun[]> {
  const { data } = await api.get<{ runs: ScriptRun[] }>(`/api/v1/scripts/${id}/runs`);
  return data.runs ?? [];
}

export async function getScriptRun(runId: string): Promise<ScriptRun> {
  const { data } = await api.get<ScriptRun>(`/api/v1/script-runs/${runId}`);
  return data;
}
