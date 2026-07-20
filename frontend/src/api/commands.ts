import { api } from "./client";

export interface CommandRun {
  id: string;
  command: string;
  requester: string;
  targetKind: string;
  targetName: string;
  hostCount: number;
  status: string;
  exitCode?: number;
  output: string;
  error: string;
  startedAt?: string;
  finishedAt?: string;
  createdAt: string;
}

export interface RunCommandReq {
  command: string;
  targetKind: "host" | "group";
  hostIds?: string[];
  groupId?: string;
}

export async function runCommand(req: RunCommandReq): Promise<CommandRun> {
  const { data } = await api.post<CommandRun>("/api/v1/commands/run", req);
  return data;
}

export async function listCommandRuns(): Promise<CommandRun[]> {
  const { data } = await api.get<{ runs: CommandRun[] }>("/api/v1/command-runs");
  return data.runs ?? [];
}

export async function getCommandRun(id: string): Promise<CommandRun> {
  const { data } = await api.get<CommandRun>(`/api/v1/command-runs/${id}`);
  return data;
}
