import { api } from "./client";
import type { Host } from "./hosts";

// AI assistant: read-only natural-language queries over fleet data via Ollama.

export interface AssistantStatus {
  enabled: boolean;
  model: string;
  reachable: boolean;
  ready: boolean;
}

export interface AssistantHost {
  hostname: string;
  environment?: string;
  status: string;
  primaryIp?: string;
  os?: string;
  diskFreePct?: number;
  memUsedPct?: number;
  loadPerCore?: number;
}

export interface AssistantSession {
  username: string;
  hostname: string;
  clientIp?: string;
  startedAt: string;
}

export interface MetricHistoryPoint {
  t: string; // bucket timestamp (ISO)
  samples: number;
  diskFreePctAvg?: number;
  diskFreePctMin?: number;
  memUsedPctAvg?: number;
  memUsedPctMax?: number;
  loadPerCoreAvg?: number;
  loadPerCoreMax?: number;
}

export interface MetricHistory {
  hostname: string;
  windowHours: number;
  bucketMinutes: number;
  metrics?: string[]; // which series the question was about (disk/memory/load); absent = all
  points: MetricHistoryPoint[];
}

export interface AssistantTableColumn {
  label: string;
  kind?: string; // "" text | "time" RFC 3339 | "bytes"
}

// Generic tabular tool result (audit events, schedules, past sessions, transfers).
export interface AssistantTable {
  title: string;
  columns: AssistantTableColumn[];
  rows: string[][];
}

export interface AskResult {
  status: string; // pending|done|error
  answer?: string;
  hosts?: AssistantHost[];
  sessions?: AssistantSession[];
  host?: Host;
  history?: MetricHistory;
  table?: AssistantTable;
  error?: string;
}

export async function assistantStatus(): Promise<AssistantStatus> {
  const { data } = await api.get<AssistantStatus>("/api/v1/assistant/status");
  return data;
}

// List models from the configured Ollama, or a URL being tested in settings.
export async function assistantModels(url?: string): Promise<string[]> {
  const { data } = await api.get<{ models: string[] }>("/api/v1/assistant/models", {
    params: url ? { url } : undefined,
  });
  return data.models ?? [];
}

export interface AskHandle {
  id: string;
  conversationId: string;
}

// askAssistant starts a question. Pass the conversationId returned by a previous
// call to continue that thread (follow-up questions see the earlier exchanges);
// omit it to start a fresh conversation.
export async function askAssistant(question: string, conversationId?: string): Promise<AskHandle> {
  const { data } = await api.post<{ id: string; conversationId: string }>(
    "/api/v1/assistant/ask",
    { question, conversationId },
  );
  return { id: data.id, conversationId: data.conversationId };
}

export async function askResult(id: string): Promise<AskResult> {
  const { data } = await api.get<AskResult>(`/api/v1/assistant/ask/${id}`);
  return data;
}
