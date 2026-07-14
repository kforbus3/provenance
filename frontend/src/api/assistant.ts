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
  points: MetricHistoryPoint[];
}

export interface AskResult {
  status: string; // pending|done|error
  answer?: string;
  hosts?: AssistantHost[];
  sessions?: AssistantSession[];
  host?: Host;
  history?: MetricHistory;
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

export async function askAssistant(question: string): Promise<string> {
  const { data } = await api.post<{ id: string }>("/api/v1/assistant/ask", { question });
  return data.id;
}

export async function askResult(id: string): Promise<AskResult> {
  const { data } = await api.get<AskResult>(`/api/v1/assistant/ask/${id}`);
  return data;
}
