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

// DocSource is a documentation citation the assistant used to ground an answer,
// linking back into the in-app help at the exact section.
export interface DocSource {
  docTitle: string;
  heading: string;
  slug: string;
  anchor: string;
}

// AssistantAction is one proposed action in the propose→confirm→execute flow.
export interface AssistantAction {
  id: string;
  kind: string;
  preview: string;
  risk: string;   // safe | guarded | destructive
  permission: string;
  status: string; // proposed | executed | failed | cancelled | expired
  outcome?: string;
  createdAt: string;
  expiresAt: string;
}

export interface AskResult {
  status: string; // pending|done|error
  answer?: string;
  hosts?: AssistantHost[];
  sessions?: AssistantSession[];
  host?: Host;
  history?: MetricHistory;
  table?: AssistantTable;
  sources?: DocSource[];
  actions?: AssistantAction[];
  error?: string;
}

// executeAssistantAction confirms and runs a proposed action; the returned record
// carries the terminal status (executed/failed) and outcome.
export async function executeAssistantAction(id: string): Promise<AssistantAction> {
  const { data } = await api.post<AssistantAction>(`/api/v1/assistant/actions/${id}/execute`);
  return data;
}

export async function cancelAssistantAction(id: string): Promise<void> {
  await api.post(`/api/v1/assistant/actions/${id}/cancel`);
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
