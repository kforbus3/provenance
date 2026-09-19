import { api } from "./client";

// Searching the Aldgate collector through Provenance, never directly.
//
// The collector's credential lives on the Provenance server, every query is
// audited against the person who ran it, and Logs.View decides who may run one.
// A browser talking to OpenSearch would give up all three.

export type LogEntry = {
  timestamp: string;
  receivedAt?: string;
  host: string;
  program: string;
  severity: string;
  severityCode: number;
  facility?: string;
  message: string;
  sourceAddress?: string;
};

export type LogBucket = { key: string; count: number };

export type LogResult = {
  total: number;
  entries: LogEntry[];
  byHost: LogBucket[];
  bySeverity: LogBucket[];
  tookMs: number;
};

export type LogStatus = {
  configured: boolean;
  reachable?: boolean;
  url?: string;
  hostsSending?: number;
  error?: string;
  hint?: string;
};

export type LogQuery = {
  q?: string;
  host?: string;
  program?: string;
  minSeverity?: number;
  since?: string;
  until?: string;
  limit?: number;
  order?: "asc" | "desc";
};

// Whether a collector is configured at all, kept separate from searching.
// "No logs matched" and "no collector" look identical in an empty table and are
// completely different problems.
export async function logStatus(): Promise<LogStatus> {
  const { data } = await api.get<LogStatus>("/api/v1/logs/status");
  return data;
}

export async function logHosts(since?: string): Promise<LogBucket[]> {
  const { data } = await api.get<{ hosts: LogBucket[] }>("/api/v1/logs/hosts", {
    params: { since },
  });
  return data.hosts ?? [];
}

export async function searchLogs(q: LogQuery): Promise<LogResult> {
  const { data } = await api.get<LogResult>("/api/v1/logs/search", { params: q });
  return data;
}

export type LogConsole = {
  consoleBase: string;
  /** "view" (read-only) or "administer" — decided from your Provenance role. */
  tier: string;
  expiresAt: string;
};

/**
 * Open the log console as yourself.
 *
 * The console used to ask for a username and password of its own, which meant the
 * only credential that worked was the collector's admin account and a Provenance
 * role had nothing to do with what you could do once inside. This asks Provenance
 * for a short-lived console session instead: it sets an HttpOnly cookie scoped to
 * the console's path, and every request the console then makes is authorised
 * server-side with the collector credential your permissions earn. No password is
 * typed and none is sent to the browser.
 *
 * Called before opening the tab rather than on page load: it mints a credential
 * and is audited, so it belongs to an explicit action.
 */
export async function openLogConsole(): Promise<LogConsole> {
  const { data } = await api.post<LogConsole>("/api/v1/logs/console-token", {});
  return data;
}
