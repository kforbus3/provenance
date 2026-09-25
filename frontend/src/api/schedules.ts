import { api } from "./client";

// Recurring scans and playbook runs. Schedules are disabled until enabled.

export interface Recurrence {
  type: "interval" | "daily" | "weekly";
  everyMinutes?: number;
  timeOfDay?: string; // "HH:MM"
  weekday?: number; // 0=Sun … 6=Sat
}

export interface Schedule {
  id: string;
  name: string;
  kind: "scan" | "vulnscan" | "playbook" | "script" | "vulndb";
  enabled: boolean;
  targetKind: "host" | "group";
  targetId?: string;
  targetName?: string;
  recurrence: Recurrence;
  payload?: unknown;
  requester?: string;
  lastRunAt?: string;
  // What FIRING did ("started", "skipped: no hosts", "error: …"). It never changes
  // afterwards, so on its own every schedule reads "started" forever.
  lastStatus?: string;
  // What the firing PRODUCED, derived from the runs it created: "completed",
  // "failed", "running", or absent when it produced nothing. This is the answer to
  // "did it work".
  lastOutcome?: "completed" | "failed" | "running" | "";
  // How many records the last firing launched, and how many completed. A launched
  // record that has since been deleted counts against lastRunOk.
  lastRunTotal?: number;
  lastRunOk?: number;
  // The targeted host or group has been deleted (and the schedule disabled with it).
  targetMissing?: boolean;
  nextRunAt?: string;
  running?: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ScheduleInput {
  name: string;
  kind: "scan" | "vulnscan" | "playbook" | "script" | "vulndb";
  enabled: boolean;
  targetKind: "host" | "group";
  targetId: string;
  recurrence: Recurrence;
  payload: unknown;
}

export async function listSchedules(): Promise<Schedule[]> {
  const { data } = await api.get<{ schedules: Schedule[] }>("/api/v1/schedules");
  return data.schedules ?? [];
}

export async function createSchedule(input: ScheduleInput): Promise<Schedule> {
  const { data } = await api.post<Schedule>("/api/v1/schedules", input);
  return data;
}

export async function updateSchedule(id: string, input: ScheduleInput): Promise<Schedule> {
  const { data } = await api.put<Schedule>(`/api/v1/schedules/${id}`, input);
  return data;
}

export async function deleteSchedule(id: string): Promise<void> {
  await api.delete(`/api/v1/schedules/${id}`);
}

export async function setScheduleEnabled(id: string, enabled: boolean): Promise<Schedule> {
  const { data } = await api.post<Schedule>(`/api/v1/schedules/${id}/enable`, { enabled });
  return data;
}

export async function runScheduleNow(id: string): Promise<{ status: string }> {
  const { data } = await api.post<{ status: string }>(`/api/v1/schedules/${id}/run`, {});
  return data;
}
