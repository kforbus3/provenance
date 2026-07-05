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
  kind: "scan" | "playbook";
  enabled: boolean;
  targetKind: "host" | "group";
  targetId?: string;
  targetName?: string;
  recurrence: Recurrence;
  payload?: unknown;
  requester?: string;
  lastRunAt?: string;
  lastStatus?: string;
  nextRunAt?: string;
  running?: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ScheduleInput {
  name: string;
  kind: "scan" | "playbook";
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
