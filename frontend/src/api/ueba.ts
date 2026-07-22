import { api } from "./client";

// User-and-entity behavior analytics: access-pattern anomalies computed from session
// records (off-hours access, first host access, new source IP, activity spikes).
export interface Anomaly {
  userId: string;
  username: string;
  type: "off_hours" | "new_host" | "new_source_ip" | "activity_spike" | string;
  severity: "info" | "warning" | string;
  title: string;
  detail: string;
  host?: string;
  when: string;
}

export interface UEBAResult {
  anomalies: Anomaly[];
  analyzed: number;
  lookbackDays: number;
  recentHours: number;
  generatedAt: string;
}

export async function getAnomalies(): Promise<UEBAResult> {
  const { data } = await api.get<UEBAResult>("/api/v1/ueba/anomalies");
  return data;
}
