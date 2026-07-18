import { api } from "./client";

// Scheduled compliance reports: generate the selected CSV evidence reports on a
// weekly/monthly cadence and deliver them (attached) through the configured
// notification channels.

export interface ReportSchedule {
  enabled: boolean;
  reports: string[]; // subset of access|audit|certificates|scans
  frequency: "weekly" | "monthly";
  weekday: number; // 0=Sun..6=Sat (weekly)
  dayOfMonth: number; // 1..28 (monthly)
  hour: number; // 0..23
  lookbackDays: number;
  lastSent?: number;
}

export async function getReportSchedule(): Promise<ReportSchedule> {
  const { data } = await api.get<ReportSchedule>("/api/v1/report-schedule");
  return data;
}

export async function saveReportSchedule(p: ReportSchedule): Promise<ReportSchedule> {
  const { data } = await api.put<ReportSchedule>("/api/v1/report-schedule", p);
  return data;
}

export async function sendReportScheduleNow(): Promise<void> {
  await api.post("/api/v1/report-schedule/send");
}
