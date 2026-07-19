import { api } from "./client";

export interface SchedulerStatus {
  name: string;
  runs: number;
  lastRunAt?: string;
  lastError?: string;
  ok: boolean;
}

export interface EnrollmentStep {
  name: string;
  status: string;
  detail?: string;
  timestamp: string;
}

export interface EnrollmentJob {
  id: string;
  target: string;
  status: string;
  error?: string;
  steps: EnrollmentStep[];
  createdAt: string;
  finishedAt?: string;
}

export interface RemediationJob {
  id: string;
  hostId: string;
  hostname: string;
  requester?: string;
  ruleCount: number;
  status: string; // pending | running | completed | failed
  exitCode?: number;
  error?: string;
  startedAt?: string;
  finishedAt?: string;
  createdAt: string;
}

export interface ClusterInstance {
  id: string;
  hostname: string;
  version: string;
  isLeader: boolean;
  startedAt: string;
  lastHeartbeat: string;
}

export interface JobsResponse {
  schedulers: SchedulerStatus[];
  enrollmentJobs: EnrollmentJob[];
  remediationJobs: RemediationJob[];
  cluster?: ClusterInstance[] | null;
}

export async function getJobs(): Promise<JobsResponse> {
  const { data } = await api.get<JobsResponse>("/api/v1/system/jobs");
  return data;
}

// downloadBackup streams a pg_dump of the database and saves it locally.
export async function downloadBackup(): Promise<void> {
  const res = await api.get("/api/v1/system/backup", { responseType: "blob" });
  const url = URL.createObjectURL(res.data as Blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `fleet-backup-${Date.now()}.sql`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
