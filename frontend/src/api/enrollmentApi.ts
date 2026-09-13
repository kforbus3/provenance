import { api } from "./client";

export interface EnrollmentStep {
  name: string;
  status: string;
  detail?: string;
  timestamp: string;
}

export interface EnrollmentJob {
  id: string;
  hostId?: string;
  target: string;
  status: string;
  steps: EnrollmentStep[];
  error?: string;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
}

export async function listEnrollmentJobs(limit = 100): Promise<EnrollmentJob[]> {
  const { data } = await api.get<{ jobs: EnrollmentJob[] }>(`/api/v1/enrollment/jobs?limit=${limit}`);
  return data.jobs ?? [];
}

// clearEnrollmentJobs removes all finished (non-running) jobs and returns the count.
export async function clearEnrollmentJobs(): Promise<number> {
  const { data } = await api.delete<{ deleted: number }>("/api/v1/enrollment/jobs");
  return data.deleted ?? 0;
}

export interface LoginAccountMigration {
  host: string;
  from: string;
  to: string;
  migrated: boolean;
  steps: string[];
}

// migrateLoginAccount moves one host onto a different Provenance login account.
// The backend creates and verifies the new account before removing the old one,
// so a failure here means the host is still reachable through the account it has.
export async function migrateLoginAccount(hostId: string, user?: string): Promise<LoginAccountMigration> {
  const { data } = await api.post<LoginAccountMigration>(`/api/v1/hosts/${hostId}/login-account`, { user: user ?? "" });
  return data;
}
