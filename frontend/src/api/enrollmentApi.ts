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
  oldAccountLeft: boolean;
  steps: string[];
}

export interface MigrateLoginAccountOptions {
  user?: string;
  // Delete the superseded account and its on-host artefacts. Defaults to false:
  // adopting the new account is reversible, deleting the old one is not.
  removeOld?: boolean;
  // Required to touch a host Provenance's own access depends on.
  confirmControlPlane?: boolean;
}

// migrateLoginAccount moves one host onto a different Provenance login account.
// The backend creates the new account, proves a certificate login as it, and
// records it — in that order — before it will consider removing the old one, so a
// failure at any point leaves the host reachable on the account it has.
export async function migrateLoginAccount(
  hostId: string,
  opts: MigrateLoginAccountOptions = {},
): Promise<LoginAccountMigration> {
  const { data } = await api.post<LoginAccountMigration>(
    `/api/v1/hosts/${hostId}/login-account`,
    { user: opts.user ?? "", removeOld: !!opts.removeOld, confirmControlPlane: !!opts.confirmControlPlane },
  );
  return data;
}
