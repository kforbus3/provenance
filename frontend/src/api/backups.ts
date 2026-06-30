import { api, getAccessToken } from "./client";

// Encrypted database backups + scheduled-backup policy.

export interface BackupInfo {
  name: string;
  size: number;
  createdAt: string;
}

export interface BackupPolicy {
  enabled: boolean;
  intervalHours: number;
  retentionCount: number;
}

export async function listBackups(): Promise<{ backups: BackupInfo[]; dir: string }> {
  const { data } = await api.get<{ backups: BackupInfo[]; dir: string }>("/api/v1/system/backups");
  return { backups: data.backups ?? [], dir: data.dir };
}

export async function createBackup(): Promise<BackupInfo> {
  const { data } = await api.post<BackupInfo>("/api/v1/system/backups", {});
  return data;
}

export async function getBackupPolicy(): Promise<BackupPolicy> {
  const { data } = await api.get<BackupPolicy>("/api/v1/system/backup-policy");
  return data;
}

export async function saveBackupPolicy(p: BackupPolicy): Promise<BackupPolicy> {
  const { data } = await api.put<BackupPolicy>("/api/v1/system/backup-policy", p);
  return data;
}

export function backupDownloadUrl(name: string): string {
  const token = getAccessToken() ?? "";
  return `/api/v1/system/backups/${encodeURIComponent(name)}?token=${encodeURIComponent(token)}`;
}
