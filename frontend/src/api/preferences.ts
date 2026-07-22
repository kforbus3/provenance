import { api } from "./client";

// Per-user UI preferences: small JSON values that follow the user across devices.
// value is null when the user hasn't set this preference (apply a client default).
export async function getPreference<T>(key: string): Promise<T | null> {
  const { data } = await api.get<{ key: string; value: T | null }>(`/api/v1/preferences/${key}`);
  return data.value ?? null;
}

export async function setPreference<T>(key: string, value: T): Promise<void> {
  await api.put(`/api/v1/preferences/${key}`, { value });
}

// The Dashboard Quick Connect pin list.
export const QUICK_CONNECT_PREF = "dashboard.quickConnect";
export interface QuickConnectPref {
  hostIds: string[];
}
