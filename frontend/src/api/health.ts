import { api } from "./client";

// System health: a live status report of Fleet's subsystems (admin only).

export interface HealthComponent {
  name: string;
  status: "ok" | "warn" | "error";
  detail: string;
}

export interface SystemHealth {
  overall: "ok" | "warn" | "error";
  components: HealthComponent[];
  checkedAt: string;
  version: string;
}

export async function getSystemHealth(): Promise<SystemHealth> {
  const { data } = await api.get<SystemHealth>("/api/v1/system/health");
  return data;
}
