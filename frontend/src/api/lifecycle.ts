import { api } from "./client";

// A single credential/certificate lifecycle attention item. All metadata — never
// secret material.
export interface LifecycleItem {
  kind: "api_token" | "credential" | "password" | "ca_key";
  id: string;
  name: string;
  owner: string;
  status: "expired" | "expiring" | "stale" | "aging";
  dueAt: string | null;
  ageDays: number;
}

export interface LifecycleReport {
  items: LifecycleItem[];
  counts: Record<string, number>;
  generatedAt: string;
}

export async function getLifecycleReport(): Promise<LifecycleReport> {
  const { data } = await api.get<LifecycleReport>("/api/v1/lifecycle/expiry");
  return { items: data.items ?? [], counts: data.counts ?? {}, generatedAt: data.generatedAt };
}
