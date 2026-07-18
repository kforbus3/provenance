import { api } from "./client";

// Fleet insights: explainable, at-a-glance health observations derived from host
// status/metrics and metric-history trends. Scoped to hosts the caller can access.

export interface Insight {
  severity: "critical" | "warning" | "info";
  category: string; // offline|disk|disk-runway|memory|load|updates
  hostId: string;
  hostname: string;
  title: string;
  detail: string;
}

export async function listInsights(): Promise<Insight[]> {
  const { data } = await api.get<{ insights: Insight[] }>("/api/v1/insights");
  return data.insights ?? [];
}
