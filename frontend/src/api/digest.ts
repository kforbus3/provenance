import { api } from "./client";

// Scheduled fleet-health digest: a recurring summary built from the same insights
// as the dashboard, delivered through the configured notification channels.

export interface DigestPolicy {
  enabled: boolean;
  frequency: "daily" | "weekly";
  hour: number; // 0-23, server local time
  weekday: number; // 0=Sun .. 6=Sat (weekly only)
  lastSent?: number;
}

export async function getDigest(): Promise<DigestPolicy> {
  const { data } = await api.get<DigestPolicy>("/api/v1/digest");
  return data;
}

export async function saveDigest(p: DigestPolicy): Promise<DigestPolicy> {
  const { data } = await api.put<DigestPolicy>("/api/v1/digest", p);
  return data;
}

export interface DigestPreview {
  title: string;
  body: string;
  severity: string;
}

export async function previewDigest(): Promise<DigestPreview> {
  const { data } = await api.get<DigestPreview>("/api/v1/digest/preview");
  return data;
}

export async function sendDigest(): Promise<void> {
  await api.post("/api/v1/digest/send");
}
