import { api } from "./client";

// Outbound notification settings (email / webhook) + per-event routing. The SMTP
// password is write-only: the server stores it encrypted and never returns it.

export interface EmailConfig {
  enabled: boolean;
  host: string;
  port: number;
  username: string;
  password?: string; // only sent when changing it
  from: string;
  to: string;
  security: string; // starttls | tls | none
}

export interface WebhookConfig {
  enabled: boolean;
  url: string;
  format: string; // json | slack | discord | teams
}

export interface PagerDutyConfig {
  enabled: boolean;
  routingKey?: string; // only sent when changing it
  minSeverity: string; // info | warning | error
}

export interface OpsgenieConfig {
  enabled: boolean;
  apiKey?: string; // only sent when changing it
  region: string; // us | eu
  minSeverity: string;
}

export interface NotificationConfig {
  email: EmailConfig;
  webhook: WebhookConfig;
  pagerduty: PagerDutyConfig;
  opsgenie: OpsgenieConfig;
  events: Record<string, { email: boolean; webhook: boolean }>;
  throttleMinutes: number;
  passwordSet?: boolean;
  pagerdutyKeySet?: boolean;
  opsgenieKeySet?: boolean;
}

export interface EventType {
  key: string;
  label: string;
}

export async function getNotifications(): Promise<NotificationConfig> {
  const { data } = await api.get<NotificationConfig>("/api/v1/notifications");
  return data;
}

export async function saveNotifications(cfg: NotificationConfig): Promise<NotificationConfig> {
  const { data } = await api.put<NotificationConfig>("/api/v1/notifications", cfg);
  return data;
}

export async function testNotification(channel: "email" | "webhook" | "pagerduty" | "opsgenie"): Promise<{ ok: boolean; error?: string }> {
  const { data } = await api.post<{ ok: boolean; error?: string }>("/api/v1/notifications/test", { channel });
  return data;
}

export async function listEventTypes(): Promise<EventType[]> {
  const { data } = await api.get<{ events: EventType[] }>("/api/v1/notifications/events");
  return data.events ?? [];
}
