import { api } from "./client";

// Forward audit events to an external collector (syslog or HTTP) for SIEM.

export interface AuditForwardConfig {
  enabled: boolean;
  type: "syslog" | "http";
  address: string;
  protocol: "udp" | "tcp";
}

export async function getAuditForwarding(): Promise<AuditForwardConfig> {
  const { data } = await api.get<AuditForwardConfig>("/api/v1/audit/forwarding");
  return data;
}

export async function saveAuditForwarding(cfg: AuditForwardConfig): Promise<AuditForwardConfig> {
  const { data } = await api.put<AuditForwardConfig>("/api/v1/audit/forwarding", cfg);
  return data;
}

export async function testAuditForwarding(cfg: AuditForwardConfig): Promise<{ ok: boolean; error?: string }> {
  const { data } = await api.post<{ ok: boolean; error?: string }>("/api/v1/audit/forwarding/test", cfg);
  return data;
}
