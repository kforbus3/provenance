import { api } from "./client";

// Forward audit events to an external collector (syslog or HTTP) for SIEM.

export interface AuditForwardConfig {
  enabled: boolean;
  type: "syslog" | "http";
  address: string;
  protocol: "udp" | "tcp";
  // Syslog TLS (RFC 5425). An https:// address covers the http type instead.
  tls?: boolean;
  insecureSkipVerify?: boolean;
  caCertPem?: string;
  // Write-only. The stored token is never returned; tokenSet says whether one
  // exists. Omitting it on save keeps the stored one rather than clearing it —
  // which is what this type not having the field at all used to do, since the save
  // replaced the whole record and the UI could not send what it did not model.
  token?: string;
  tokenSet?: boolean;
}

export async function getAuditForwarding(): Promise<AuditForwardConfig> {
  const { data } = await api.get<AuditForwardConfig>("/api/v1/audit/forwarding");
  return data;
}

export async function saveAuditForwarding(cfg: AuditForwardConfig): Promise<AuditForwardConfig> {
  const { data } = await api.put<AuditForwardConfig>("/api/v1/audit/forwarding", cfg);
  return data;
}

// With no argument, tests the saved configuration — which is what pressing Test
// after saving means. Passing one tests that instead, so a target can be tried
// before it is stored.
export async function testAuditForwarding(
  cfg?: AuditForwardConfig,
): Promise<{ ok: boolean; error?: string }> {
  const { data } = await api.post<{ ok: boolean; error?: string }>(
    "/api/v1/audit/forwarding/test", cfg ?? {});
  return data;
}
