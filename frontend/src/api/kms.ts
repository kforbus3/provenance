import { api } from "./client";

// Read-only status of the external KMS/HSM backend that envelope-protects Fleet's
// master passphrases. Configuration is boot-time environment only — there is no
// write path from the UI.
export interface KMSStatus {
  provider: string;
  enabled: boolean;
  keyId: string;
  caPassphraseWrapped: boolean;
  vaultPassphraseWrapped: boolean;
  healthy: boolean;
  health: string; // "ok" | "n/a" | error message
}

export async function getKMSStatus(): Promise<KMSStatus> {
  const { data } = await api.get<KMSStatus>("/api/v1/kms/status");
  return data;
}
