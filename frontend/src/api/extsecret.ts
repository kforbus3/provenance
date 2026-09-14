import { api } from "./client";

// The external secrets-manager CONNECTION. Credentials are never returned by the
// server — only whether each one is set — so this type has no field that could hold
// one on the way back. The write type below is the only place they appear.
export interface ExtSecretConfig {
  vaultAddr?: string;
  vaultCaCertPem?: string;
  vaultSkipVerify?: boolean;
  vaultTokenSet?: boolean;
  awsRegion?: string;
  awsAccessKey?: string;
  awsEndpoint?: string;
  awsSecretKeySet?: boolean;
  awsSessionSet?: boolean;
  /** Provider names this build understands, for the per-credential picker. */
  providers?: string[];
  /** True when a connection resolves at all — including one supplied only by the
   *  environment, so the screen can say so instead of looking unconfigured. */
  effectiveConfigured?: boolean;
}

// A blank credential means "leave the stored one alone". The screen never receives
// the current value, so it cannot send it back, and clearing is done by clearing the
// address — which is visible, and therefore deliberate.
export interface ExtSecretConfigInput {
  vaultAddr?: string;
  vaultToken?: string;
  vaultCaCertPem?: string;
  vaultSkipVerify?: boolean;
  awsRegion?: string;
  awsAccessKey?: string;
  awsSecretKey?: string;
  awsSessionToken?: string;
  awsEndpoint?: string;
}

export interface ExtSecretTestResult {
  ok: boolean;
  provider?: string;
  fetched?: string;
  error?: string;
}

export async function getExtSecretConfig(): Promise<ExtSecretConfig> {
  const { data } = await api.get<ExtSecretConfig>("/api/v1/settings/extsecret");
  return data;
}

export async function saveExtSecretConfig(input: ExtSecretConfigInput): Promise<void> {
  await api.put("/api/v1/settings/extsecret", input);
}

// Tests the connection as the server RESOLVES it (environment plus saved settings),
// not as it was typed — a check that passes for a configuration the resolver would
// not assemble is worse than none. Save first, then test.
export async function testExtSecret(provider: string, ref?: string): Promise<ExtSecretTestResult> {
  const { data } = await api.post<ExtSecretTestResult>("/api/v1/settings/extsecret/test", { provider, ref: ref ?? "" });
  return data;
}
