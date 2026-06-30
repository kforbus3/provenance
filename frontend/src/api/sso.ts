import { api } from "./client";

// OIDC single sign-on configuration (admin) + a public status probe for the
// login page.

export interface OidcConfig {
  enabled: boolean;
  issuer: string;
  clientId: string;
  clientSecret?: string; // write-only
  scopes?: string[];
  usernameClaim?: string;
  emailClaim?: string;
  groupsClaim?: string;
  defaultRole?: string;
  autoProvision: boolean;
  groupRoleMap?: Record<string, string>;
  buttonText?: string;
}

export async function getOidcConfig(): Promise<{ config: OidcConfig; secretSet: boolean }> {
  const { data } = await api.get<{ config: OidcConfig; secretSet: boolean }>("/api/v1/auth/oidc/config");
  return data;
}

export async function saveOidcConfig(cfg: OidcConfig): Promise<void> {
  await api.put("/api/v1/auth/oidc/config", cfg);
}

export interface OidcStatus {
  enabled: boolean;
  buttonText: string;
}

export async function getOidcStatus(): Promise<OidcStatus> {
  const { data } = await api.get<OidcStatus>("/api/v1/auth/oidc/status");
  return data;
}

// Full-page redirect into the OIDC login flow.
export function oidcLoginUrl(): string {
  return "/api/v1/auth/oidc/login";
}
