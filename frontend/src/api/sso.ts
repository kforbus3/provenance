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

// --- LDAP / Active Directory ---

export interface LdapConfig {
  enabled: boolean;
  url: string;
  startTls: boolean;
  bindDn: string;
  bindPassword?: string; // write-only
  baseDn: string;
  userFilter?: string;
  usernameAttr?: string;
  emailAttr?: string;
  displayNameAttr?: string;
  groupsAttr?: string;
  defaultRole?: string;
  autoProvision: boolean;
  groupRoleMap?: Record<string, string>;
}

export async function getLdapConfig(): Promise<{ config: LdapConfig; secretSet: boolean }> {
  const { data } = await api.get<{ config: LdapConfig; secretSet: boolean }>("/api/v1/auth/ldap/config");
  return data;
}

export async function saveLdapConfig(cfg: LdapConfig): Promise<void> {
  await api.put("/api/v1/auth/ldap/config", cfg);
}
