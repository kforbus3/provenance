import { api } from "./client";

// Service accounts: non-human identities that authenticate via API tokens (CI/CD,
// IaC, monitoring). A service account carries roles + group host-access like a
// user; its tokens authenticate as it. Managing them requires ServiceAccount.Manage.

export interface ServiceAccount {
  id: string;
  username: string;
  displayName: string;
  isDisabled: boolean;
  createdAt: string;
  roles: string[];
  groups: string[];
  tokenCount: number;
  lastUsedAt?: string;
}

export interface ApiToken {
  id: string;
  name: string;
  prefix: string;
  createdAt: string;
  expiresAt?: string;
  lastUsedAt?: string;
  revokedAt?: string;
  secret?: string; // present only in the create response
}

export async function listServiceAccounts(): Promise<ServiceAccount[]> {
  const { data } = await api.get<{ serviceAccounts: ServiceAccount[] }>("/api/v1/service-accounts");
  return data.serviceAccounts ?? [];
}

export async function createServiceAccount(input: {
  username: string;
  displayName: string;
  roleIds: string[];
  groupIds: string[];
}): Promise<ServiceAccount> {
  const { data } = await api.post<ServiceAccount>("/api/v1/service-accounts", input);
  return data;
}

export async function updateServiceAccount(
  id: string,
  patch: { displayName?: string; disabled?: boolean; roleIds?: string[]; groupIds?: string[] },
): Promise<ServiceAccount> {
  const { data } = await api.patch<ServiceAccount>(`/api/v1/service-accounts/${id}`, patch);
  return data;
}

export async function deleteServiceAccount(id: string): Promise<void> {
  await api.delete(`/api/v1/service-accounts/${id}`);
}

export async function listTokens(saId: string): Promise<ApiToken[]> {
  const { data } = await api.get<{ tokens: ApiToken[] }>(`/api/v1/service-accounts/${saId}/tokens`);
  return data.tokens ?? [];
}

export async function createToken(
  saId: string,
  input: { name: string; expiresInDays: number },
): Promise<ApiToken> {
  const { data } = await api.post<ApiToken>(`/api/v1/service-accounts/${saId}/tokens`, input);
  return data;
}

export async function revokeToken(saId: string, tokenId: string): Promise<void> {
  await api.delete(`/api/v1/service-accounts/${saId}/tokens/${tokenId}`);
}
