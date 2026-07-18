import { api } from "./client";

// Credential vault: store static credentials (passwords, SSH keys, API keys)
// encrypted at rest, control access with per-secret grants, and reveal the
// plaintext through an audited endpoint. Secret material is only ever sent on
// create/update (to store) and returned on an explicit reveal.

export interface VaultSecret {
  id: string;
  name: string;
  folder: string;
  type: string; // password | ssh_key | api_key | generic
  username: string;
  target: string;
  description: string;
  version: number;
  createdBy?: string;
  createdAt: string;
  updatedAt: string;
  access?: string; // caller's effective access: view | use | manage
}

export interface VaultGrant {
  id: string;
  secretId: string;
  subjectKind: string; // user | group
  subjectId: string;
  subjectName?: string;
  access: string; // view | use | manage
  createdAt: string;
}

export interface VaultSecretInput {
  name: string;
  folder: string;
  type: string;
  username: string;
  target: string;
  description: string;
  secret?: string; // plaintext; on update, empty leaves the value unchanged
}

export async function listVaultSecrets(): Promise<VaultSecret[]> {
  const { data } = await api.get<{ secrets: VaultSecret[] }>("/api/v1/vault/secrets");
  return data.secrets ?? [];
}

export async function createVaultSecret(input: VaultSecretInput): Promise<VaultSecret> {
  const { data } = await api.post<VaultSecret>("/api/v1/vault/secrets", input);
  return data;
}

export async function updateVaultSecret(id: string, input: VaultSecretInput): Promise<VaultSecret> {
  const { data } = await api.put<VaultSecret>(`/api/v1/vault/secrets/${id}`, input);
  return data;
}

export async function deleteVaultSecret(id: string): Promise<void> {
  await api.delete(`/api/v1/vault/secrets/${id}`);
}

export async function revealVaultSecret(id: string): Promise<string> {
  const { data } = await api.post<{ secret: string }>(`/api/v1/vault/secrets/${id}/reveal`);
  return data.secret;
}

export async function listVaultGrants(id: string): Promise<VaultGrant[]> {
  const { data } = await api.get<{ grants: VaultGrant[] }>(`/api/v1/vault/secrets/${id}/grants`);
  return data.grants ?? [];
}

export async function createVaultGrant(id: string, input: { subjectKind: string; subjectId: string; access: string }): Promise<VaultGrant> {
  const { data } = await api.post<VaultGrant>(`/api/v1/vault/secrets/${id}/grants`, input);
  return data;
}

export async function deleteVaultGrant(id: string, grantId: string): Promise<void> {
  await api.delete(`/api/v1/vault/secrets/${id}/grants/${grantId}`);
}
