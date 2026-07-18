import { api } from "./client";

// Typed wrappers over the admin surface (/users /roles /groups /permissions
// /settings). Response envelopes mirror the backend's map[string]any shapes.

export interface User {
  id: string;
  username: string;
  email?: string;
  displayName: string;
  isSuperAdmin: boolean;
  isDisabled: boolean;
  emailVerified: boolean;
  mustChangePassword: boolean;
  requireMfa: boolean;
  lockedUntil?: string;
  lastLoginAt?: string;
  createdAt: string;
  updatedAt: string;
  roles?: string[];
  groups?: string[];
}

export interface Role {
  id: string;
  name: string;
  description: string;
  isBuiltin: boolean;
  createdAt: string;
  permissions?: string[];
}

export interface Permission {
  key: string;
  description: string;
}

export interface GroupRule {
  environment?: string;
  tagsAll?: string[];
  tagsAny?: string[];
  osContains?: string;
  hostnameContains?: string;
}

export interface Group {
  id: string;
  name: string;
  description: string;
  createdAt: string;
  rule?: GroupRule; // present = dynamic (rule-managed) membership
}

export interface CreateUserInput {
  username: string;
  email: string;
  displayName: string;
  password: string;
  isSuperAdmin: boolean;
  mustChangePassword: boolean;
}

export interface UpdateUserInput {
  email: string;
  displayName: string;
  isDisabled: boolean;
}

export async function listUsers(): Promise<User[]> {
  const { data } = await api.get<{ users: User[] }>("/api/v1/users");
  return data.users;
}

export async function createUser(input: CreateUserInput): Promise<User> {
  const { data } = await api.post<User>("/api/v1/users", input);
  return data;
}

export async function updateUser(id: string, input: UpdateUserInput): Promise<void> {
  await api.put(`/api/v1/users/${id}`, input);
}

export async function deleteUser(id: string): Promise<void> {
  await api.delete(`/api/v1/users/${id}`);
}

export async function setUserDisabled(id: string, disabled: boolean): Promise<void> {
  await api.post(`/api/v1/users/${id}/disable`, { disabled });
}

export async function unlockUser(id: string): Promise<void> {
  await api.post(`/api/v1/users/${id}/unlock`);
}

export async function assignUserRole(userId: string, roleId: string): Promise<void> {
  await api.post(`/api/v1/users/${userId}/roles/${roleId}`);
}

export async function removeUserRole(userId: string, roleId: string): Promise<void> {
  await api.delete(`/api/v1/users/${userId}/roles/${roleId}`);
}

export async function setUserRequireMFA(id: string, require: boolean): Promise<void> {
  await api.post(`/api/v1/users/${id}/require-mfa`, { require });
}

// Global "require MFA for all users" toggle, stored as a system setting.
export async function getGlobalRequireMFA(): Promise<boolean> {
  try {
    const { data } = await api.get<{ value?: { enabled?: boolean } }>("/api/v1/settings/require_mfa");
    return !!data?.value?.enabled;
  } catch {
    return false; // 404 when unset = MFA optional
  }
}

export async function setGlobalRequireMFA(enabled: boolean): Promise<void> {
  await api.put("/api/v1/settings/require_mfa", { enabled });
}

export async function resetUserPassword(id: string, newPassword: string, mustChangePassword: boolean): Promise<void> {
  await api.post(`/api/v1/users/${id}/reset-password`, { newPassword, mustChangePassword });
}

export async function resetUserMFA(id: string): Promise<void> {
  await api.post(`/api/v1/users/${id}/reset-mfa`);
}

export async function terminateUserSessions(id: string): Promise<void> {
  await api.post(`/api/v1/users/${id}/terminate-sessions`);
}

export interface AuthEvent {
  id: number;
  event: string;
  ip?: string;
  userAgent?: string;
  createdAt: string;
}

export async function userLoginHistory(id: string): Promise<AuthEvent[]> {
  const { data } = await api.get<{ events: AuthEvent[] }>(`/api/v1/users/${id}/login-history`);
  return data.events ?? [];
}

export interface UserHostAccess {
  id: string;
  hostname: string;
  description: string;
  environment: string;
  owner: string;
  address: string;
  viaDirect: boolean;
  viaGroup: boolean;
  viaTemp: boolean;
  denied: boolean;
}

// userHostAccess returns every host the user can reach, annotated with the
// source(s) of access and whether an admin has revoked (denied) it.
export async function userHostAccess(id: string): Promise<UserHostAccess[]> {
  const { data } = await api.get<{ hosts: UserHostAccess[]; count: number }>(`/api/v1/users/${id}/host-access`);
  return data.hosts ?? [];
}

export async function revokeUserHostAccess(userId: string, hostId: string): Promise<void> {
  await api.post(`/api/v1/users/${userId}/host-access/${hostId}/revoke`);
}

export async function restoreUserHostAccess(userId: string, hostId: string): Promise<void> {
  await api.post(`/api/v1/users/${userId}/host-access/${hostId}/restore`);
}

export async function listRoles(): Promise<Role[]> {
  const { data } = await api.get<{ roles: Role[] }>("/api/v1/roles");
  return data.roles;
}

export async function createRole(name: string, description: string): Promise<Role> {
  const { data } = await api.post<Role>("/api/v1/roles", { name, description });
  return data;
}

export async function deleteRole(id: string): Promise<void> {
  await api.delete(`/api/v1/roles/${id}`);
}

export async function setRolePermissions(id: string, permissions: string[]): Promise<void> {
  await api.put(`/api/v1/roles/${id}/permissions`, { permissions });
}

export async function listPermissions(): Promise<Permission[]> {
  const { data } = await api.get<{ permissions: Permission[] }>("/api/v1/permissions");
  return data.permissions;
}

export async function listGroups(): Promise<Group[]> {
  const { data } = await api.get<{ groups: Group[] }>("/api/v1/groups");
  return data.groups;
}

export async function createGroup(name: string, description: string, rule?: GroupRule): Promise<Group> {
  const { data } = await api.post<Group>("/api/v1/groups", { name, description, rule });
  return data;
}

// updateGroupRule sets (or clears, with an empty rule) a group's dynamic
// membership rule and returns the recomputed group.
export async function updateGroupRule(id: string, rule: GroupRule | null): Promise<Group> {
  const { data } = await api.put<Group>(`/api/v1/groups/${id}`, { rule });
  return data;
}

export async function deleteGroup(id: string): Promise<void> {
  await api.delete(`/api/v1/groups/${id}`);
}

export async function addUserToGroup(userId: string, groupId: string): Promise<void> {
  await api.post(`/api/v1/users/${userId}/groups/${groupId}`);
}

export async function removeUserFromGroup(userId: string, groupId: string): Promise<void> {
  await api.delete(`/api/v1/users/${userId}/groups/${groupId}`);
}

export type Settings = Record<string, unknown>;

export async function listSettings(): Promise<Settings> {
  const { data } = await api.get<{ settings: Settings }>("/api/v1/settings");
  return data.settings ?? {};
}

export async function setSetting(key: string, value: unknown): Promise<void> {
  await api.put(`/api/v1/settings/${encodeURIComponent(key)}`, value);
}
