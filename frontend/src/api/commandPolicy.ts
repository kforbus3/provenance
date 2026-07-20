import { api } from "./client";

export type CommandAction = "flag" | "block" | "approval";

export interface CommandPolicy {
  id: string;
  name: string;
  pattern: string;
  action: CommandAction;
  scopeKind: "global" | "group";
  scopeGroupId?: string;
  scopeGroupName?: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CommandPolicyInput {
  name: string;
  pattern: string;
  action: CommandAction;
  scopeKind: "global" | "group";
  scopeGroupId?: string | null;
  enabled: boolean;
}

export interface CommandApproval {
  id: string;
  userId: string;
  username: string;
  hostId?: string;
  hostname: string;
  command: string;
  status: string;
  requestedAt: string;
}

export async function listCommandPolicies(): Promise<CommandPolicy[]> {
  const { data } = await api.get<{ rules: CommandPolicy[] }>("/api/v1/command-policies");
  return data.rules ?? [];
}

export async function createCommandPolicy(input: CommandPolicyInput): Promise<void> {
  await api.post("/api/v1/command-policies", input);
}

export async function updateCommandPolicy(id: string, input: CommandPolicyInput): Promise<void> {
  await api.put(`/api/v1/command-policies/${id}`, input);
}

export async function deleteCommandPolicy(id: string): Promise<void> {
  await api.delete(`/api/v1/command-policies/${id}`);
}

export async function listCommandApprovals(): Promise<CommandApproval[]> {
  const { data } = await api.get<{ approvals: CommandApproval[] }>("/api/v1/command-approvals");
  return data.approvals ?? [];
}

export async function approveCommand(id: string): Promise<void> {
  await api.post(`/api/v1/command-approvals/${id}/approve`);
}

export async function denyCommand(id: string): Promise<void> {
  await api.post(`/api/v1/command-approvals/${id}/deny`);
}
