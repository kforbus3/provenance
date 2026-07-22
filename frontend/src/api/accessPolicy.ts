import { api } from "./client";

// Attribute-based access-control (ABAC) policies: contextual deny rules evaluated at
// connect time on top of RBAC. See the Access Policies page.
export interface AccessPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  effect: string; // "deny"
  environments: string[];
  tags: string[];
  protocols: string[];
  exemptRoles: string[];
  activeDays: number[]; // 0=Sunday..6=Saturday; empty = all days
  activeStartMin: number;
  activeEndMin: number;
  denyMessage: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface AccessPolicyInput {
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  environments: string[];
  tags: string[];
  protocols: string[];
  exemptRoles: string[];
  activeDays: number[];
  activeStartMin: number;
  activeEndMin: number;
  denyMessage: string;
}

export async function listAccessPolicies(): Promise<AccessPolicy[]> {
  const { data } = await api.get<{ policies: AccessPolicy[] }>("/api/v1/access-policies");
  return data.policies ?? [];
}

export async function createAccessPolicy(input: AccessPolicyInput): Promise<AccessPolicy> {
  const { data } = await api.post<AccessPolicy>("/api/v1/access-policies", input);
  return data;
}

export async function updateAccessPolicy(id: string, input: AccessPolicyInput): Promise<AccessPolicy> {
  const { data } = await api.put<AccessPolicy>(`/api/v1/access-policies/${id}`, input);
  return data;
}

export async function deleteAccessPolicy(id: string): Promise<void> {
  await api.delete(`/api/v1/access-policies/${id}`);
}
