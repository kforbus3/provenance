import { api } from "./client";

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  kind: "provider" | "customer";
  status: "active" | "suspended";
  createdAt: string;
  updatedAt: string;
  userCount: number;
  hostCount: number;
}

export async function listTenants(): Promise<Tenant[]> {
  const { data } = await api.get<{ tenants: Tenant[] }>("/api/v1/tenants");
  return data.tenants ?? [];
}

export async function createTenant(name: string): Promise<Tenant> {
  const { data } = await api.post<Tenant>("/api/v1/tenants", { name });
  return data;
}

export async function renameTenant(id: string, name: string): Promise<void> {
  await api.patch(`/api/v1/tenants/${id}`, { name });
}

export async function setTenantStatus(id: string, status: "active" | "suspended"): Promise<void> {
  await api.post(`/api/v1/tenants/${id}/status`, { status });
}
