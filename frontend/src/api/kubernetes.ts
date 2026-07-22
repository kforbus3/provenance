import { api } from "./client";

// Brokered Kubernetes access: register clusters and reach them through Fleet, which
// injects a vaulted bearer token and audits every call.
export interface K8sCluster {
  id: string;
  name: string;
  apiServer: string;
  credentialId?: string;
  credentialName?: string;
  insecureTls: boolean;
  namespace: string;
  description: string;
  createdBy?: string;
  createdAt: string;
  updatedAt: string;
}

export interface K8sClusterInput {
  name: string;
  apiServer: string;
  credentialId?: string | null;
  caCert: string;
  insecureTls: boolean;
  namespace: string;
  description: string;
}

export interface K8sResourceRow {
  name: string;
  namespace: string;
  status: string;
  created: string;
}

export async function listClusters(): Promise<K8sCluster[]> {
  const { data } = await api.get<{ clusters: K8sCluster[] }>("/api/v1/k8s/clusters");
  return data.clusters ?? [];
}

export async function createCluster(input: K8sClusterInput): Promise<K8sCluster> {
  const { data } = await api.post<K8sCluster>("/api/v1/k8s/clusters", input);
  return data;
}

export async function updateCluster(id: string, input: K8sClusterInput): Promise<K8sCluster> {
  const { data } = await api.put<K8sCluster>(`/api/v1/k8s/clusters/${id}`, input);
  return data;
}

export async function deleteCluster(id: string): Promise<void> {
  await api.delete(`/api/v1/k8s/clusters/${id}`);
}

export async function listResources(id: string, kind: string, namespace?: string): Promise<K8sResourceRow[]> {
  const { data } = await api.get<{ items: K8sResourceRow[] }>(
    `/api/v1/k8s/clusters/${id}/resources`,
    { params: { kind, namespace } },
  );
  return data.items ?? [];
}
