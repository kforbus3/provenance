import { api } from "./client";

// Brokered Kubernetes access: register clusters and reach them through Provenance, which
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

// Mint a scoped token and download a kubeconfig that reaches every cluster you
// can see, through the broker. One call: a token with nothing to point at is
// useless, and so is a config with no credential.
//
// The token appears exactly once, inside the file — Provenance keeps only its
// hash — so this triggers a download rather than returning a string something
// might log.
export async function downloadKubeconfig(): Promise<void> {
  const { data } = await api.post("/api/v1/k8s/kubeconfig", {}, { responseType: "blob" });
  const url = URL.createObjectURL(new Blob([data], { type: "application/yaml" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = "provenance-kubeconfig.yaml";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// The RBAC a cluster needs before Provenance can broker it. Downloaded rather
// than shown, because it is applied with kubectl, not read.
export async function downloadOnboardingManifest(
  access: "read" | "operate", namespace: string,
): Promise<void> {
  const { data } = await api.get("/api/v1/k8s/onboarding-manifest", {
    params: { access, namespace: namespace || undefined },
    responseType: "blob",
  });
  const url = URL.createObjectURL(new Blob([data], { type: "application/yaml" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = "provenance-rbac.yaml";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
