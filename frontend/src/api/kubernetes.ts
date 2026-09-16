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

// --- write actions, through the audited proxy ---
//
// These go through `/proxy/*` rather than a bespoke endpoint: the broker already
// forwards any method with the vaulted credential injected and records each call
// as `k8s.proxy`, so a new backend route would be a second path to audit and get
// wrong. What a caller may actually do is bounded by the credential's RBAC on the
// cluster, which is where that decision belongs.

function proxy(clusterId: string, path: string): string {
  return `/api/v1/k8s/clusters/${clusterId}/proxy${path}`;
}

// A strategic-merge patch, the same shape kubectl sends.
const MERGE = { headers: { "Content-Type": "application/merge-patch+json" } };

export async function scaleDeployment(
  clusterId: string, namespace: string, name: string, replicas: number,
): Promise<void> {
  await api.patch(
    proxy(clusterId, `/apis/apps/v1/namespaces/${namespace}/deployments/${name}`),
    { spec: { replicas } }, MERGE,
  );
}

// What `kubectl rollout restart` does: stamp the pod template so the controller
// rolls it, rather than deleting pods and hoping. A deployment with a rollout
// strategy then replaces them in order instead of all at once.
export async function restartDeployment(
  clusterId: string, namespace: string, name: string,
): Promise<void> {
  await api.patch(
    proxy(clusterId, `/apis/apps/v1/namespaces/${namespace}/deployments/${name}`),
    {
      spec: {
        template: {
          metadata: {
            annotations: { "kubectl.kubernetes.io/restartedAt": new Date().toISOString() },
          },
        },
      },
    },
    MERGE,
  );
}

export async function deletePod(
  clusterId: string, namespace: string, name: string,
): Promise<void> {
  await api.delete(proxy(clusterId, `/api/v1/namespaces/${namespace}/pods/${name}`));
}
