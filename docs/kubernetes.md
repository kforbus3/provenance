# Kubernetes access brokering

Provenance brokers access to Kubernetes clusters the same way it brokers SSH, RDP, and databases: users
never hold the cluster credential. Instead Provenance acts as an **authenticating proxy** — a user (or
their `kubectl`) authenticates to Provenance, and Provenance forwards the request to the cluster's API server
with a **vaulted bearer token** injected, auditing every call.

Manage clusters under **Kubernetes** (register/edit/delete needs `Kubernetes.Manage`; reaching a
cluster needs `Kubernetes.Access`).

## Register a cluster

1. **Store the credential in the vault.** Create a vault secret whose value is a Kubernetes bearer
   token — typically a ServiceAccount token bound to a role with the access you want to broker.
2. **Register the cluster** with its API server URL (`https://…:6443`), the vault credential, a
   default namespace, and either a CA certificate (to verify the API server's TLS) or the
   "skip TLS verification" option for test clusters.

The token is decrypted only in memory at the point of use and is never returned to the client.

## Browse resources

The built-in browser lists common resource kinds — pods, deployments, services, namespaces, nodes —
per namespace, with no `kubectl` required. Every listing is audited (`k8s.list`).

## Act on resources

Deployments can be **restarted** and **scaled**, and pods can be **deleted**, from the browser.
These go through the same audited proxy as `kubectl` (`k8s.proxy`) rather than a separate
endpoint, so there is one path to the cluster and one thing to audit.

Restart stamps the pod template the way `kubectl rollout restart` does, so the controller replaces
pods in whatever order its rollout strategy says — rather than deleting them and hoping. Deleting a
pod is a restart when something owns it and a removal when nothing does, and the confirmation says
which.

Other kinds get no actions. The useful operations on a node are cordon and drain, and on a service
or configmap it is editing a manifest; none of those are one-click operations and presenting them
as though they were would be worse than leaving them out.

**A refusal here is usually the cluster's, not Provenance's.** An action the credential's RBAC does
not allow comes back as HTTP 403, and the message says so explicitly — sending an operator to look
at Provenance's permissions for a decision made on the cluster wastes the one useful piece of
information the error carried.

## Use kubectl through the broker

Point `kubectl` at Provenance's proxy for a cluster and authenticate with a Provenance token:

    kubectl --server=https://<prov-host>/api/v1/k8s/clusters/<clusterId>/proxy \
            --token=<fleet-access-token> \
            get pods -n <namespace>

Provenance forwards each request to the cluster's API server with the vaulted credential and records it
(`k8s.proxy`). What the caller can do in the cluster is bounded by the credential's own RBAC on the
cluster side, on top of Provenance's `Kubernetes.Access` gate and any [access policies](./access-policies.md).

## Notes

- The backend reaches the API server directly, so the cluster's control plane must be reachable from
  Provenance's network.
- Use a least-privilege ServiceAccount token, not a cluster-admin credential, unless brokered
  cluster-admin is genuinely intended.
