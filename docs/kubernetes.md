# Kubernetes access brokering

Moorgate brokers access to Kubernetes clusters the same way it brokers SSH, RDP, and databases: users
never hold the cluster credential. Instead Moorgate acts as an **authenticating proxy** — a user (or
their `kubectl`) authenticates to Moorgate, and Moorgate forwards the request to the cluster's API server
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

## Use kubectl through the broker

Point `kubectl` at Moorgate's proxy for a cluster and authenticate with a Moorgate token:

    kubectl --server=https://<fleet-host>/api/v1/k8s/clusters/<clusterId>/proxy \
            --token=<fleet-access-token> \
            get pods -n <namespace>

Moorgate forwards each request to the cluster's API server with the vaulted credential and records it
(`k8s.proxy`). What the caller can do in the cluster is bounded by the credential's own RBAC on the
cluster side, on top of Moorgate's `Kubernetes.Access` gate and any [access policies](./access-policies.md).

## Notes

- The backend reaches the API server directly, so the cluster's control plane must be reachable from
  Moorgate's network.
- Use a least-privilege ServiceAccount token, not a cluster-admin credential, unless brokered
  cluster-admin is genuinely intended.
