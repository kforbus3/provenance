# Kubernetes access brokering

Provenance brokers access to Kubernetes clusters the same way it brokers SSH, RDP, and databases: users
never hold the cluster credential. Instead Provenance acts as an **authenticating proxy** — a user (or
their `kubectl`) authenticates to Provenance, and Provenance forwards the request to the cluster's API server
with a **vaulted bearer token** injected, auditing every call.

Manage clusters under **Kubernetes** (register/edit/delete needs `Kubernetes.Manage`; reaching a
cluster needs `Kubernetes.Access`).

## Register a cluster

**Kubernetes → Cluster RBAC** generates the manifest a cluster needs first: a
ServiceAccount, the roles, the bindings, and a long-lived token Secret. Apply it
with `kubectl`, then paste the token and CA it prints.

It is generated rather than documented because a step that is documented is a
step somebody shortcuts — and the shortcut is `cluster-admin`, which is one line
and works. What the manifest grants instead:

- **read** — browse and diagnose. No writes, no Secrets.
- **operate** — the above plus workload lifecycle. Still **no Secrets, no
  ServiceAccounts, no RBAC**.

Neither is `cluster-admin`, and neither is the built-in `edit` role — `edit`
grants Secrets read *and* write, which is rarely what somebody wants from a
management UI and never what they expect. Being able to create a ServiceAccount
is excluded for the same reason: it is a route to a token, and a token is a route
back to everything the role withholds.

Reading is always cluster-wide, because `view` alone does **not** cover
cluster-scoped nodes and every cluster UI lists them. Writes can be confined to
one namespace, and that confinement matters: anything able to create workloads in
a namespace can mount that namespace's Secrets into a pod and read them. No RBAC
rule prevents that; scoping the write binding does.



1. **Store the credential in the vault.** Create a vault secret whose value is a Kubernetes bearer
   token — typically a ServiceAccount token bound to a role with the access you want to broker.
2. **Register the cluster** with its API server URL (`https://…:6443`), the vault credential, a
   default namespace, and either a CA certificate (to verify the API server's TLS) or the
   "skip TLS verification" option for test clusters.

The token is decrypted only in memory at the point of use and is never returned to the client.

## Browse resources

The built-in browser lists common resource kinds — pods, deployments, services, namespaces, nodes —
per namespace, with no `kubectl` required. Every listing is audited (`k8s.list`).

## Changing things: kubectl, not buttons

The built-in browser is **read-only on purpose**. Provenance is not trying to be a Kubernetes
dashboard: the upstream Kubernetes Dashboard is archived and unmaintained, and its successor
[Headlamp](https://headlamp.dev) is a Kubernetes SIG project that does that job far better than a
re-implementation here would.

What Provenance does that a dashboard does not is hold the credential. So changing a cluster goes
through `kubectl` pointed at the broker, below — the operator authenticates to Provenance, the
cluster credential never reaches them, and every call is recorded.

**What a caller may do is decided on the cluster, not here.** Provenance's `Kubernetes.Access`
permission governs whether someone may reach a cluster at all; the ServiceAccount's RBAC governs
what they can do once there. A read-only credential makes the whole path read-only, and no setting
in Provenance can widen it.

## Connect a tool: kubeconfig

**Kubernetes → Download kubeconfig** mints a token for you and returns a config
that reaches every cluster you can see, through the broker. One action rather
than two, because a token with nothing to point at is useless and so is a config
with no credential.

What you get:

- **One context per registered cluster**, each `server:` pointing at
  `/api/v1/k8s/clusters/<id>/proxy` — never at the cluster directly. The
  cluster's own credential stays vaulted and never enters the file.
- **A token scoped to `/api/v1/k8s`.** It can reach the Kubernetes broker and
  nothing else in Provenance: not a host, not a credential, not a playbook. A
  leaked kubeconfig is bounded by what its owner could already do to the
  clusters.
- **An expiry.** A credential that lives in a file and never expires is one
  nobody revokes, because nobody remembers it exists.

The token is shown once, inside the file — Provenance stores only its hash, so a
lost kubeconfig is regenerated rather than recovered. Revoke one like any other
token.

A scoped token cannot mint another; downloading a kubeconfig requires a signed-in
session. Otherwise a leaked file could renew itself forever and escape its own
expiry.

This is what makes **any** Kubernetes tool work through Provenance — `kubectl`,
`k9s`, Lens, or a desktop Headlamp — with the credential brokered, the calls
audited, and the audit naming the person rather than a shared account.

## Headlamp

The stack ships [Headlamp](https://github.com/kubernetes-sigs/headlamp)
(Apache-2.0, a Kubernetes SIG project) behind an opt-in profile:

    docker compose --profile kubernetes up -d

It is deliberately **not** given a kubeconfig containing a token. A kubeconfig
carries one credential, so a shared one would make every operator reach
Provenance as the same identity and collapse the audit log to a single actor —
which is the whole reason to embed a UI rather than link out to one. Each
operator supplies their own scoped token instead.

Headlamp is not run with `-in-cluster`: it must not pick up an ambient
ServiceAccount. Every cluster it can see arrives through Provenance's proxy or
not at all.

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
