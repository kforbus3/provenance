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

## The embedded console

The stack ships [Headlamp](https://github.com/kubernetes-sigs/headlamp)
(Apache-2.0, a Kubernetes SIG project) behind an **opt-in** compose profile — a
deployment that has joined no clusters should not run a Kubernetes UI:

    docker compose --profile kubernetes up -d

Open it from the cluster row (**Open cluster UI**). It is framed inside
Provenance rather than linked to, so the operator does not leave the pane or log
in a second time — and **Open in new tab** gives the same console a full window
when a frame is too small for the job.

There is no login and no token to paste. Provenance signs the console in for you.

### Who can open it

Exactly whoever holds **`Kubernetes.Access`**. That permission gates the route
that mints the console's credential, so the console is governed by Provenance's
roles and there is nothing separate to keep in sync. `Kubernetes.Manage` is a
different and stronger thing: it covers registering and removing clusters.

Two consequences worth knowing:

- Taking `Kubernetes.Access` away stops an operator opening the console, but a
  console they already have open keeps working until its token expires (12 hours
  at most). To cut it immediately, revoke their `Headlamp console for <user>`
  token from their API tokens, or disable the account.
- **Signing out of Provenance revokes the console token**, so a shared browser
  does not leave working cluster access behind for whoever sits down next.

### How it is wired

**Provenance tells Headlamp which clusters exist; Headlamp never learns a
cluster credential.** The backend writes a kubeconfig containing cluster names
and server URLs — each pointing at `/api/v1/k8s/clusters/<id>/proxy`, never at a
cluster directly — with a user entry carrying an **empty** credential block. The
cluster's own credential stays vaulted and is injected by the broker.

The console's *operator* credential is supplied separately, and per person:

1. The SPA asks `POST /api/v1/k8s/console-token` for a token scoped to
   `/api/v1/k8s` and valid 12 hours, named `Headlamp console for <user>`.
2. It posts that token to Headlamp's own
   `POST /headlamp/clusters/<name>/set-token`, which stores it in an **HttpOnly
   cookie** — Headlamp's normal mechanism, not something bolted on.
3. Only then is the console rendered. Headlamp reads its token when it boots, so
   a console mounted before the cookie exists would sit on its auth screen and
   stay there.

Because the cookie belongs to the **origin** rather than to the frame, the same
console is already signed in when opened in a new tab. Nothing secret travels in
the URL.

It is a per-user token rather than one shared console credential on purpose: a
shared one would make every operator reach Provenance as the same identity and
collapse the audit log to a single actor — which is the whole reason to embed a
console rather than link out to one. Minting **supersedes** the operator's
previous console token, so each person has at most one live at a time; a second
browser tab is unaffected (it sends the same cookie), a second *device* mints its
own and takes over.

Three details that matter if you are debugging it:

- The cluster-list file is written to `PROV_HEADLAMP_KUBECONFIG` (default
  `/headlamp/clusters/kubeconfig`), on a volume the backend writes and Headlamp
  reads read-only. **Unset disables the whole mechanism**, which is the case for
  any deployment not running the profile.
- It is rewritten at backend startup and whenever a cluster is registered,
  edited or removed. Headlamp **watches** the file, so a newly registered cluster
  appears in the console within about ten seconds — no restart. (The write is an
  atomic rename, which is deliberate: Headlamp reads this file at arbitrary
  moments and logs a parse error on a half-written one.)
- If Provenance cannot mint a token — no `Kubernetes.Access`, or the caller is
  itself using a scoped token — the console falls back to Headlamp's own
  *"paste your authentication token"* prompt, and the token from **Download
  kubeconfig** works there. A scoped token cannot mint another, or a leaked one
  would renew itself forever and its expiry would mean nothing.

Headlamp is deliberately **not** run with `-in-cluster`: it must not pick up an
ambient ServiceAccount. Every cluster it can see arrives through the broker or
not at all.

### What you get

The full Headlamp surface — workloads, storage, network, logs, events, search —
rendered against live data, with every call brokered and audited. A cluster
overview shows real CPU, memory, pod and node counts; watches arrive over a
WebSocket that Provenance's proxy upgrades and passes through (visible in the
audit log as `k8s.proxy` with status `101`).

## Use kubectl through the broker

Point `kubectl` at Provenance's proxy for a cluster and authenticate with a Provenance token:

    kubectl --server=https://<prov-host>/api/v1/k8s/clusters/<clusterId>/proxy \
            --token=<provenance-token> \
            get pods -n <namespace>

Easier: **Download kubeconfig** produces a file that already has this right for
every cluster you can see, so `KUBECONFIG=provenance-kubeconfig.yaml kubectl
get nodes` just works.

Provenance forwards each request to the cluster's API server with the vaulted credential and records it
(`k8s.proxy`). What the caller can do in the cluster is bounded by the credential's own RBAC on the
cluster side, on top of Provenance's `Kubernetes.Access` gate and any [access policies](./access-policies.md).

## Notes

- The backend reaches the API server directly, so the cluster's control plane must be reachable from
  Provenance's network.
- Use a least-privilege ServiceAccount token, not a cluster-admin credential, unless brokered
  cluster-admin is genuinely intended. **Cluster RBAC** generates one.
- **`PROV_PUBLIC_URL` must be correct.** Both the downloadable kubeconfig and the
  console's cluster list build their `server:` from it, so if it is wrong they
  point somewhere unreachable and the failure looks like a broken cluster rather
  than a misconfigured URL.
- **A bearer token is not sent over plain HTTP.** `kubectl` (client-go) drops it,
  so a kubeconfig edited to use `http://` fails with `missing access token` even
  though the same token works over HTTPS. Serve Provenance over TLS.
- Node rows in the built-in browser show a blank status. The browser reads
  `status.phase`, which pods have and nodes do not — a node's readiness lives in
  its conditions. The embedded console reports it correctly.
