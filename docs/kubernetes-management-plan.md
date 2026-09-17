# Plan: Kubernetes management in Provenance

Provenance brokers access to Kubernetes clusters but can only *look* at them. This
is the plan for making it somewhere you can actually operate a cluster.

## What this is

**Provenance is the tool the operator interacts with.** That is the requirement,
and it is not the same as "Provenance contains a re-implementation of every
Kubernetes UI feature".

The upstream Kubernetes Dashboard is archived and unmaintained; Kubernetes SIG UI
points at **Headlamp** (Apache-2.0, `kubernetes-sigs/headlamp`), and Lens and
Rancher cover the same ground commercially. Rebuilding that surface would put us
permanently behind an open-source project whose whole job it is.

So the shape is: **embed Headlamp, and route it through Provenance.** The
operator opens a cluster from the Kubernetes page and gets a full management UI
without leaving Provenance and without a second login. Headlamp renders;
Provenance owns identity, the credential and the audit trail.

That only counts as seamless if all of the following hold, and each one is work:

1. **Headlamp talks to the cluster through Provenance's proxy**, never directly —
   so the cluster credential stays vaulted and every call is recorded.
2. **No second login.** The operator's Provenance session is the identity.
3. **Launched from the cluster row**, embedded rather than a link to somewhere
   that looks like a different product.
4. **`kubectl` keeps working** through the same path, for the operation nobody
   anticipated.

The alternative — pointing an operator at a Headlamp that holds its own
kubeconfig — is rejected. It is less work and it gives up the only thing that
makes this worth doing: that an operator never holds cluster access of their own.

## The discipline

Build what Headlamp cannot: brokering, policy, recording, and the joins to data
Provenance already holds. Do not build what Headlamp already does well — resource
browsing, YAML views, Helm, CRDs, the plugin system. Every item below has to say
which side of that line it is on.

---

## Phase 0 — the proxy has to be able to carry it

Nothing below Phase 1 is possible until this is done, and it is invisible from
the outside, so it is easy to skip and then discover.

`k8sbroker/proxy.go` does `client.Do` followed by `io.Copy`. That is fine for
list and get. It cannot do the rest:

| Missing | Breaks |
|---|---|
| `http.Flusher` on the response | **watches** — events sit in Go's write buffer instead of arriving live, so nothing auto-updates |
| connection upgrade (hijack / WebSocket / SPDY) | **exec, attach, port-forward, `logs -f`** — these are not ordinary HTTP requests and cannot be proxied by copying a body |

Also in Phase 0, because they change what everything else can assume:

- **`SelfSubjectAccessReview` preflight.** Ask the cluster what the credential can
  actually do, and render accordingly. Today the UI would show a control and let
  the operator discover the 403 by pressing it. With arbitrary clusters being
  joined, every credential will differ — read-only, namespace-scoped, admin — and
  a UI that cannot tell is a UI that lies. This is the single highest
  value-per-line item in the plan.
- **Cluster health.** Reachable, server version, node count, on the cluster list,
  plus a **Test** button at registration. Right now an unreachable cluster or a
  bad token is discovered by clicking into it and reading a proxy error.

## Phase 1 — embed Headlamp

> **Dependency found while scoping this, and it reorders the phase.** Headlamp
> can be pointed at an arbitrary API server by mounting a kubeconfig
> (`-kubeconfig`, or `KUBECONFIG`, supported for the in-cluster deployment), so
> routing it through Provenance's proxy works. But a kubeconfig carries **one**
> bearer token, so every Headlamp user would reach Provenance as the same
> identity and the audit log would record one actor for the whole team — which
> defeats the reason for embedding it rather than linking out.
>
> Provenance's durable tokens live in `api_tokens`, whose `service_account_id` is
> `NOT NULL`: tokens belong to service accounts, not people. **Per-user tokens are
> a schema and auth change, not a detail**, and they gate the rest of the phase.
> Shipping the embed first would mean launching with attribution that is wrong,
> and retrofitting it later.
>
> Headlamp's own OIDC support (Keycloak is a documented provider) identifies the
> human *to Headlamp*, which is what makes single sign-on possible — but it does
> not change which token reaches Provenance. Two separate problems, and only the
> second one touches the audit trail.

**1a. Per-user access tokens** — a durable token ownable by a user, not only by a
service account. This is the gate.

**1b. Ship Headlamp** as a container, with a kubeconfig pointing at
`/api/v1/k8s/clusters/<id>/proxy`.

**1c. Embed it** in the Kubernetes page, scoped to the selected cluster, single
sign-on, no second login.

**1d. Download a kubeconfig** for `kubectl`, `k9s` or desktop Headlamp — same
proxy, same audit, same attribution. Falls out of 1a almost for free.

### As originally sketched

- **Ship Headlamp** as a container in the stack (Apache-2.0, SIG-maintained).
- **Point it at the broker** with a per-user kubeconfig, so calls carry the
  operator's identity into the audit log rather than a shared one.
- **Embed it** in the Kubernetes page, scoped to the selected cluster.
- **Single sign-on** from the Provenance session.
- **Generate a kubeconfig** the operator can download for `kubectl`, `k9s` or a
  desktop Headlamp — same proxy, same audit, same per-user attribution.

This replaces most of what the original plan called table stakes. The built-in
browser stays as the quick "what is running" view and the fallback when Headlamp
is not deployed.

**Single sign-on landed after the embed, and it needed a second mechanism.** 1a
made the token per-user, which fixed attribution — but the operator still had to
paste that token into Headlamp's auth screen, so there *was* a second login even
though there was no second identity. Headlamp keeps a cluster token in an
HttpOnly cookie set by its own backend, which JavaScript cannot write; what it
can do is call the same-origin endpoint that sets it. So Provenance mints a
short-lived scoped token and posts it to
`POST /headlamp/clusters/<name>/set-token` before rendering the console. Being a
cookie on **this** origin, it also signs in a plain browser tab — which is where
**Open in new tab** comes from. See `kubernetes.md` for the shipped behaviour.

Worth recording because it generalises: proxying the tool under Provenance's own
origin, rather than linking to it, is what made its auth mechanism reachable at
all. A linked-out Headlamp could not have been signed in this way.

## Phase 1b — the built-in browser, only where it earns it (table stakes)

- **Resource kinds from API discovery, not a hardcoded map.** The current five
  (`namespaces, nodes, pods, services, deployments`) miss statefulsets,
  daemonsets, jobs, cronjobs, ingresses, configmaps, PVCs — and every CRD.
  Discovery makes CRDs work for free, which matters because anything interesting
  installed on a cluster ships them.
- **Resource detail and YAML view.** A row is not enough to diagnose anything.
- **Events**, cluster-wide and per-object. This is what a `CrashLoopBackOff`
  actually means, and without it the browser shows a problem it cannot explain.
- **Namespace picker** driven by the namespace list, replacing the free-text
  field where a typo renders an empty table that looks like "nothing there".
- **Metrics** from metrics-server, where present.

## Phase 2 — the operations people actually perform

- **Pod logs** — follow, multi-container, previous-container after a restart.
  The most-used screen in any cluster UI, and the usual reason someone gives up
  on one.
- **A container shell (`exec`)** — see Phase 3, which is where it gets recorded.
  It belongs in the daily-use set regardless.
- **Rollouts** — scale, restart, rollout history and rollback.
- **Delete**, with the distinction the confirmation has to make: deleting a pod
  a controller owns is a restart; deleting a bare pod is a removal.
- **Apply / edit YAML.**
- **Node lifecycle** — cordon, drain, uncordon.

These are the reason the feature exists. They are not table stakes to be
deferred — "easy to use" means an operator reaches for this instead of a terminal,
and that is decided entirely by whether logs, exec and rollouts are here and
good. Phase 3 makes them *better than* a dashboard's; Phase 2 is what makes them
exist at all.

## Phase 3 — the part that justifies doing this at all

Each of these reuses machinery that already exists in this codebase, and none of
them can exist in a standalone dashboard.

- **`kubectl exec` through the session recorder.** Provenance already records and
  replays SSH and RDP sessions (`recorder`, `livesessions`, `sessionsapi`). A
  shell in a container is the same thing and should be recorded the same way —
  searchable, replayable, attributable to a person rather than to a
  ServiceAccount. **No other Kubernetes UI records what you did in an exec
  session.** This is the feature that makes the whole plan worth building.
- **Command policy for kubectl.** `commandpolicy` already flags, blocks and
  approval-gates shell commands per host. The same shape applies to verb +
  resource + namespace: block `delete namespace`, gate `exec` in production
  behind approval, flag `delete` on anything in `kube-system`.
- **Approvals** for destructive cluster actions, reusing the existing workflow
  rather than inventing a second one.
- **Vulnerability findings against running workloads.** Provenance already scans
  container images by digest and deduplicates across the fleet (`vulnscan`,
  `containerscans`). The images running in a joined cluster are the same kind of
  object. Joining them means a workload list that says which pods are running
  something known-vulnerable — which is a question Headlamp cannot answer.
- **Access policies per namespace.** `accesspolicy` already does ABAC over hosts;
  extending it to cluster + namespace + verb is how you let a team operate its
  own namespace without handing anyone a kubeconfig.

## Phase 4 — fleet

- **Cluster onboarding that does the work.** Joining a cluster today means
  hand-writing a ServiceAccount, a ClusterRole, bindings and a non-expiring token
  Secret, then pasting a CA. Provenance should emit that manifest for the access
  level being granted, and tell the operator what it will and will not permit.
  For a product whose pitch is "join your clusters", this is the first thing a
  new user hits.
- **Credential lifecycle.** Those ServiceAccount tokens do not expire and nothing
  watches them. Provenance has an Expiry & Rotation surface; cluster credentials
  should appear in it.
- **Helm releases** — list, history, rollback.
- **Multi-cluster views** — the same question asked across every joined cluster.

## What stays out

- **A YAML IDE, a cost explorer, a service-mesh view.** Dashboard features with
  no Provenance angle and no daily use.
- **Reproducing Headlamp's plugin system.** Extensibility is its differentiator,
  not ours.

Keeping `kubectl` working through the proxy is not a substitute for any of this,
but it stays: it is the escape hatch for the operation nobody anticipated, and it
costs nothing now that the proxy has to stream and upgrade anyway.

## Sequencing

**Phase 0 first, in full.** Every interesting screen in Phase 2 — live logs, a
container shell, anything that auto-updates — is impossible until the proxy can
stream and upgrade. It is also the smallest phase. Skipping it means building
Phase 1 and then discovering the good parts cannot be built.

**Then Phase 1 and 2 together, kind by kind**, rather than finishing Phase 1
first. A namespace of pods you can list, inspect, read logs from and shell into is
worth more than every resource kind listed and nothing actionable. Deployments and
pods first; the long tail of kinds after.

**Phase 3 layers onto Phase 2 as each piece lands** — exec ships recorded, not
recorded later. Retrofitting a recording onto a shipped shell means a window where
the most sensitive thing in the product is the one thing not audited.
