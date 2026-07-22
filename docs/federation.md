# Multi-Site Federation

Federation turns one Fleet Terminal instance into a **hub** — a single pane of
glass over many independent **site** instances, each a full Fleet stack on its
own separated network. Operators log into the hub and manage every site from one
place.

Federation is **opt-in and off by default** (`FLEET_MODE=standalone`): a standalone
instance builds and mounts none of it and is unchanged. A hub can add/revoke sites,
rotate its federation key, and watch live link state; via a global **site selector**
in the top bar it operates *every* management page against a chosen site (host list,
terminals, SFTP/file browser, databases, Kubernetes, scans, playbooks, schedules,
audit, and everything else) transparently through the hub proxy — with no per-page
changes, because the proxy forwards to the site's own unmodified API.

## Model

- **Standalone (default).** `FLEET_MODE=standalone` — nothing federation-related
  is built or mounted. Behavior is identical to a non-federated build.
- **Hub.** `FLEET_MODE=hub`. Holds the site registry, accepts inbound links from
  sites, aggregates a read-model, and proxies actions to sites. The hub is the
  authorization authority.
- **Site.** `FLEET_MODE=site`. A normal instance that additionally dials **out**
  to the hub and, in managed mode, executes hub-authorized, key-verified
  requests against its own unmodified `/api/v1`.

Sites are assumed to have **no inbound reachability**. All hub↔site traffic rides
a single **site-initiated** WSS connection (outbound 443), multiplexed with
yamux. The hub never needs a route back into a site.

## Trust

Federation uses **Ed25519 public keys only** — never the per-instance HS256
session secret. Each side holds the other's public key:

- The **hub** generates a federation identity keypair on first boot, private key
  encrypted at rest with `FLEET_CA_PASSPHRASE` (same envelope as the SSH CA key).
- Each **site** generates its own keypair at join; the private key never leaves
  the site.

Three short-lived EdDSA token types (`internal/federation/fedauth`):
- **link token** — site-signed; proves site identity when opening the channel.
- **service token** — hub-signed; authenticates the hub to a site per request.
- **acting-user assertion** — hub-signed; carries the acting operator's identity
  and the permissions the hub authorized, bound to one exact request by a
  `sha256(method+path+body)` digest and a single-use nonce.

### Key rotation

Both identities can be rotated in place, with no re-enrollment and no link downtime:

- **Hub key** — an operator clicks **Rotate hub key** on the Sites page (or `POST
  /api/v1/federation/keys/rotate`). The hub generates a new identity, retires the old
  one (kept briefly for verification overlap), and pushes the new public key to every
  live site over the control channel; offline sites re-learn it when they next link.
- **Site key** — a site operator triggers `POST /api/v1/federation/site/rotate-key`
  (permission `System.Configure`). The site generates a new keypair and, over the
  already-authenticated link, sends the new public key **signed by its current key**.
  The hub verifies that signature against the site's active key and stages the new key
  as *pending* — leaving the current key in force. The site then commits the new key
  locally and reconnects; on that reconnect the hub sees the new key authenticate,
  **promotes** it to active, and clears the pending slot. Because the hub accepts both
  the active and the pending key during the overlap, a crash or drop mid-rotation never
  locks the site out — it simply reconnects with whichever key it still holds.

## Transport

The federation application protocol is always **WSS** — a single outbound TLS
connection on 443 from the site to the hub, authenticated by the Ed25519 tokens above.
This is deliberate: a site needs **no inbound reachability**, so it works from behind
NAT and restrictive egress firewalls. `FLEET_FEDERATION_TRANSPORT=wireguard` does not
change the wire protocol; it documents that the WSS link rides an operator-provided
WireGuard (or other VPN) underlay — point `FLEET_HUB_URL` at the hub's overlay address
so the control plane never traverses the public internet. Both settings run identical
code; the choice is purely which network the WSS link is carried over.

## Joining a site

1. On the hub: **Sites → Add Site**, name it. The hub mints a one-time,
   self-gating join token (1h TTL) and shows a config blob.
2. On the site host: set the blob (`FLEET_MODE=site`, `FLEET_HUB_URL`,
   `FLEET_HUB_JOIN_TOKEN`, `FLEET_HUB_KEY_FINGERPRINT`) and start the stack.
3. The site generates its keypair, `POST`s `/federation/join`, pins the hub key
   fingerprint (aborting on mismatch — MITM defense), persists trust, and opens
   the persistent `/federation/link` channel. It appears **active / up** on the
   hub within seconds.

Revoke from the hub (**Sites → trash**) drops the link and purges the site's
cached data. A site can leave via `POST /api/v1/federation/leave`
(`System.Configure`) or by reverting to `FLEET_MODE=standalone`.

## Central identity

The hub authenticates the operator with its own login/RBAC. When the operator
acts on a site, the hub sends a signed acting-user assertion carrying the
operator's permission snapshot; the site verifies it against the pinned hub key,
synthesizes a principal (a stable site-local *shadow user* mapped from the hub
user), and runs the request through its **own unmodified handlers**. Site-side
audit records the actor as `hub:<username>`. Audit hash-chains stay **per-site**
and are never merged; the hub keeps its own audit entry, linked by the assertion
nonce.

## Data freshness

Sites **push** a read-model (host inventory/status + heartbeat) over the channel;
the hub caches it (`fed_cache_*`) and re-broadcasts live events tagged with
`site_id`. Dashboards read the cache, so they stay populated (with a staleness
indicator) even while a site is briefly offline. Live actions (terminals, SFTP,
management writes) go to the site on demand over the same channel.

## Security notes

- Treat the hub federation key like the CA key: a compromise lets the hub assert
  any identity to every site. It is encrypted at rest and supports rotation.
- Federation refuses to run on development defaults (`FLEET_MODE` in hub/site
  mode requires `FLEET_ENV=production` with real secrets).
- Assertions are ≤60s, single-use (nonce), and request-bound, so a captured
  assertion can't be replayed against a different action, host, or body.

## Using the single pane

On a hub, the top bar shows a **site selector** (`◎ Hub (local)` plus each
active site with a 🟢/🔴 link indicator). Pick a site and the entire UI operates
against it — the host list, terminals, file browser, scans, playbooks,
schedules, sessions, and audit all transparently route through the hub to that
site (a request interceptor rewrites `/api/v1/*` to the site proxy). Switch back
to **Hub (local)** to manage the hub itself. The Sites page always shows the
registry and the aggregated cross-site host list regardless of the selector.

## Federation and multi-tenancy

Federation and [multi-tenancy](./multi-tenancy-plan.md) are **orthogonal and compose**:

- **Multi-tenancy is horizontal** — it isolates many customers *inside one instance*
  (Postgres row-level security).
- **Federation is vertical** — it aggregates many *independent instances* under one hub.

For an **MSP**, the natural shape is *"a federated site is a tenant at the hub"*: the hub
is the provider's single pane of glass, each customer datacenter is an autonomous **site**,
and the hub maps each site to a **tenant** so the provider's own operators get per-customer
isolation on the hub — while each site stays fully autonomous and keeps working if the hub or
WAN is down.

Because a site runs the request through its **own** handlers under a synthesized site-local
principal (the shadow user), each site enforces its own RBAC, [access policies](./access-policies.md),
and command policies independently — the hub is an authorization *initiator*, never a bypass.
Audit hash-chains stay **per-site** and authoritative; the hub keeps only a linked copy, so a
compromised hub cannot rewrite a site's audit history.

### How the mapping works

When [multi-tenancy](./multi-tenancy-plan.md) is enabled on the hub, **a site belongs to the
tenant of the operator who minted its join token**. Mint a join token while acting in tenant
`acme` and the site that redeems it — along with its aggregated read-cache (inventory, sessions,
scans, schedules, playbook runs, transfers) and sync state — is owned by `acme`. Everything the
hub shows for that site is then tenant-scoped by row-level security:

- the **Sites list** and the top-bar **site selector** only show a tenant's own sites;
- the **aggregated inventory** and cross-site dashboards only include that tenant's sites;
- the **proxy** (browser terminals, SFTP, every management page) refuses to reach a site the
  acting tenant does not own — a cross-tenant site id resolves to *not found*, never to another
  customer's infrastructure.

A provider operator switches tenant context (the standard tenant switcher) to manage a different
customer's sites. Single-tenant and non-multi-tenant hubs are unaffected: every site simply
belongs to the default tenant, exactly as before.

## Testing two stacks locally

Federation needs two instances. The quickest path is two copies of the app
stack, one as the hub and one as the site, both in `production` mode (federation
refuses dev defaults). Sketch:

1. **Hub** — run the normal stack with:
   ```
   FLEET_ENV=production
   FLEET_MODE=hub
   FLEET_PUBLIC_URL=https://<hub-host>     # sites dial this
   FLEET_JWT_SECRET=... FLEET_CSRF_SECRET=... FLEET_CA_PASSPHRASE=...
   ```
   Log in, go to **Sites → Add Site**, name it, copy the config blob.

2. **Site** — run a second stack (separate DB/volumes) with the blob appended:
   ```
   FLEET_ENV=production
   FLEET_MODE=site
   FLEET_HUB_URL=wss://<hub-host>
   FLEET_HUB_JOIN_TOKEN=<from the blob>
   FLEET_HUB_KEY_FINGERPRINT=<from the blob>
   FLEET_JWT_SECRET=... FLEET_CSRF_SECRET=... FLEET_CA_PASSPHRASE=...
   ```
   The site's own jump host + managed hosts are enrolled as usual (standalone
   behavior is intact on a site).

3. On the hub: the site flips to **active / 🟢 up** within seconds; its hosts
   appear in the aggregated list. Select the site in the top bar and use Hosts /
   Terminals / Files / Security exactly as you would locally — every action runs
   at the site, audited there as `hub:<you>`. **Rotate hub key** on the Sites
   page and confirm linked sites keep working (the new key is pushed live).

The hub must be reachable from the site on 443 (outbound only); the site never
needs an inbound hole.
