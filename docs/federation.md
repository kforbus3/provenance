# Multi-Site Federation

Federation turns one Fleet Terminal instance into a **hub** — a single pane of
glass over many independent **site** instances, each a full Fleet stack on its
own separated network. Operators log into the hub and manage every site from one
place.

> Status: F0–F5 implemented. Standalone is unchanged. A hub can add/revoke
> sites, rotate its federation key, watch live link state, and — via a global
> **site selector** in the top bar — operate *every* management page against a
> chosen site (host list, terminals, SFTP/file browser, scans, playbooks,
> schedules, audit, etc.) transparently through the hub proxy. Remaining polish:
> site-initiated key rotation and the WireGuard transport option.

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
