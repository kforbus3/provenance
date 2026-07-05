# Multi-Site Federation

Federation turns one Fleet Terminal instance into a **hub** — a single pane of
glass over many independent **site** instances, each a full Fleet stack on its
own separated network. Operators log into the hub and manage every site from one
place.

> Status: this is delivered in phases (see the branch history). F0–F2 (mode
> plumbing, join + persistent tunnel, cached host aggregation) and the F4 HTTP
> management proxy are implemented. F3 (live terminal / SFTP proxy) and the
> per-page frontend site dimension are in progress; the hub proxy for those
> returns `501` until then.

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
