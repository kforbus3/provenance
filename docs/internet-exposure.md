# Exposing Fleet Terminal to the Internet

This guide covers putting the Fleet Terminal web UI on the public internet behind
**Nginx Proxy Manager (NPM)** with a **Let's Encrypt** certificate, so users on
laptops anywhere can reach hosts over SSH **without a VPN, SSH client, or keys**.

## Why this is a defensible design

The browser is never an SSH client and never holds an SSH credential. The backend
is the sole SSH client; per-login ephemeral Ed25519 keys live only in backend RAM,
and certificates are short-lived, **unique per (user, host)**, and revoked on
logout / idle / disable. A stolen laptop or hijacked browser session yields no
reusable host access. That property is what makes internet exposure reasonable —
materially safer than exposing SSH or a VPN concentrator directly.

What you still must get right: TLS, MFA, rate limiting, and keeping everything
except the proxy off the public internet.

## Network topology

```
Internet ──443──> Nginx Proxy Manager (TLS / Let's Encrypt) ──> backend:8080 (internal Docker network)
                                                                    └─> jump host ─WireGuard─> managed hosts
```

- Publish **only** NPM's 443 (and 80 for the ACME challenge) to the internet.
- Keep `backend:8080`, `frontend`, Postgres, Redis, the jump host, and WireGuard
  on the internal Docker network. Do **not** map their ports to the host.
- The frontend container already proxies `/api` + WebSocket to the backend, so NPM
  only needs one upstream (the frontend), or you can route `/api` to the backend
  directly — either works.

## Backend configuration

Start from [`.env.production.example`](../.env.production.example). The essentials:

| Variable | Why |
|---|---|
| `FLEET_ENV=production` | Production posture |
| `FLEET_PUBLIC_URL=https://fleet.example.com` | Must match the public URL; drives CORS, cookies, WebAuthn RPID |
| `FLEET_COOKIE_SECURE=true` | Auth cookies only sent over HTTPS |
| `FLEET_ALLOW_BOOTSTRAP=false` | Belt-and-braces; the wizard also self-seals once a user exists |
| `FLEET_REFRESH_TOKEN_TTL=168h` | Shorter refresh lifetime than the 30-day default |
| `FLEET_SESSION_IDLE_TTL` / `_ABSOLUTE_TTL` | Tighten idle/absolute caps |
| `FLEET_AUTH_RATE_LIMIT_PER_MIN` / `_BURST` | Per-IP throttle on auth endpoints |
| `FLEET_WEBAUTHN_RPID` / `_ORIGINS` | Required for passkeys to work on the public domain |

Generate strong secrets: `openssl rand -hex 32` for `FLEET_JWT_SECRET`,
`FLEET_CSRF_SECRET`, and `FLEET_CA_PASSPHRASE`.

## MFA

MFA is **opt-in**, with two controls:

- **Per user:** Users → Edit → *Require MFA*. The user is forced to enroll a TOTP
  factor at their next sign-in before any session is issued.
- **Globally:** Users → *Require MFA for all*. Every user must enroll.

Enforcement is server-side: when MFA is required and the user has no confirmed
factor, login returns an enrollment challenge and **no session** until a valid
code is provided. Prefer **passkeys/WebAuthn** (phishing-resistant) where you can;
TOTP is the universal fallback used for forced enrollment.

For an internet deployment, enabling *Require MFA for all* is strongly recommended.
Users can also generate one-time **recovery codes** (Settings → Security) to regain
access if their authenticator is lost.

## Rate limiting (built in)

The backend enforces a per-IP token-bucket limit, keyed on the client IP from
`X-Forwarded-For` (which NPM sets). A stricter budget guards `/api/v1/auth/*` and
`/api/v1/bootstrap/*`; a looser one covers the rest. Over-limit requests get
`429 Too Many Requests`. Tune via `FLEET_*RATE_LIMIT*`. This complements — does not
replace — per-account lockout (`lockout_policy` setting: `max_failed`,
`lockout_minutes`).

> The IP is only trustworthy because the app sits behind a proxy that sets
> `X-Forwarded-For`. Never expose the backend directly, or clients could spoof it.

## Nginx Proxy Manager setup

1. **DNS:** point `fleet.example.com` at the NPM host.
2. **Proxy Host:** Domain `fleet.example.com` → Forward to the frontend
   container's port. Enable **Block Common Exploits** and **Websockets Support**
   (required for the terminal).
3. **SSL tab:** request a Let's Encrypt cert, **Force SSL**, **HTTP/2**, and
   **HSTS** enabled.
4. **Advanced tab:** add a rate-limit zone and request-size cap, e.g.:

   ```nginx
   # in the http context (NPM: Settings or a custom snippet)
   limit_req_zone $binary_remote_addr zone=fleet_login:10m rate=10r/m;

   # in the proxy host Advanced box
   client_max_body_size 5g;          # match FLEET_MAX_UPLOAD_BYTES if using SFTP
   location /api/v1/auth/ {
       limit_req zone=fleet_login burst=10 nodelay;
       proxy_pass http://frontend;   # or backend upstream
   }
   ```
5. **Access List (optional, strong):** if your remote users have known source IP
   ranges, add an NPM Access List to allow only those — the single biggest
   reduction in attack surface.

### Using your own certificate (instead of Let's Encrypt)

If you have a certificate from your own CA — a commercial/purchased cert, an
enterprise/internal PKI, or a wildcard you manage — use it in place of the
Let's Encrypt request:

1. In NPM, go to **SSL Certificates → Add SSL Certificate → Custom**.
2. Provide, in **PEM** format:
   - **Certificate** — your leaf certificate followed by any intermediate/chain
     certificates (the "full chain"). Order: leaf first, then intermediates.
   - **Certificate Key** — the matching **private key**, and it must be
     **unencrypted** (NPM cannot prompt for a passphrase; run
     `openssl rsa -in enc.key -out plain.key` to strip one first).
   - **Intermediate Certificate** — only if your chain isn't already bundled into
     the Certificate field.
3. On the Proxy Host's **SSL tab**, choose that custom certificate instead of
   "Request a new SSL Certificate", and keep **Force SSL**, **HTTP/2**, and
   **HSTS** enabled exactly as with Let's Encrypt.

Requirements and caveats:

- **The certificate's SAN (or CN) must match the hostname in `FLEET_PUBLIC_URL`.**
  Fleet derives the cookie domain, CORS origin, and the **WebAuthn/passkey relying
  party ID** from that hostname, so a mismatched cert breaks login and passkeys, not
  just the TLS padlock.
- **Internal/enterprise CA:** every client browser must **trust your CA** (its root
  installed in the OS/browser trust store), or users get a certificate warning and
  WebAuthn refuses to run. Public/commercial certs need no client-side trust.
- **Renewal is on you.** Unlike Let's Encrypt (which NPM auto-renews), a custom cert
  does **not** auto-renew — replace it in NPM before it expires (re-upload, or script
  it against the NPM API). Fleet's Expiry & Rotation dashboard tracks *Fleet's* CA
  and tokens, **not** the front-door proxy certificate, so track that one separately.

### Not using Nginx Proxy Manager?

Any TLS-terminating reverse proxy works — **Caddy** (automatic HTTPS with your own
cert via the `tls <cert> <key>` directive), **nginx** (`ssl_certificate` /
`ssl_certificate_key`), **Traefik**, or a Kubernetes ingress. Whatever you use must:

- terminate TLS with your certificate and forward to the **frontend** container;
- pass **WebSocket** upgrades through (the terminal, SFTP, RDP, and the live events
  feed are all WebSockets);
- set `X-Forwarded-For` / `X-Forwarded-Proto`, and — so Fleet sees the real client
  IP for the audit log, rate limiter, and the conditional-access IP allowlist — add
  the proxy's address to **`FLEET_TRUSTED_PROXIES`** (see the conditional-access
  notes); and
- match **`FLEET_PUBLIC_URL`** to the external `https://…` hostname the cert covers.

## Defense-in-depth in front of NPM

- **Cloudflare (recommended):** proxy the DNS record and enable WAF, Bot Fight
  Mode, rate-limiting rules, country/ASN blocks, and a **Turnstile/CAPTCHA**
  challenge on the login path. This absorbs bot noise before it reaches you.
- **fail2ban:** watch the nginx access log for repeated `401`s on
  `/api/v1/auth/login` and ban offending IPs at the firewall.
- **Firewall:** allow only 443/80 inbound to the proxy host.

## Enrolling existing hosts (no password auth)

Hosts that already use per-user keys in `authorized_keys` (password auth disabled)
can be enrolled three ways, all from the host's Enroll dialog:

- **SSH private key** — paste an existing private key that's authorized on the
  host. Used once over HTTPS for the bootstrap; never stored.
- **SSH agent (key never leaves the operator's machine)** — the backend performs
  the SSH handshake but forwards each signing request to the operator's local
  agent over a WebSocket; only signatures cross the wire. Build the bridges with
  `make enroll-agent-all` (cross-compiles macOS/Linux/Windows into
  `backend/bin/`) and hand each operator the binary for their OS — e.g.
  `fleet-enroll-agent-darwin-arm64` (Apple Silicon),
  `fleet-enroll-agent-windows-amd64.exe`. Then, with the key loaded (`ssh-add`):

  ```sh
  fleet-enroll-agent \
    -url https://fleet.example.com \
    -host web-01 \                 # hostname or id (register it in the UI first)
    -token "$FLEET_TOKEN" \        # your access token (or -user/-password, non-MFA)
    -bootstrap-user opsadmin \     # the user whose agent key is in authorized_keys
    [-via-jump] [-wg-endpoint vpn.example.com:51820] [-sudo-password ...]
  ```

  The bridge needs `$SSH_AUTH_SOCK` set (run `ssh-add` first) and network access to
  the host (directly, or add `-via-jump` to route through the jump host).

- **Manual pre-trust + "trusted"** — install the CA trust yourself, then enroll
  with the trusted method (no key or password sent to the backend).

After bootstrap the host trusts the Fleet CA and every user connects with their
own ephemeral per-host certificate; the operator's bootstrap key is no longer used.

## Pre-flight checklist

- [ ] Only proxy 443/80 are internet-reachable; everything else internal.
- [ ] `FLEET_COOKIE_SECURE=true`, `FLEET_ENV=production`, HTTPS + HSTS forced.
- [ ] Strong `FLEET_JWT_SECRET` / `FLEET_CSRF_SECRET` / `FLEET_CA_PASSPHRASE`.
- [ ] `FLEET_ALLOW_BOOTSTRAP=false` after the first admin exists.
- [ ] *Require MFA for all* enabled (or per-user for every account).
- [ ] Per-IP rate limits set; `lockout_policy` tuned.
- [ ] NPM Access List / Cloudflare WAF in front (if feasible).
- [ ] WebAuthn RPID/origins set to the public domain so passkeys work.
- [ ] `FLEET_JUMP_KNOWN_HOSTS` set so the gateway pins the jump host key.
