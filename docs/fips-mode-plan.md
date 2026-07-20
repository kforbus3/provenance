# FIPS Mode — Design & Migration Plan

Status: **P0–P4 implemented** on branch `feature/fips-mode` (opt-in, default-off,
non-FIPS behavior unchanged). A fresh `FLEET_FIPS_MODE=true` deploy works end-to-end
including the OpenVPN overlay, and the existing-install migration toolset (`fleetctl
fips …`, verify-then-upgrade-on-login, secret re-seal sweep) and a UI readiness
dashboard are in place. Both a FIPS boot and a default WireGuard boot are validated in
Docker. The only remaining items are operator-provided (FIPS-OpenSSL host images) — see
"Implementation status" below.

## Implementation status

**Done (P2 — cert-authenticated overlays: OpenVPN + strongSwan, per-host selectable):**
- **`internal/overlaypki`** — an X.509 CA (ECDSA P-256) distinct from the SSH CA, shared by
  both cert overlays (which authenticate peers with X.509 certs an SSH CA cannot issue).
  The CA key is `secretbox`-sealed at rest (v3/PBKDF2 under FIPS) in `overlay_ca`; generated
  once and **reloaded** (decrypted) on restart. Client certs are CN-bound to the host UUID
  (`fleet-h-<id>`), recorded in `overlay_clients`.
- **`internal/overlay`** — an `Overlay` interface (`EnsureServer` / `ProvisionHost`) with two
  implementations:
  - **OpenVPN**: jump-host `server.conf`, per-host `client.ovpn`, `ccd` static-IP pins.
    Suite: TLS 1.2/1.3, AES-256-GCM, **ECDHE-P256** (pins `tls-groups secp256r1:secp384r1`
    — OpenSSL 3 ignores the deprecated `ecdh-curve` and would otherwise pick non-approved
    X25519), ECDSA-P256 mutual cert auth.
  - **strongSwan / IPsec (IKEv2)**: `swanctl` responder + initiator config, per-host virtual
    IP pinned **server-side** to the client cert CN via a single-address pool (spoof-proof).
    Suite: `aes256-sha256-ecp256` (IKE, ECDHE P-256) + `aes256gcm16-ecp256` (ESP).
- **Per-host selection.** The overlay is chosen **per host** at enrollment (`hosts.overlay`
  column; enroll dialog dropdown / `overlay` API field), resolved as per-enroll choice →
  the host's recorded overlay → the deployment default `FLEET_OVERLAY`. Enrollment dispatches
  WireGuard vs. a cert overlay on that effective value and provisions via the overlay
  registry, storing the assigned address in the **same `wg_address` column** WireGuard uses —
  so the SSH gateway dials the host identically regardless of transport. The WireGuard path
  is untouched (all changes are additive, gated on `overlay.IsCertOverlay(effective)`).
- **Server boot** builds both provisioners sharing the PKI; the overlay CA is created
  **lazily** (only when a host actually uses a cert overlay), pre-warmed on boot only when the
  deployment default is itself a cert overlay — so a pure-WireGuard deployment never creates it.
- Validated end-to-end in Docker: OpenVPN PKI chain + live tunnel (mutual ECDSA auth,
  TLS1.3/`TLS_AES_256_GCM`, ECDHE-P256, ping over the tunnel), ccd static per-host IP,
  Fleet's actual provisioning scripts on real containers; overlay-CA persistence/reload
  against real Postgres; FIPS + WireGuard boots both validated. strongSwan config generation
  is unit-tested (FIPS proposals, CN-pinned IP, no non-approved curves); its live IPsec
  tunnel requires an IPsec-capable host to exercise (kernel xfrm), documented as such.

**Done (P0 — foundation, and P1 — in-process crypto):**
- **Go 1.24 toolchain** with the native FIPS 140-3 module. It is compiled into every
  Go 1.24 binary, so FIPS is a **runtime toggle** — no separate artifact. The
  entrypoint sets `GODEBUG=fips140=on` when `FLEET_FIPS_MODE=true`; the backend
  **fails closed** at boot if the module isn't active in FIPS mode.
- **`internal/cryptoprofile`** — the single policy hub. `Default` = today's behavior
  verbatim; `FIPS` = the approved set. Selected once at boot from `FLEET_FIPS_MODE`.
- **ECDSA P-256** for the user CA and every per-session/host/system identity
  (`ca`, `identity/{issuer,system,material}`); the key type is derived from the
  signer, and the in-RAM key **zeroize** handles both Ed25519 and ECDSA.
- **PBKDF2-HMAC-SHA256** KDF (600k iters) for at-rest secrets (`secretbox` v3
  envelope; Open still reads v2/argon2id + legacy) and passwords (`auth/password`;
  Verify auto-detects the algorithm, enabling verify-then-upgrade-on-login). The
  MFA-at-rest key uses **HKDF-SHA256** under FIPS.
- **SSH transport pinned** to AES-GCM + ECDH-P256/384 + ECDSA/RSA host keys +
  HMAC-SHA-256 across every gateway `ssh.ClientConfig` (never negotiates
  curve25519/chacha20).
- **TOTP → HMAC-SHA256** and **WebAuthn → ES256/RS256 only** (no EdDSA) under FIPS.
- **Boot self-check** (module active + active CA not Ed25519) and **`fleetctl fips
  check`** readiness report.

Validated end-to-end: a fresh `FLEET_FIPS_MODE=true` deploy activates the module,
generates an ECDSA CA, and passes the self-check; a non-FIPS deploy is byte-for-byte
unchanged (Ed25519, module off); FIPS-without-module refuses to start.

**Done (P1 TLS pins):**
- **Outbound TLS pinned** to `MinVersion: TLS 1.2` on SMTP (`notify/senders.go`) and
  LDAP StartTLS (`auth/ldap.go`); the enroll-agent **fails closed** on `-insecure` when
  `FLEET_FIPS_MODE` is set, and pins TLS 1.2 on its remaining paths.

**Done (P3 — existing-install migration toolset, M2–M6):**
- **M2 (CA migration):** `fleetctl rotate-ca` in a FIPS-configured environment mints an
  **ECDSA** CA (key type follows `cryptoprofile.For(FIPS)`); rotation keeps the prior CA
  trusted through the transition (dual-CA).
- **M3 (secret re-seal):** the boot re-seal (`FLEET_REENCRYPT_SECRETS=true`) upgrades the
  CA-key envelope on `secretbox.NeedsReseal`; and **`fleetctl fips reseal-secrets`** sweeps
  every at-rest secret to PBKDF2 in place — CA key, overlay CA key, notification secrets
  (SMTP/PagerDuty/Opsgenie), LDAP/OIDC secrets, and vault entries — each verify-before-
  overwrite via `secretbox.ResealBytes`. Targets v3 unconditionally (run before the flip).
- **M5 (credential refresh):** login now **verify-then-upgrades** a matched Argon2id
  password to PBKDF2 (best-effort, never blocks login); **`fleetctl fips
  flag-stale-passwords`** forces `must_change_pw` on local accounts still on a non-FIPS
  hash (for accounts that never log in). WebAuthn EdDSA passkeys are surfaced for
  re-registration in the readiness report.
- **M6 (attestation):** `fleetctl fips check` reports module status, overlay, CA key type,
  password-hash algorithms, and MFA factors with a ready/not-ready verdict.

**Done (P4 — docs + UI):**
- This runbook (deploy config, jump-host requirements, migration steps).
- A **FIPS 140-3 Readiness** card on the System Health page (`GET /api/v1/system/fips`),
  mirroring `fleetctl fips check` with per-artifact OK / NOT-FIPS chips and an overall
  verdict. Hides itself on older backends.

Validated end-to-end (Docker): a `FLEET_FIPS_MODE=true` backend boots with the module
active, applies all migrations, creates the overlay PKI CA, generates an **ECDSA** user
CA, and `fips check` returns a green verdict; a default (non-FIPS) boot on a fresh DB is
unchanged — Ed25519 CA, WireGuard overlay, module off, and the overlay PKI is never
created.

**Remaining (operator-provided / optional):**
- **Host-OS FIPS OpenSSL images** — the jump host and managed hosts must run a
  FIPS-validated OpenSSL for the whole trust chain to be FIPS; Fleet documents this
  requirement but does not ship the host images.
- **Guided TOTP re-enrollment UX** — SHA-1 TOTP still verifies (HMAC-SHA-1 is technically
  FIPS-approved); a forced SHA-256 TOTP re-enrollment flow is not built, by choice.

---

## Original design (grounded in a full crypto inventory of the codebase)

## Goal & boundary

Add an opt-in **FIPS mode** in which *all* cryptography Fleet performs uses FIPS 140-3
approved algorithms running inside a validated cryptographic module. FIPS mode is a
**policy profile**, selected by `FLEET_FIPS_MODE=true`. When off (the default),
nothing changes — Ed25519, WireGuard, and Argon2id remain for normal installs. We take
nothing away from non-FIPS deployments.

Two deployment stories, both required:
1. **Fresh FIPS deploy** — easy: start with `FLEET_FIPS_MODE=true` and the approved
   profile is used from first boot.
2. **Existing install → FIPS** — the hard part: a migration that rotates the CA to an
   approved key type, replaces the WireGuard overlay with OpenVPN, re-encrypts secrets
   under an approved KDF, and refreshes credentials. Planned in detail below.

Honest scope statement for buyers: FIPS mode requires the **whole trust chain** to be
FIPS — the Fleet backend image (validated module), the jump host, and every managed
host's OS crypto (OpenSSL) — not just the Go binary.

---

## What must change (from the inventory)

| # | Today (non-FIPS) | FIPS profile | Where |
|---|---|---|---|
| 1 | Ed25519 CA + all SSH certs | **ECDSA P-256** (or P-384) | `ca/ca.go:89`, `identity/{issuer.go:73, system.go:44, material.go:33}` |
| 2 | SSH transport: default negotiation (curve25519, chacha20-poly1305, ed25519 host keys) | Pin **aes-256-gcm + ecdh-sha2-nistp256 + ecdsa/rsa host keys + hmac-sha2-256** | every `ssh.ClientConfig` in `sshgw/gateway.go` (~16 sites) + the terminal/enroll server configs |
| 3 | WireGuard overlay (Curve25519/ChaCha20/Poly1305/BLAKE2s) | **OpenVPN** (FIPS OpenSSL, TLS 1.2+, AES-256-GCM, ECDHE-P256, cert auth) | `enrollment/service.go:520-684`, jumphost scripts, gateway address resolution |
| 4 | Argon2id KDF (secrets + passwords) | **PBKDF2-HMAC-SHA256** (SP 800-132, high iteration count) | `secretbox/secretbox.go:104`, `auth/password.go:33` |
| 5 | Legacy bare-SHA-256-as-key (secrets, MFA key) | **disallow in FIPS** (fail closed; force re-seal) | `secretbox/secretbox.go:87`, `auth/mfa.go:42` |
| 6 | TOTP HMAC-SHA1 | **HMAC-SHA256 TOTP** (policy decision — see Open Questions) | `auth/mfa.go:35,208` |
| 7 | WebAuthn advertises EdDSA + ES256 | **restrict COSE algs to ES256 (P-256) / RS256** | `auth/webauthn.go:84` |
| 8 | Go 1.23, no FIPS module, `CGO_ENABLED=0` alpine | **Go 1.24+ `GOFIPS140` module**, `GODEBUG=fips140=on` in FIPS mode | `go.mod`, `backend/Dockerfile` |
| 9 | Outbound TLS clients: Go defaults | Pin `MinVersion: TLS1.2` + approved cipher suites (SMTP/LDAP/OIDC) | `notify/senders.go:69`, `auth/ldap.go:78`, http transports |
| 10 | Enroll-agent `InsecureSkipVerify` | Verify certs (needed for FIPS *and* is a standing security gap) | `cmd/fleet-enroll-agent/main.go:64,98` |

**Already FIPS-approved (keep):** AES-256-GCM (secretbox, MFA-at-rest), AES-256-CBC+PBKDF2
(backup via openssl), HMAC-SHA256 (JWT/MFA tokens), SHA-256 (audit hash chain, token
hashing), `crypto/rand`.

---

## Foundational decision — the Go FIPS runtime (and the x/crypto caveat)

Use **Go 1.24+'s native FIPS 140-3 module** (`GOFIPS140`), not BoringCrypto. It is pure
Go (no cgo), so we keep the `CGO_ENABLED=0` static-alpine build model, and one image
serves both modes: FIPS mode just sets `GODEBUG=fips140=on` (strict: `=only`) at runtime
and selects the FIPS profile.

**The catch the inventory surfaced:** `golang.org/x/crypto` — which provides the SSH
transport (`x/crypto/ssh`) and Argon2 — is **outside the boundary of the Go FIPS
module.** So a FIPS build does not, by itself, make SSH or the KDF compliant. Two
consequences, both handled by the plan:

- **SSH transport:** the fix is to **pin** the SSH algorithms (#2) to AES-GCM +
  ECDH-P256 + ECDSA. Those primitives are implemented by the Go *standard library*
  (`crypto/aes`, `crypto/cipher`, `crypto/ecdsa`, `crypto/sha256`), which the FIPS
  module *does* validate. `x/crypto/ssh` is protocol framing that calls into those
  validated primitives — the accepted FIPS posture (the module does the crypto; the
  framing does not). We must never let it negotiate curve25519/chacha20.
- **Argon2 → PBKDF2:** replace with Go 1.24's `crypto/pbkdf2` (stdlib, validated HMAC),
  eliminating the x/crypto/argon2 dependency in FIPS mode.

Deliverable: bump to Go 1.24+, a `Dockerfile` build arg producing a `GOFIPS140`-built
image, and a boot-time self-check that the validated module is active when
`FLEET_FIPS_MODE=true` (fail closed otherwise).

---

## The crypto-profile abstraction (keeps non-FIPS untouched)

Introduce a `cryptoprofile` selected once at boot from `FLEET_FIPS_MODE`:

```
type Profile interface {
    GenerateCAKey() (crypto.Signer, keytype string)   // ed25519 | ecdsa-p256
    GenerateIdentityKey() (crypto.Signer, error)       // per-session/host/system
    KDF(passphrase, salt) []byte                        // argon2id | pbkdf2-sha256
    SSHAlgorithms() ssh.Config-pins                     // nil(default) | pinned FIPS set
    OverlayProvisioner() Overlay                         // wireguard | openvpn
    TOTPAlgorithm() otp.Algorithm                        // sha1 | sha256
    WebAuthnCredParams() []COSE                          // default | es256/rs256 only
    Name() string                                        // "default" | "fips"
}
```

`DefaultProfile` = today's behavior verbatim. `FIPSProfile` = the approved set. Every
current hardwired choice (the `ed25519.GenerateKey` at `ca.go:89`, `issuer.go:73`, etc.;
the Argon2 in `secretbox`/`password`; the bare `ssh.ClientConfig`s; the WG enrollment)
routes through the profile. This is the bulk of the code work and it is mechanical once
the interface exists.

Fail-closed boot validation in FIPS mode: refuse to start if the active CA is Ed25519,
the overlay is WireGuard, any at-rest secret is still Argon2id/legacy-sealed, or the
validated module isn't active — with a clear "run the FIPS migration" error.

---

## Overlay: WireGuard → OpenVPN

WireGuard has **no FIPS mode** (its primitives are all non-approved), so it is replaced,
not reconfigured. **OpenVPN is the primary/default FIPS overlay**; **IPsec/IKEv2 via
strongSwan is a supported alternative** (`FLEET_OVERLAY=openvpn|strongswan`) for
operators who prefer kernel IPsec or already run strongSwan. Both authenticate hosts
with certs from Fleet's ECDSA CA and use approved suites (AES-256-GCM, ECDH/ECDHE
P-256). The overlay is pluggable behind the profile's `OverlayProvisioner`, so adding
strongSwan is a second provisioner implementation, not a rearchitecture.

FIPS OpenVPN shape: OpenVPN 2.5+ linked against a **FIPS-validated OpenSSL 3 provider**,
`tls-version-min 1.2`, `data-ciphers AES-256-GCM`, ECDHE-P256, and **certificate auth**
— clients present a cert issued by Fleet's (now ECDSA) CA. This is a nice synergy: the
overlay and SSH share the same FIPS CA, and the per-host identity Fleet already persists
(from the HA work) becomes the OpenVPN client identity.

Fleet changes:
- The jump-host image runs an **OpenVPN server** (FIPS OpenSSL) instead of / alongside
  the WG hub. It trusts the Fleet CA and issues/accepts client certs.
- `internal/enrollment` gains an **OpenVPN provisioning path** parallel to the WG one:
  install openvpn, drop a client config + a CA-issued client cert, bring up the tunnel,
  register the client on the server. Reuses the enrollment scaffolding (validation,
  jump-peer step, address assignment).
- The gateway's address resolution (`firstAddr`, overlay address) becomes overlay-aware
  (WG address vs OpenVPN-assigned address).
- Config: `FLEET_OVERLAY=wireguard|openvpn` (derived from FIPS mode by default);
  OpenVPN server params mirror the existing WG ones.

---

## Fresh FIPS deploy (the easy path)

`FLEET_FIPS_MODE=true` + the FIPS image. First boot: CA generated ECDSA P-256, secrets
PBKDF2-sealed, overlay = OpenVPN, TOTP SHA-256, WebAuthn ES256-only, SSH pinned. Boot
self-check passes. Done — indistinguishable in workflow from a normal deploy.

**Config for the OpenVPN overlay (derived automatically under FIPS; shown for clarity):**

| Env var | Default | Meaning |
|---|---|---|
| `FLEET_FIPS_MODE` | `false` | `true` sets `GODEBUG=fips140=on` and derives the FIPS profile. |
| `FLEET_OVERLAY` | derived | Deployment **default** overlay: `openvpn` under FIPS (else `wireguard`). Overridable per host at enrollment (`wireguard` \| `openvpn` \| `strongswan`). |
| `FLEET_OVPN_PORT` | `1194` | UDP port the jump-host OpenVPN server listens on. |
| `FLEET_WG_SUBNET` / `FLEET_WG_JUMP_IP` | — | Reused verbatim for every overlay's address plan (OpenVPN `server`/`ccd`, strongSwan pool/virtual IPs). |
| `FLEET_WG_JUMP_ENDPOINT` | — | Address managed hosts dial; OpenVPN applies `FLEET_OVPN_PORT`, strongSwan uses IKE UDP 500/4500. |

Per host, the overlay is chosen in the **enroll dialog's "VPN overlay" dropdown** (or the
`overlay` field of the enroll API) — "Deployment default" keeps `FLEET_OVERLAY`.

**Jump host** needs the relevant VPN package(s) — `openvpn` and/or `strongswan` +
`strongswan-swanctl` (the test-fabric image installs all three) — plus a `/dev/net/tun`
device (OpenVPN) or kernel IPsec/`xfrm` (strongSwan), and `NET_ADMIN` (the enrollment
scripts install the VPN package on demand if missing). The first host on a given overlay
provisions that overlay's jump-host server idempotently; the overlay CA is created on
first use (or on boot when the default is a cert overlay).

**Verify** with `fleetctl fips check` (module active, overlay, ECDSA CA) and, on the jump
host, `pgrep -f 'openvpn .*server.conf'` (OpenVPN) or `swanctl --list-conns` / `swanctl
--list-sas` (strongSwan). A managed host that enrolled over a cert overlay shows its
assigned address (same column as WireGuard) and a `tun0` (OpenVPN) or IPsec policy to the
jump's overlay IP.

---

## Migration: existing install → FIPS (the hard part)

An existing install has Ed25519 CA + certs, a WireGuard overlay, Argon2id-sealed secrets
and passwords, SHA-1 TOTP, possibly EdDSA WebAuthn creds, and a non-FIPS binary. The
migration is a **staged, reversible-until-cutover** procedure driven by a new
`fleetctl fips ...` toolset and a readiness dashboard. Phases:

**M0 — Readiness report.** `fleetctl fips check`: enumerate every non-compliant artifact
(CA key type, overlay, each secret's KDF, password-hash algorithms in use, TOTP alg,
EdDSA WebAuthn creds, binary/module status). Nothing changes; produces the work list.

**M1 — Deploy the FIPS-capable binary.** Swap to the `GOFIPS140` image, still with
`FLEET_FIPS_MODE=false`. The validated module is now present; behavior unchanged. This
de-risks the runtime change from the crypto migration.

**M2 — CA migration (Ed25519 → ECDSA), dual-CA.** Extend the existing additive CA
rotation (`ca.go:118 Rotate` — the one hardwired `ed25519.GenerateKey` to fix) to mint an
**ECDSA** CA while the Ed25519 CA stays active/trusted. Push the new CA's public key into
every host's `TrustedUserCAKeys` (the enrollment `caTrustScript` already writes this —
run it as a fleet-wide "trust new CA" sweep, leader-gated per the HA model). New sessions
issue ECDSA certs; old Ed25519 certs still validate. Once every host trusts the ECDSA CA,
**retire** the Ed25519 CA (KRL/inactivate). No session interruption.

**M3 — Overlay migration (WireGuard → OpenVPN), dual-overlay.** Stand up the OpenVPN
server on the jump host alongside WG. Re-enroll each host onto OpenVPN (issue a client
cert from the ECDSA CA, install the client, bring up the tunnel) while WG stays up — the
gateway prefers whichever overlay is healthy. Once a host is reachable over OpenVPN,
tear down its WG peer. This is effectively a fleet-wide re-enrollment; plan it as a
batched, resumable job with per-host status (like enrollment jobs today). Highest-effort
phase.

**M4 — Re-encrypt secrets (Argon2id → PBKDF2).** Extend the secretbox envelope-migration
already present (`ReencryptSecrets`, `ca.go:57-85`) to re-KDF: on read (or a one-shot
sweep), if a secret is Argon2id/legacy-sealed and FIPS mode is arming, re-seal with
PBKDF2-HMAC-SHA256 using the same passphrase. Covers the CA key, vault secrets, and
SMTP/OIDC/LDAP creds. The MFA-at-rest key (`mfa.go:42`, bare SHA-256) moves to a proper
KDF too.

**M5 — Credential refresh.** Passwords can't be re-hashed without the plaintext:
`password.go` gains PBKDF2 support and a **verify-then-upgrade-on-login** path (verify
against the stored `$argon2id$`, re-hash as `$pbkdf2$`, store the new algorithm tag) plus
an admin "force password reset" for accounts that don't log in within a window. If TOTP
moves to SHA-256, users **re-enroll TOTP** (guided prompt); EdDSA WebAuthn credentials
are flagged and must be re-registered. Recovery codes re-generated.

**M6 — Flip `FLEET_FIPS_MODE=true`.** The boot self-check now must pass: ECDSA CA,
OpenVPN overlay, all secrets PBKDF2, module active, SSH pinned. Enforcement is
fail-closed — any residual non-FIPS artifact blocks startup with a pointer to the
offending item. Emit a **FIPS attestation** record (module version, algorithm set, CA
fingerprint) to the audit log.

Reversibility: M1–M4 are reversible (dual-CA, dual-overlay, secrets still decryptable).
M6 is the point of no return; M5 credential changes are one-way. The readiness report
gates M6.

---

## What stays unchanged for non-FIPS installs

Everything. `FLEET_FIPS_MODE=false` (default) selects `DefaultProfile`: Ed25519, WG,
Argon2id, SHA-1 TOTP, default SSH negotiation — byte-for-byte today's behavior. The
FIPS-built image runs identically with `fips140=off`. The only visible additions are the
config flag and the `fleetctl fips` subcommands (inert unless used).

---

## Open questions (need your call)

1. **Overlay:** ✅ Decided — **OpenVPN primary/default**, **strongSwan (IPsec/IKEv2) a
   supported alternative** behind the same overlay abstraction.
2. **TOTP:** move to HMAC-SHA256 (stricter, but some authenticator apps only do SHA-1),
   or keep HMAC-SHA1 (HMAC-SHA-1 is technically still FIPS-approved for HMAC, though many
   FIPS programs disallow SHA-1 entirely)? Affects whether users must re-enroll MFA.
3. **CA curve:** ECDSA **P-256** (compact/fast, ubiquitous) or **P-384** (higher
   assurance, some agencies mandate)? Or RSA-3072 for maximum interop?
4. **Host OS crypto:** do we ship/require a FIPS-OpenSSL jump-host image and document the
   managed-host OpenSSL FIPS requirement, or leave host-OS FIPS to the operator?
5. **One image or two:** single FIPS-capable image (mode via flag) vs separate
   `fleet:fips` image. Single is simpler; some buyers want a physically separate
   validated artifact.

---

## Sequencing & effort

- **P0 (foundation):** Go 1.24 bump + `GOFIPS140` build + boot self-check + the
  `cryptoprofile` abstraction with `DefaultProfile` wired (no behavior change). Verifies
  the whole thing is inert until FIPS is enabled.
- **P1:** `FIPSProfile` for the *in-process* crypto — ECDSA CA/identities, pinned SSH
  algorithms, PBKDF2 KDF, TOTP/WebAuthn policy, TLS-client pins. Fresh-deploy FIPS works
  end-to-end **except the overlay**.
- **P2:** OpenVPN overlay (jump-host server + enrollment provisioning + gateway
  address-awareness). Fresh FIPS deploy fully works.
- **P3:** the `fleetctl fips` migration toolset (M0–M6) for existing installs — CA
  dual-rotation sweep, dual-overlay re-enrollment, secret re-seal, credential upgrade,
  fail-closed flip + attestation.
- **P4:** docs (a FIPS deployment + migration runbook, like the HA guide), the
  FIPS-OpenSSL host images, and a readiness dashboard in the UI.

P2 (overlay) and P3 (migration) are the heavy, highest-care areas — adversarial review,
and the migration must be tested against a real WG→OpenVPN + Ed25519→ECDSA transition on
the test fabric before it touches a production install.
