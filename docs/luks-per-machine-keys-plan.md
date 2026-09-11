# Per-machine LUKS keys — design plan

**Status:** not started. This is a plan, not a description of what the product does.

## The problem

A LUKS recovery passphrase belongs to an **image**, not to a machine.

`cryptsetup luksFormat` runs once, during the image build, with the passphrase
that build generated. Imaging writes that image to a disk block-for-block, so
every machine imaged from one image carries an identical LUKS header and accepts
the same passphrase on every encrypted partition. The vault note filed with each
credential already says exactly this.

Updates do not change it. RAUC's slot devices are rewritten for an encrypted
image to `/dev/mapper/luks-rootfs-a|b`, so a bundle install makes a fresh
filesystem *inside* the existing container and extracts a tar into it. The
header, and every keyslot in it, is untouched. A machine keeps the passphrase of
the image it was imaged from for as long as it lives.

So one extracted passphrase opens **every disk imaged from that image**. For a
fleet of kiosks behind a locked door that may be an acceptable concentration.
For laptops it is not: the threat model for a laptop is that somebody has the
laptop.

### What this is not

Day-to-day unlock is already per-machine when `--unlock tpm2` is used: the
volume is bound to that machine's TPM, and the passphrase is the *recovery*
slot. This plan narrows the blast radius of the recovery key. It does not change
how a healthy machine boots.

## What "done" looks like

Each machine holds a recovery passphrase that is unique to it, filed in the
credential vault against that machine, and the image-wide passphrase no longer
opens it.

## The mechanism: rekey at first boot

The machinery is largely present. `luks-enroll.sh` already runs once at first
boot, manipulates keyslots, and reaps the bootstrap key afterwards — under
`ConditionPathExists=!/var/lib/luks-enroll.done`, so it is inert on every
subsequent boot.

1. Generate 32 random bytes on the machine.
2. `cryptsetup luksAddKey` it to every encrypted volume, authenticating with the
   bootstrap keyfile that is already on the BOOT partition.
3. Hand the new passphrase to the server, which files it as
   `luks/machine/<machine-id>`.
4. **Wait for the server to confirm it is stored.**
5. Only then `cryptsetup luksRemoveKey` the image-wide passphrase.

### The ordering is the whole design

Add → report → **confirm** → remove. Never remove before a confirmed store.

Every failure must leave the machine openable by something somebody has:

| fails at | machine still opens with | cost |
|---|---|---|
| add | image passphrase | none; retry next boot |
| report | image passphrase **and** its own | none; retry |
| confirm | both | none; retry |
| remove | both | not narrowed yet; retry |

There is no ordering of these steps that is merely *less good*. Get it backwards
— remove before confirm — and the failure mode is a machine whose recovery key
exists nowhere, discovered at a console. That is the same reasoning that already
makes `StoreImagePassphrase` file the passphrase **before** the build starts, in
a place where the stakes are considerably lower.

## The hard part: getting the key to the server

Today a machine never transmits key material. This plan requires it to, and that
is the part that deserves the most scrutiny.

**The agent check-in is the wrong channel.** It is plain HTTP in every
deployment I have seen (`checkin_url` is read out of `/boot/ab-deploy.json`, and
the imaging network is not a place to assume TLS). Pushing a recovery passphrase
over it would be worse than the problem being solved.

**Preferred: pull it over SSH, after enrollment.** The server already opens
authenticated, encrypted SSH sessions to managed hosts — that is how nudge,
install and host registration work, and the machinery is the same `s.dial` in
every case. Inverting the direction removes the new push path entirely:

- the machine adds its keyslot at first boot and leaves the passphrase in a
  root-only file
- after enrollment the server reads it over SSH, files it, and tells the machine
  to remove the image-wide slot and the temporary file
- a machine that is never enrolled keeps both keys, which is the safe state

This also gets the confirmation step for free: the server has stored the value
before it asks for the removal, so step 4 is not a protocol, it is the order of
two SSH commands.

**If a push is required anyway** (machines that are never enrolled as hosts), it
must be HTTPS with a verified certificate, refuse to send over plain HTTP, and
authenticate the machine as more than a MAC address.

## Consequences elsewhere

- **The delete guard** (shipped) keys on the image credential. It needs a second
  rule for `luks/machine/*` — those are one-to-one and deleting one is always
  destroying a recovery key.
- **`luks-enroll.sh` reaps the bootstrap key** after TPM2/Tang enrollment. The
  rekey needs that key, so it must run before the reaper, or the reaper must
  wait. Both units are already condition-guarded; the ordering is a
  `Before=`/`After=` pair, not new machinery.
- **Bundles are unaffected.** `make-bundle.sh` opens the *image*, not a machine,
  so it still wants the image passphrase.
- **Re-imaging resets it.** A machine imaged again is a new machine as far as
  keys are concerned; the old per-machine credential should be retired.
- **Recovery gets easier, not harder.** Finding the right passphrase becomes
  "look up this machine" rather than "work out which image this was built from,
  months ago".

## Migration

Existing machines keep the shared key until something narrows them. Two paths,
both wanted:

- **on re-imaging** — free, no extra code beyond the first-boot path
- **narrow now** — an action on an enrolled host that runs the same
  add/store/remove over SSH, so a fleet can be migrated without re-imaging

The image-wide credential must survive until the last machine imaged from it has
been narrowed. The dependency badge already shows exactly that count, which is
what makes this migration auditable rather than hopeful.

## Open questions

1. **Keep the image passphrase as a break-glass?** Retaining it in a separate,
   tightly-scoped vault folder trades some of the benefit for a fleet-wide way
   in when per-machine records are lost. My inclination is no — it re-creates
   the concentration this removes — but it is a real choice.
2. **What authenticates a machine that pushes?** Only relevant if the pull-over-
   SSH design is rejected.
3. **FIPS interaction.** Per-machine keys touch the same keyslot code the FIPS
   profile already reworked (PBKDF2 rather than argon2); the rekey must honour
   the active crypto profile rather than hard-coding a KDF.
4. **Does this apply to `--unlock passphrase` images?** Those have no bootstrap
   keyfile to authenticate the `luksAddKey` with. Probably out of scope: a
   machine that requires a typed passphrase at every boot already has a human
   who knows it.

## Effort

The rekey script and its unit ordering are small. The SSH pull, the vault
naming, the delete-guard rule and the "narrow now" action are each modest. The
cost is concentrated in testing the failure paths — specifically, proving that
every interruption leaves a machine that still opens — and that is where the
time should go, because it is the only part where a mistake is unrecoverable.
