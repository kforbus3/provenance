# Imaging and OS updates

Provenance manages a machine's whole life. Most of this product manages
machines that already exist — access, sessions, policy, audit. This part builds
the operating system they run and puts it on their disks: an A/B image builder,
a PXE imaging server, signed RAUC update bundles, and a control plane that rolls
those bundles out in stages.

It is one program, not two talking to each other. That matters more than it
sounds, and the rest of this page is mostly the consequences.

## Why one program

An imaging control plane, on its own, has to be a **pull**: each machine runs an
agent that checks in every few minutes and is told whether to install anything.
That is not a preference, it is forced by how machines are provisioned. A
machine is imaged on a private provisioning switch and then moved to wherever it
actually lives. From that moment the imaging server does not know its address
and usually cannot route to it. So it cannot push, and an operator who starts a
rollout can only wait.

This server already reaches every enrolled host, through the jump host over the
overlay, because that is what the rest of it does all day. So the pull stays —
it is what makes a rollout work at all for a machine behind a firewall nobody
here controls — and reaching out becomes the fast path on top of it:

- **A rollout that would take hours of polling finishes in minutes.** The
  machines a rollout is waiting on are asked to check in now, and do.
- **Machines that can never reach this server can still be updated.** The server
  reaches *them*, installs directly, and reports what it saw on the host.

In the other direction, imaging supplies the half of a machine's life that a
fleet manager never has: what image it was built from, what is inside that
image, and what version it is running right now.

## What decides what

**The rollout engine decides what happens.** Canary, soak, batch size, failure
budget, maintenance window, and the rule that a machine counts as updated only
when it comes back on the new version and healthy. It lives in
`backend/internal/imaging/engine.go` and is deliberately pure — every function
takes a rollout, a report and a clock, and returns a decision. Nothing in it
reads a database, a socket, or the wall clock. That is what makes the rules
testable at all, and those rules are the parts that can be silently wrong in a
way that only ever shows up as "the whole fleet is on the bad version".

**Reaching a machine decides nothing.** A nudge makes a machine ask sooner; the
answer it gets is the same answer it would have got on its own timer. This is
the line to hold: there is one set of rules governing a rollout, however it was
started, and no second copy of a decision that has to be kept in step.

Identity, host access, audit and notification are this product's, as they are
for everything else it manages.

## The three ways a machine gets an update

Chosen per machine, best first.

### 1. Its own check-in (the base case)

The agent checks in on its timer, is told there is a bundle for it, installs it,
reboots, and reports the new version. No operator, no network path inward, no
component of this server needing to be up at the right moment.

This is the one that has to keep working. Everything below is an optimisation on
top of it.

### 2. Nudge (the normal case)

The machine is paired with an enrolled host this server can reach. It runs

```
ab-agent --now
```

over the SSH gateway. The agent then does exactly what it would have done five
minutes later, and the rollout applies its rules unchanged.

If the nudge fails — host asleep, overlay blip, sshd busy — the agent polls on
its own timer anyway. **A failed nudge costs latency, not the update**, which is
why one is logged at debug and not raised as an alert.

### 3. Direct install

The machine cannot reach this server at all: a site with no route home, or a
host imaged before the agent existed. The server runs

```
ab-update <bundle URL>
```

on it. The machine still fetches the bundle itself, from the URL recorded on the
rollout. RAUC verifies the signature against the certificate baked into the
image exactly as on every other path — an operator asking for an install does
not become a reason to trust a bundle.

This bypasses the canary, the soak and the failure budget, so it is offered in
the UI only for machines that cannot use path 1 or 2, and never as the habitual
button.

### …and the report that closes it

A machine updated by (3) still cannot say what happened, so the rollout would
sit on it until the offer times out — recording a successful update as a
failure. The server files the report instead, but only about what it has just
*read off the host*: the version file the bundle's install hook wrote, and
`systemctl is-system-running`.

That is not the machine's self-report relayed onward. It is the server saying
"I looked, and this is what is there", which is better evidence than the
machine's own word, not worse. The distinction is kept in the record —
`reportSource` is `agent` or `observed`, with `reportedBy` naming who — because
when one kind of claim turns out to be wrong, the fleet's history should say
which kind it was.

## Machines and hosts

A **machine** is keyed by what the imager saw, usually a MAC address. A **host**
is an enrolled thing with a hostname and an overlay address.

They are deliberately not the same record, and a machine is not a column on a
host. A machine exists *before* it is a host: it is imaged on the provisioning
switch and only later enrolled. That window is exactly where "imaged perfectly
and never came back" lives — the failure the imager's own reports cannot cover,
because the last of them is sent before the reboot. A machine that never appears
again is visible here precisely because it is its own record.

Pairing a machine to a host is recorded explicitly, by an operator, and never
inferred from a hostname. Hostname matching works right up until somebody
renames one, and then it silently re-points at a different machine — which for a
rollout means updating something nobody targeted.

An unpaired machine is not hidden and is not broken. It still takes rollouts, on
its own timer. What it cannot do is be reached: no nudge, no direct install, no
reading a version off it when it goes quiet.

## Rollout targets

A rollout targets one of three things, and it resolves to **machines**, never to
hosts:

- **The whole fleet** — every A/B machine. Not every host: an ordinary server
  that was never imaged has no machine record, so it is not in the set and
  cannot be reached by a rollout at all.
- **A host group** — the same groups access control and policy use, not a second
  set naming the same machines. A stale copy of "which machines are production"
  is how the wrong fleet gets an update. Members of the group that are not A/B
  machines are simply not targeted; they are not attempted and cannot fail it.
- **Individual hosts** — for updating one machine without inventing a group for
  it. The picker offers only hosts already paired with a machine, because an
  unpaired host resolves to nothing.

A machine reaches a rollout through the host it is paired with. **A host with no
machine record is invisible to every rollout, including a fleet-wide one** — which
is correct for a server that was never imaged, and wrong for an A/B machine this
server did not image (restored from backup, imaged by an earlier server, or whose
record was deleted). Register it from the host's own page: **Hosts → the host →
details → A/B updates → Register for updates**. That reads its real slot and
version over SSH rather than assuming them, and refuses a host that has no
`ab-update` rather than creating a record that could only ever fail.

## Maintenance windows

A window gates when a rollout may **start** a machine. One already installing is
left to finish; there is no way to reach into an install, and interrupting one is
how a machine ends up on neither version.

Windows are evaluated in **server-local time**, on purpose. The alternative —
each machine deciding against its own clock — means a window means different
things on different machines, and the machine whose timezone is wrong is exactly
the one nobody notices until it reboots mid-shift.

A window may wrap past midnight (`22:00`–`04:00`), in which case it belongs to
the day it *started* on: a Saturday window covers 23:00 Saturday and 01:00
Sunday, and neither Saturday noon nor Sunday noon.

## Building images

Builds run in the **builder-runner** sidecar, which is the only thing in a
deployment that touches the Docker socket.

That split is the point. Building an image means running a privileged container
that attaches a disk image to a loop device and debootstraps into it. A process
that can ask the Docker daemon for that can ask it for anything — a socket that
can start a privileged container with `/` bind-mounted is root on the host with
extra steps. So the backend holds an HTTP client and a token, and the privilege
lives in a container that does nothing else, rather than in the one that also
holds the SSH certificate authority.

The runner does not hold the raw socket either. It talks to `dockerproxy`, which
passes an allowlist of the calls a build actually makes and refuses the rest:
`exec` into another container, an arbitrary image, a host bind mount outside the
project. Both ways of getting an allowlist wrong are quiet — too tight and a
build fails with a 403 that names no call, too loose and the socket is still a
socket — so both directions are covered by
`scripts/imaging/test-docker-proxy.sh` against a real daemon.

The sidecar has no users, no sessions, no database and no opinion about who may
do anything. Every request reaching it has already passed this product's
authentication, permission check and audit. A second copy of that would mean
there were two, and the weaker one would be the one that mattered.

Building is **opt-in**:

```bash
docker compose --profile imaging up -d
```

with `FLEET_BUILDER_RUNNER_URL` and `FLEET_BUILDER_RUNNER_TOKEN` set. With no
runner URL the build routes answer `501` and say so; nothing is broken, the
deployment simply does not include the privileged sidecar. A fleet that consumes
images somebody else builds should not have to run one, nor invent a secret for
a service it does not have.

Also set **`HOST_PROJECT_DIR`** to this project's absolute path on the host. The
runner starts sibling containers through the Docker socket, so the daemon
resolves *their* bind mounts against the host filesystem rather than the
runner's; the socket proxy uses the same value to bound what a build may mount.
Left empty it is discovered from the runner's own `/project` mount, which is
right whenever that mount exists.

> **The profile is what makes the Provisioning tab work at all.** Without it
> there is no PXE server to start, no host NICs to enumerate, and no builder — so
> "Imaging → Provisioning" renders with an empty interface list. That is the
> deployment being incomplete, not the page being broken.

One build of a kind runs at a time. Two image builds share the output directory
and the same builder tag, and the failure is not a clean error — it is two loop
devices and a half-written artefact.

Cancelling a build removes the container, rather than only relabelling the job.
A non-interactive shell defers signals until its foreground command returns, so
signalling the shell alone would leave the builder running while the UI claimed
the build was cancelled.

## SBOMs, and what they cannot tell you

Every image and every bundle gets both an **SPDX 2.3** and a **CycloneDX 1.5**
SBOM, written beside the artefact, plus a `packages.tsv`. Verified against a real
build: 201 packages, every one carrying a version, and every CycloneDX component
carrying a **purl** — which is the field a CVE scanner matches on. These do the
vulnerability job properly.

They do **not** carry licence data. `make-sbom.sh` writes `NOASSERTION` for
`licenseConcluded`, `licenseDeclared` and `copyrightText` on every package, and
does not attempt to read them — Debian keeps licences in per-package copyright
files that are only semi-machine-readable, and guessing would be worse than
declining. So these SBOMs answer "what CVEs affect this image" and cannot answer
"what licences am I shipping", which is the other half of why an SBOM gets asked
for. Worth knowing before feeding one to a compliance tool and getting 201
unknowns back.

## The recovery passphrase

Ticking **Generate the recovery passphrase and store it** (on by default for an
encrypted build) generates 256 bits of random and files it **before the build
starts**.

That ordering is the whole point. Storing it afterwards means a write that fails —
an expired token, a sealed store, a network blip — has already produced an
encrypted image that nobody holds the recovery key for, and nothing about that
image says so. Storing first can only leave an unused secret behind if the build
then fails, which costs nothing and is visible in the credential list. **If the
passphrase cannot be stored, the build is not started.**

Where it goes:

- **An external secrets manager, when one is connected** — HashiCorp Vault KV v2
  or AWS Secrets Manager, from `FLEET_EXTSECRET_*`. An organization that already
  has a secrets manager should not need a second copy of record. The path is
  `FLEET_IMAGING_SECRET_PREFIX` (default `secret/blackfriars/images`) plus the
  image name.
- **Provenance's own credential vault otherwise**, sealed at rest, under
  `imaging/luks/<image>`.

Either way a credential record is created, so the passphrase is found the same way
in **Credentials** whichever backend holds the material — an external-backed record
simply carries a reference instead of a sealed blob.

Neither backend will **overwrite** an existing entry: Vault writes with `cas: 0`
and AWS uses `CreateSecret`, so a name already in use is refused rather than
replaced. The value that would be destroyed is the only copy of a recovery key for
machines already in the field.

**The image name is settled before the build**, because that is what the secret is
filed under. The backend picks the free name itself — it reads the same output
directory the image library comes from — and passes it explicitly, rather than
letting the builder choose one the backend cannot see until the build is already
running.

To recover a machine that will not boot: find `imaging/luks/<image>` in
Credentials, or read the reference straight from your secrets manager. Every
machine imaged from that image accepts the same passphrase on any encrypted
partition — rotating it means re-imaging, or `cryptsetup luksChangeKey` per
machine.

### An update never changes disk encryption

A machine's LUKS header is written **once, at imaging time**, and no update ever
touches it. For an encrypted image the RAUC slot devices are `/dev/mapper/
luks-rootfs-a|b`, so installing a bundle makes a fresh filesystem *inside* the
existing container and extracts into it. Every keyslot survives.

Three consequences, and the third is the one that costs people a machine:

1. **A machine keeps the passphrase of the image it was IMAGED from, for life** —
   however many bundles it installs afterwards. Its current OS version tells you
   nothing about which credential opens its disk.
2. **The credential for a newer image does not open an older machine.** A fleet
   can therefore hold several LUKS passphrases at once, partitioned by *when each
   machine was imaged*, not by what it is running.
3. **Deleting the credential for a retired image destroys the only recovery key
   for every machine imaged from it.** Nothing about those machines points back
   at it. The credential list shows a machine count on each `luks/` entry for
   this reason, and the server refuses the deletion while any machine still
   depends on it — `?force=true` overrides, and is audited separately.

Rotating a deployed machine's passphrase means `cryptsetup luksChangeKey` on that
machine, or re-imaging it. See
[per-machine LUKS keys](./luks-per-machine-keys-plan.md) for the plan to narrow
one-passphrase-per-image down to one per machine; it is **not implemented**.

### Bundle builds take the passphrase from the vault

Building a bundle from an encrypted image has to open its root slot, which needs
that image's passphrase. If the image was built with **generate and store** on,
the server files the passphrase as `luks/<image>` and supplies it automatically —
leave the field in the build dialog blank. Supply one explicitly only for an image
built with storing turned off, where your copy is the only one.

## Building for another distribution family

The builder handles two families. Which one is chosen follows from `--distro`:

| family | distros | bootstrap | initramfs | bootloader |
| --- | --- | --- | --- | --- |
| `deb` | debian, ubuntu | `debootstrap` | initramfs-tools | `grub-install` |
| `rpm` | almalinux, rocky, rhel | `dnf --installroot` | dracut | `grub2-install` |

For the RPM family `--suite` is a **major version** (`9`, `10`), not a codename —
there are no codenames, and dnf wants `--releasever`.

**RAUC is built from source there.** There is no `rauc` package in base or EPEL —
checked, not assumed: `dnf list rauc` on a stock Rocky 9 with EPEL enabled returns
*No matching Packages*. Since RAUC is what makes an image A/B-updatable, it is
built inside the image (pinned by `RAUC_VERSION`, default `v1.13`) and the
toolchain removed afterwards. It is built *in* the image rather than on the
builder because it links against that distribution's glib, openssl, curl and
libnl; a binary built elsewhere would be linked against another distribution's
versions of all four. CRB (CodeReady Builder) is enabled for meson and ninja.

The bootstrap installs the release package **first, on its own, with
`--nogpgcheck`**, and everything after it verified normally. The keys arrive
*inside* that package, so there is nothing to verify against until it lands;
installing it alone is what keeps that window to one package. It is a real window
and not a formality: with the wrong key in place the second transaction is
refused.

Two things about that first step are not obvious:

- **It comes from the target's mirror, not the builder's repositories.** A Rocky
  builder has no `almalinux-release` and never will, so the bootstrap defines its
  own repository with `--repofrompath` pointing at the distribution being built.
  The builder's own distribution therefore decides nothing about which
  distributions it can build.
- **The keys are handed over explicitly.** The release package puts them inside
  the installroot, but the repo definitions reference them as
  `file:///etc/pki/rpm-gpg/...`, and dnf resolves a `file://` URI against the
  *builder's* root. They are copied out so the URI resolves and imported into the
  installroot's rpmdb so packages are checked against them. Building Rocky 10 on
  a Rocky 9 builder is what found this, and it is the normal case.

AlmaLinux needs **two** packages — it splits repository definitions into
`almalinux-repos` — where Rocky ships them inside `rocky-release`. Installing only
the release package leaves an installroot with a distribution identity and no
repositories to install the distribution from.

### The A/B root across both initramfs harnesses

The two boot scripts — the overlay root and the LUKS bootstrap key — live at
`/usr/lib/ab/initramfs/` and are **shared**, not reimplemented per family:

| | initramfs-tools | dracut |
| --- | --- | --- |
| overlay root | `scripts/local-bottom` | `pre-pivot` hook, `90ab-overlay` |
| LUKS key | `scripts/init-premount` | `initqueue/settled`, `91ab-luks-key` |
| what installs it | `hooks/` | `module-setup.sh` |
| the mounted root | `$rootmnt` | `$NEWROOT` |

Only the last row reaches the scripts, and one line reconciles it. This is the
code that decides whether a machine's writable state exists at all; two copies
would diverge exactly once, on whichever family nobody had booted lately.

`initqueue/settled` for the LUKS key is a deliberate choice. `pre-trigger` is too
early — udev has not enumerated anything, so the `blkid` that finds the BOOT
partition finds nothing and every boot falls back to prompting. `pre-mount` is too
late — the root device, and so the unlock, is what the initqueue is already
waiting for. `settled` is where devices exist and the unlock has not yet given up.

The build **verifies** the hook is in the generated initramfs (`lsinitrd | grep
ab-overlay`) and fails if it is not: dracut does not error when a module it was
told to add contributed nothing, and an image missing that hook boots read-only
with no slot selection — which looks like a working image until you need to roll
back.

> **RPM images have not been booted on real hardware.** The modules are included
> and the initramfs is checked for them, but a hook that runs at the wrong moment
> is not something a build can detect. Both ways this can be wrong are
> recoverable rather than fatal: a mis-ordered LUKS hook falls back to a
> passphrase prompt, and a missing overlay boots the slot read-only — which is
> what `ab.state=off` does deliberately. Neither leaves a machine that will not
> start.

## Building for another architecture

Building an arm64 image (or imager) on an amd64 host runs arm64 binaries under
qemu, which the kernel only does once a `binfmt_misc` interpreter is registered.
Docker does not do that on its own, and without it the build dies inside a
Dockerfile `RUN` with a bare **`exec format error`** that says nothing about the
cause.

Register the interpreters **on the host, once**:

```bash
sudo apt install qemu-user-static binfmt-support
```

This is the recommended route and the default assumption. It persists across
reboots, and it needs no exception in the Docker socket proxy.

The alternative is to let each build register them itself, using the third-party
`tonistiigi/binfmt` image. That image runs **as host root**, and everything else
the socket proxy permits is built from this repository — so it is **off by
default** and has to be turned on deliberately:

```
BINFMT_ALLOW=1
BINFMT_IMAGE=tonistiigi/binfmt@sha256:<digest>   # pin it if you enable it
```

Note this registration only survives until the host reboots, which the package
route does not have to.

Either way the build now **stops** when no interpreter is available, and says
which of the two remedies to apply. It used to warn and carry on, so the real
failure arrived minutes later as `exec format error` inside a Dockerfile — a
message about the wrong thing entirely.

The check reads the **host's** registrations, which the builder-runner sees
through a read-only bind of `/proc/sys/fs/binfmt_misc` at `/host/binfmt_misc`.
That mount is not decoration: a container's own `/proc/sys/fs/binfmt_misc` is
empty whatever the host has registered, so reading it would refuse to build on a
host where `qemu-user-static` had already made the build work — reporting the
correct configuration as the broken one.

## Disk encryption and how it unlocks

Ticking **Encrypt the root filesystem (LUKS)** always enrols the passphrase you
give as a recovery slot. The **unlock method** decides what *else* can open the
disk, and the trade-off is always the same one: what has to be present at boot
for the machine to come up on its own.

| method | boots unattended | needs |
| --- | --- | --- |
| `keyfile` (default) | yes, anywhere | nothing — the key is in the initramfs |
| `tpm2` | yes, on that machine only | a TPM; enrolled on first boot |
| `tang` | yes, on that network | a reachable Tang server |
| `passphrase` | **no** | somebody at the console, every boot |

**`keyfile` protects the disk at rest, not the machine.** The initramfs is not
encrypted, so the key can be read off a drive by anyone holding the machine. It
defends against a disk pulled out of a rack, which is the common case; `tpm2`
defends against the machine itself walking, because the key is sealed to that
TPM and means nothing anywhere else.

**`tang` mounts the root filesystem `_netdev`**, so networking comes up before
the disk. Off that network the machine falls back to asking for the passphrase —
which is exactly the intended behaviour for a laptop, and a surprise for a server
in a rack whose Tang server is down.

**`passphrase` cannot reboot unattended**, including after an A/B update. That
makes it the wrong choice for anything the rollout engine manages.

TPM2 and Tang enrol on the machine's *first boot* rather than at build time, since
neither the TPM nor the network exists in the builder. Until that enrolment runs,
the passphrase is the only thing that opens the disk — so a machine that fails
first boot is recovered with it.

## Every build option, and where it is reachable

The build dialog exposes everything `build-image.sh` takes. That has not always
been true — options were added to the builder, modelled in the sidecar, typed in
the API client, and then not given a control, so the only way to reach them was
the API. **If you add a builder flag, add the control in the same change.**

| | flag | in the dialog |
| --- | --- | --- |
| distribution / release / arch | `--distro --suite --arch` | Distribution row |
| image name | `--name` | Image name |
| profile, desktop | `--profile --desktop` | Profile row |
| hostname, user, password | `--hostname --username --password` | Identity row |
| SSH key, key-only | `--ssh-pubkey --ssh-key-only` | Identity / Customization |
| extra packages | `--packages` | Extra packages |
| Secure Boot | `--secure-boot` | Profile row |
| encryption + unlock + Tang | `--encrypt --unlock --tang-url` | Encryption |
| image / root size, compression | `--image-size --root-size --compress` | Storage |
| writable-state model | `--state-model` | Writable state |
| per-slot upper layer | `--slot-private-upper` | Writable state |
| persist / slot-private / volatile / reset / keep / own | `--persist --slot-private --volatile --reset-on-update --keep-path --own-path` | Writable state |
| customization script | `--run-script` | Customization |

### Writable state

The root slot is read-only and an A/B update replaces it wholesale, so anything
written there is destroyed by the next update. This section is what survives
instead, and it is **fixed at build time**: a machine records the layout it was
imaged with and refuses a change at boot, because a layout that moved under a
running system is a system whose data is somewhere it is not looking.

- **model** — `overlay` puts one overlay over the whole root, which is what every
  image built before this existed gets. `paths` keeps the root read-only and makes
  only the enumerated paths writable.
- **per-slot upper layer** — each slot gets `upper-A`/`upper-B` rather than
  sharing one, so a configuration change made under A cannot follow you into B.
  Booting the other slot then recovers from a bad *edit*, not only a bad image —
  at the cost of the slots no longer sharing anything the overlay covers.
- **the path directives** — shared across slots, private to each slot, discarded
  on reboot, reset when the slot changes, held back from that reset, and owned by
  the image.

Paths must be **absolute**. The builder silently skips anything else, so the
dialog refuses to submit instead: a skipped directive is a setting that looks
accepted and is not in the image, and it is found on a machine.

### What does not survive an update

The root slot is replaced wholesale, so **anything installed onto a running
machine with `dnf` or `apt` is gone at the next update**. That is what A/B means,
not a defect in it — but it makes package installs on a live machine the wrong
place for anything the machine needs permanently.

| Path | Survives an update? |
|---|---|
| `/etc`, `/home`, `/var` and the rest of the overlay | yes — carried across |
| `/usr`, `/bin`, `/sbin`, `/lib`, `/boot` | **no** — replaced by the bundle |
| `/usr/local` | yes — the one carve-out |

The failure this produces is quiet and specific: the machine comes up on the new
slot with a *complete and correct* configuration in `/etc` and nothing to run it
with. Enrollment installs the overlay client (`openvpn` or `wireguard-tools`)
with the package manager, so every enrolled A/B machine dropped off the VPN on its
first update — config, certificate and key all present, binary and unit gone.

Images now carry the overlay client for whichever overlay the deployment uses, so
this is fixed going forward. Anything else you need permanently belongs **in the
image**: add it with `--packages`, or in `overlay.d` if it is a file rather than a
package.

## The netboot imager

Before any machine can be imaged there has to be something for it to boot. The
**netboot imager** is a kernel and initramfs the machine downloads over TFTP and
executes; it is what writes the image to the disk. Without one, PXE boots into
nothing, and the provisioning preflight refuses to start the server.

Build it from **Imaging → Images → Build netboot imager**. It is separate from an
OS image build because it takes no distribution, profile or credentials — only an
architecture.

It is **per architecture**, because the imager *is* a kernel: an amd64 imager
cannot boot an arm64 machine however it is served. Building an arm64 image is only
half of supporting arm64 and this is the other half. amd64 lives at the top of the
imager directory, where it always has, so a server predating arm64 support keeps
working untouched; other architectures get a subdirectory. A machine picks its own
at boot from iPXE's `${buildarch}`, so both can be present and neither interferes.

The Images tab shows which architectures have one, and says so plainly when none
do — rather than leaving it to be discovered from the provisioning preflight after
a network has been chosen and Start pressed.

## Provisioning: choosing the network to image on

**Imaging → Provisioning** is where a machine gets written in the first place. It
is one choice with everything else derived from it: **which interface** the
machines are on.

That choice is the whole point of the page. DHCP and TFTP are bound to the NIC
you pick and to nothing else, so they cannot reach — or disturb — any other
network this host is attached to. The interface list marks the NIC carrying the
default route as the **main LAN**, because a standalone DHCP server there
competes with the one the network already has, and that is somebody else's
outage rather than a message in this UI.

Picking an interface fills in the rest:

- **A NIC with no address** is the normal state of a dedicated provisioning port —
  nothing on that segment hands out addresses because this server is what will.
  It is offered a free subnet that does not overlap anything the host is already
  on, and the server assigns the address to the NIC when it starts. Runtime only:
  a reboot reverts it and starting again re-applies it, so the host's permanent
  network configuration is never touched.
- **A NIC that already has one** keeps it, and gets a lease range inside its own
  subnet — starting a quarter of the way in and stopping short of broadcast.

The page reads **status**, **preflight** and **configuration** in a single call
because they are individually useless: "running" means something different when
preflight is reporting that something else on the segment is already answering
DHCP. Preflight runs *before* the stack starts, because the failures here are the
quiet kind.

**Per-machine images** underneath assign a MAC its own image; anything not listed
gets the default. It is keyed on MAC rather than hostname because the machine has
no hostname yet — that is the point of the exercise.

Everything on this tab needs `Imaging.Provision`, which is deliberately separate
from `Imaging.Manage`: this is the part that puts a DHCP server on a network.

The **Overlay** tab beside it manages the files layered into an image at build
time — unit files, configs, scripts, certificates, small binaries.

- **Upload files**, or **upload a folder** and keep its tree beneath a path you
  choose. Uploads are byte-exact: they travel base64-encoded rather than as text,
  because a browser reading a file cannot know whether it holds UTF-8, and
  guessing wrong corrupts it silently rather than failing.
- **Create and edit** text files in place, **download** anything (including what
  the editor will not open), **rename or move**, and **change the mode**.

Two things about uploads are worth knowing before a folder of scripts does
nothing on a machine:

- **A browser cannot read a file's permissions.** Everything uploaded arrives with
  a default mode, so anything that has to *run* needs its mode set afterwards —
  `cp -a` preserves what is here, so an unexecutable script is an unexecutable
  script on every machine built from that image.
- **Empty directories are not uploaded**, because a browser does not report them.
  A directory that must exist needs a file in it.

Files are capped at 16 MiB (`MAX_OVERLAY_BYTES`) in each direction. Every path,
typed or uploaded, is resolved against the overlay root and refused if it lands
outside it — a folder upload names one path per file, and each is checked.

## The imaging run itself

Two more endpoints are machine-facing, and unauthenticated for a stronger reason
than the heartbeat: the imager runs from a netboot initramfs, on the
provisioning network precisely because it has not been provisioned yet. There is
no moment at which a credential could have been given to it.

| endpoint | who calls it | what it does |
| --- | --- | --- |
| `POST /api/imaging/report` | the imager, on each phase change | progress; held in memory, expires on its own |
| `POST /api/imaging/checkin` | the installed system, on first boot | records that the machine came back |

`checkin` is the one that closes the loop. Without it, "imaged" is the last thing
ever heard from a machine — and it is sent *before* the reboot, so a machine that
images perfectly and then fails to boot looks exactly like a success.

Note these paths are **unversioned**, and deliberately so. `/api/fleet/heartbeat`
is compiled into every agent on every image ever built, and the report URL is
derived inside a netboot initramfs from the address the image came from. Neither
can be changed by editing this repository: the change would have to reach
machines that only take an update by asking these endpoints for one. They are
the wire contract; the `/api/v1/imaging/...` routes are the convenience.

## Machines imaged before a fix

A build fix only reaches machines imaged after it. These four all produce the same
shape — the machine works, and cannot be *updated* — so they are collected here
rather than left in the changelog.

| Symptom on the machine | Cause | What to do |
|---|---|---|
| `rauc: error while loading shared libraries: libjson-glib-1.0.so.0` | rpm images built before the runtime libraries were kept: `dnf remove` of the build toolchain took `json-glib` with it | `dnf install -y json-glib`, then rebuild the image and the bundle |
| Update fails at 99% with `failed to start tar extract: Failed to execute child process "tar"` | rpm images built before `tar`/`gzip` were installed — a bundle's payload is a tar archive, and `dnf --installroot` never provided one | `dnf install -y tar gzip`, then rebuild the image and the bundle |
| Machine comes up after an update with no VPN, but its config and certificate are intact | the overlay client was installed by enrollment into `/usr`, which the update replaced | reinstall it (`dnf install -y openvpn`; `systemctl enable --now openvpn-client@fleet-overlay`) — permanent once re-imaged from a current image |
| OpenVPN tunnel works until the machine reboots, then never comes back | RHEL-family hosts enrolled before the client config was written where `openvpn-client@.service` reads it — the tunnel was a bare daemon enabled by nothing | re-enroll the host |

The first two are the ones to watch for, because the machine images and boots
perfectly and only fails the first time you try to update it — rauc is used for
nothing else.

## Configuration

| variable | meaning |
| --- | --- |
| `FLEET_ARTIFACT_DIR` | where the builder writes images and bundles, and the provisioning server serves them from (default `/output`) |
| `FLEET_CONTROL_URL` | the base URL **machines in the field** use to reach this server |
| `FLEET_AGENT_INTERVAL` | seconds between agent check-ins (default 300) |
| `FLEET_AGENT_TOKEN` | optional shared token required on the heartbeat endpoint |
| `FLEET_IMAGING_NUDGE` | `true` (default) to reach machines a rollout is waiting on; `false` to leave rollouts to poll |
| `FLEET_BUILDER_RUNNER_URL` | the builder-runner sidecar. Empty (default) = no build path at all |
| `FLEET_BUILDER_RUNNER_TOKEN` | shared secret sent as `X-Runner-Token`. Required whenever a runner URL is set |

`FLEET_CONTROL_URL` is the one that catches people. It is the address a machine
on the far side of the fleet can reach, which is routinely **not** the address
an operator's browser uses. Getting it wrong produces a bundle URL that fails on
the machine and nowhere else. Creating a rollout without it set is refused
rather than guessed, for that reason.

It is also the way out of the imaging-address trap: the URL burned into an image
at build time is the *provisioning server's*, which the machine stops being able
to reach the moment it is unracked. Every heartbeat reply carries the current
control URL, so the fleet can be re-pointed centrally.

`FLEET_AGENT_INTERVAL` is likewise sent in every reply, so re-pacing the whole
fleet does not mean touching a machine.

### Serving updates to machines that have left the imaging network

`FLEET_CONTROL_URL` tells machines where to find this server after they leave the
provisioning segment — it is returned in every heartbeat reply, so the fleet
re-points itself, and it is what a rollout builds its bundle URL from.

Setting it is not enough on its own. **Something has to serve `/bundles/` at that
address.** The provisioning listener is deliberately bound to `SERVER_IP` — the
imaging segment — so a machine that has been moved to the main network cannot
reach it, and a `CONTROL_URL` pointing anywhere else answers 404. The web UI's
port does not serve bundles either.

The provisioning container has a second listener for exactly this, off unless you
switch it on. In `server/.env`:

```sh
UPDATE_IP=10.10.0.208     # an address machines can reach after they are moved
UPDATE_PORT=80           # optional, defaults to 80
```

It serves `/bundles/`, `/health` and the heartbeat endpoint, and nothing else —
not the image library. It is skipped as a no-op if it would duplicate the imaging
listener. Then set the backend's `FLEET_CONTROL_URL` to that same address:

```sh
FLEET_CONTROL_URL=http://provisioning.example.com
```

Check it end to end before relying on it — a wrong value fails on the machine and
nowhere else:

```sh
curl -o /dev/null -w '%{http_code}\n' http://provisioning.example.com/bundles/<bundle>.raucb
```

> The two names are easy to confuse: the backend reads **`FLEET_CONTROL_URL`**,
> and the PXE server's own compose file uses **`CONTROL_URL`** for the value it
> writes into each machine's deploy marker at imaging time.

## The heartbeat endpoint

`POST /api/v1/imaging/heartbeat` is **unauthenticated by default**, and is the
only endpoint in this product that is. That is a deliberate decision and worth
stating plainly.

It is reached by machines this system provisioned and handed no credential to:
at the moment of a machine's first check-in it has just been imaged and has
nothing to authenticate with. What a caller can assert is bounded to a fixed set
of fields, and what it can *cause* is bounded to "install a bundle this server is
already offering, signed by a key the machine already trusts". A machine that
lies its way into a rollout therefore receives an update it would have been
given anyway.

Note what the heartbeat cannot set: groups, hold, label. Those are an operator's
word about a machine, never the machine's word about itself — otherwise anything
on the network could put itself into a rollout it was never targeted by.

Set `FLEET_AGENT_TOKEN` when the control plane is reachable from a network that
is not the provisioning one.

It answers `key=value` lines rather than JSON. The agent is a shell script on a
minimal image that ships neither `jq` nor `python3`; adding a JSON parser to
every machine in order to read six fields would be a strange price, and
hand-rolling one in `sed` to avoid it would be worse.

## Permissions

| permission | grants |
| --- | --- |
| `Imaging.View` | see images, bundles, rollouts, builds, and each machine's OS version |
| `Imaging.Build` | build images, bundles and the imager; manage the artefact library and build overlay |
| `Imaging.Manage` | run rollouts, pair and hold machines, nudge and install |
| `Imaging.Provision` | configure and run the PXE stack, and assign MACs to hostnames |

Three, because they are genuinely different acts. **Build** produces an artefact
and reaches no host at all; the person who maintains the image is often not the
person who runs the fleet, and splitting these is what makes "you may prepare the
release, someone else approves putting it on the fleet" expressible. **Manage**
is the act that changes what a machine boots. **Provision** reconfigures a
network segment, where the blast radius of a wrong DHCP range is every machine
on that switch, imaged or not.

`Imaging.Manage` means the ability to change what operating system a managed host
is running. It is a high-privilege grant and should be treated like
`Command.Run` — which is in fact how the reach half of it is enforced
underneath: every nudge and direct install goes through the same gateway,
certificate issuance and audit path as any other command, and a caller cannot act
on a host they cannot already see.

## Boundaries

- **Machines are not imaged from the web UI.** Imaging happens over PXE on the
  provisioning network, before a machine is a host at all. This shows what was
  imaged and takes over from the first boot.
- **The agent is not optional.** A fleet where every host is reachable could in
  principle run without one, but the agent is what makes a rollout correct when
  *this* server is down, and correctness that depends on a second system being up
  is not correctness.
- **The builder still needs privileged containers**, and the PXE server still
  needs to sit on the provisioning segment. Being one product does not make those
  go away — it means they are one deployment's concerns rather than two products',
  and that the privilege is contained deliberately rather than by accident of
  which repository it lived in.
- **There is no Kubernetes manifest for the builder, on purpose.** Everything
  else here ships one. Mounting a node's Docker socket into a pod and running it
  privileged is a materially different proposition in a shared cluster than it is
  on a single Docker host — it is node-level root, available to anything that can
  reach the pod, and it does not survive a containerd-only node at all. Doing it
  properly on Kubernetes means a different build strategy (BuildKit or Kaniko in
  a pod, with its own cache and registry story), not a translated compose file.
  Until that exists, run the builder on a Docker host and point the cluster at
  the artefacts it produces; `FLEET_BUILDER_RUNNER_URL` is a URL precisely so the
  builder does not have to live where the backend does.

  The rest of imaging — rollouts, machines, heartbeats, the artefact library —
  works on Kubernetes unchanged. Only building is affected.

## Backups

The database backup covers machines, rollouts, users, sessions, tokens and the
audit log, like everything else here. It cannot cover two things that are files:

- **`output/rauc-keys/`** — the update signing key. Losing it means no machine
  already deployed can ever be updated again. Not "until we re-key": ever,
  because those machines verify against a certificate baked into their own image.
  Leaking it means anyone can sign an update every one of them will install.
- **`server/.env` and the MAC assignments** — the provisioning stack's network
  configuration and which machine gets which hostname.

`scripts/imaging/imaging-keys-backup.sh` archives exactly those. Built images and
bundles are deliberately *not* in it: they are large, and they are reproducible
from the builder given the same inputs — unlike the key, which is reproducible
from nothing.

## A note on names on disk

Machines already in the field carry paths from this code's earlier life as a
separate project: `/usr/lib/flipside/version`, `ab-agent`, `ab-update`. They are
compiled into every image that has already been built, so they are kept. A
rename would make this server unable to read a version off any machine imaged
before it, for a cosmetic gain.
