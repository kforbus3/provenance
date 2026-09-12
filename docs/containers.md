# Containers

Provenance sees what containers each host runs, scans those images for known
vulnerabilities, holds the compose files that define them, and rolls image
updates out in stages.

That last part replaces a setup a lot of people have: a renovate bot watching
registries, a git repository holding compose files, and CI that deploys them.
This does the same job with one source of truth and one place to decide, because
the split version has a specific failure — the bot opens a merge request, nobody
reads it, and six months later nothing has been updated and everybody believes
it has.

## What you see

The **Containers** screen has three tabs.

**Stacks** is what each host *should* be running. Provenance holds the compose
file and writes a rendered copy to the host, so a stack keeps running when
Provenance does not — you lose the ability to change it, not to run it. Every
row shows two numbers: `revision` is what should be deployed, `deployedRevision`
is what the host last confirmed. A tool showing only the first would report
success for a deploy that never landed.

**Updates** is what the registries say is available for the images your hosts
are running.

**Rollouts** is what is being applied right now, and what happened.

## Two kinds of update

An image can be out of date in two different ways, and they need different
answers:

| | what it means |
|---|---|
| **a newer tag exists** | `nginx:1.24` is running; `1.27` has been published |
| **the tag moved** | `1.0.0` still, but rebuilt on a patched base image |

The second is the one a version comparison alone can never see. A base-image
security rebuild republishes the same version number, so a tool that compares
only version strings tells you that you are current while you run months-old
bytes. Provenance reports both, separately, and never collapses them into one
badge. On the Updates tab they read as **"1.27 available"** and **"rebuilt"**.

This is why every container's **digest** is recorded, not just its tag. A tag is
a label that moves; the digest is what is actually running.

## The ordering refuses to guess

Two tags are compared only when their prefix, their suffix and their component
count all match. So:

- `15-alpine` is never offered `16-bookworm` — a different base image is not an
  upgrade
- `v2` is never ordered against `release-3` — those are two numbering schemes,
  not two versions
- `1.2` is never ordered against `1.2.3`

When tags cannot be ordered, the row reads **"cannot compare"** and says why. It
does **not** read "up to date". Silence there would be read as an answer, and it
would be the wrong one.

## How registries are asked

Directly over the registry HTTP API — no Docker daemon and no credential helper.
An anonymous bearer token is fetched per repository and cached for the pass, and
manifests are fetched with `HEAD`, so no manifest body is ever transferred.

Rate limits are the binding constraint. Docker Hub counts manifest requests per
IP, shared across every image your whole fleet runs, so:

- a pass checks at most 40 images
- a result stays good for 12 hours
- only the leader instance checks, in a multi-instance deployment

**Images built on the host are not asked about at all.** Docker records a
repository digest only for images it *pulled*, so a locally built one has none —
including this product's own containers. Asking a registry about such a name
resolves it to Docker Hub, where the repository does not exist and the answer is
a 401, which would read as "needs credentials" and send you to configure
credentials that cannot help. Those rows say **built locally** instead.

A registry that will not answer — private, offline, rate limited — is recorded
against *that image* and the pass continues. One private registry with no
credentials must not stop the fleet learning about everything else. The row says
which it was, because "needs credentials", "no such tag" and "rate limited" have
different answers.

**"Check registries now"** on the Updates tab runs a pass immediately. It re-asks
the registries about images **already discovered** — it does not reach out to your
hosts, so it will not make a host that has not been swept yet appear.

Images are discovered by the monitor sweep as it reaches each host, on a ten-minute
cadence of their own. Containers change whenever somebody deploys, so they are
deliberately not aged like a kernel version, which changes at a reboot. A fleet
that has just upgraded therefore fills in over the following few sweeps rather
than all at once.

## Rolling an update out

Press **Roll out** on an update. You choose:

- **canary hosts** — proved first, alone. The rest waits on them.
- **soak** — how long the canaries must run before the fleet follows
- **batch size** — how many hosts move at once after the soak
- **failure budget** — stop after this many failures. **0 means no limit.**
- **maintenance window** — optional, in server-local time

The defaults are cautious rather than fast: one canary, a fifteen-minute soak,
and a halt on the first failure. The cost of being slow is waiting. The cost of
being fast is every host on a broken image at the same moment.

These are the same pacing rules image rollouts obey — literally the same code,
so the two cannot drift.

The hosts are chosen when the rollout is created, not rediscovered as it runs. A
rollout whose membership changed underneath it could never be complete, and a
host that started running the image after you approved the change was never part
of what you approved.

### What "verified" means

A host counts as done only when it is **running the target image** — not when
the deploy command exits zero.

That distinction is the point of the feature. When a tag has moved,
`docker compose up -d` finds the tag already present locally, starts the old
bytes again, and exits zero. A rollout counting the exit code would march that
no-op across the whole fleet, report every host as updated, and leave every host
on the vulnerable image.

So an update deploy pulls first, and every host is read back afterwards and
compared against the digest the rollout targets. A host on the right tag but the
wrong bytes **fails** — that is exactly the situation the rollout was started to
fix.

### Pausing, resuming, cancelling

- **Pause** stops new hosts starting. Hosts mid-deploy finish.
- **Resume** carries on. Resuming a *halted* rollout forgives the failures that
  stopped it, so it does not immediately re-halt on the same ones.
- **Cancel** stops for good. Hosts already updated stay updated.

A rollout with an unlimited failure budget reaches **completed** even if every
host failed — that is genuinely the state it is in, so the row shows
`completed · 3 failed` rather than a green tick.

## What can and cannot be updated

Only hosts whose compose file Provenance manages. Updating means rewriting the
image reference and bringing the stack back up, and Provenance can only do that
for a file it holds.

A host running the image outside a managed stack is **reported**, not guessed
at — the rollout marks it failed with *"no Provenance-managed stack on this host
names nginx:1.24 — adopt its compose file to make it updatable"*. Recreating a
container whose run configuration was never recorded would mean inventing the
parts nobody told us, and a container that comes back missing a volume or a
network is worse than one that was never touched.

To make such a host updatable, add its compose file as a stack on the **Stacks**
tab.

### How the compose file is edited

Line by line, not parsed and re-emitted. A YAML round-trip drops your comments,
renormalises your quoting and reorders your keys — which buries a one-line tag
bump in a diff nobody can review, attached to a change you are being asked to
approve. Provenance changes the bytes it was asked to change and nothing else.

Only exact repository *and* tag matches move. Rewriting `nginx:1.24` leaves
alone:

- `nginx-extras:1.24` — a different repository
- `ghcr.io/nginx:1.24` — a different registry
- `nginx:1.24-alpine` — a different variant
- `registry.example.com:5000/app:1.4` — where the `:5000` is a port, not a tag

A digest pin is dropped rather than carried onto the new tag, where it would
name the old bytes.

Every rewrite is a normal stack revision, visible in the stack's history and
rollback-able like any other.

## Vulnerability scanning

Container images are scanned with the same grype sidecar the host scans use, on
a daily pass.

Scanning is keyed by **digest** and deduplicated across the fleet: the same
image running on twenty hosts is fetched and scanned once, because the answer is
identical and scanning it per host would multiply bandwidth, disk and registry
rate-limit pressure for nothing.

A digest's contents never change, so a result is re-scanned when the
*vulnerability database* moves — which is what turns a clean image into a
vulnerable one without anybody touching the image.

An image that could not be scanned records *why*. An image that could not be
pulled must never read as an image with no vulnerabilities.

## Permissions

| action | permission |
|---|---|
| see stacks, updates and rollouts | `Host.View` |
| add or edit a stack definition | `Host.Edit` |
| deploy, roll back, start or control a rollout | `Command.Run` |
| see and trigger update checks and image scans | `Host.Scan` |

Deploying needs `Command.Run` because writing a file to a host and bringing
containers up *is* running something on that host — it would be strange for the
permission governing one command not to govern the one that runs several.
