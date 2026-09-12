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

## Updating everything at once

The warning above the list has an **Update all** button: one rollout covering
every image with something available, rather than one rollout per image.

That distinction matters. Ten separate rollouts each pace themselves, so a canary
of one would mean ten hosts taking an unproven update at the same moment — which
is not a canary. One rollout paces the whole operation, and it paces by **host**:
a host takes every update that applies to it, then the next host follows. So a
host is either current or it is not, rather than half-updated across the fleet.

An image a given host does not run is not a failure — a rollout over ten images
rarely has all ten everywhere. A host that turns out to be running none of them by
the time its turn comes is marked **skipped**, not verified: it took no updates,
and recording it as verified would claim one that never happened.

## What can and cannot be updated

It depends on the kind of update, and most of the time you need nothing at all.

**A rebuild — the same tag republished** — needs no compose file changed, so
Provenance does not need to hold one. Every compose-managed container records
which project and service it is and where that project lives, so the update is:
go to that directory, pull that service, bring that service back up. Nothing to
adopt.

**A version bump** — `1.24` to `1.27` — is written *into* the compose file, so
something has to edit it. If no stack owns that file yet, Provenance **adopts the
host's own**: it reads the file, records it as a stack, and applies the change as
a normal revision. From then on the edit has an author, a note and a rollback,
which an edit made to a file nobody owns would not.

Adoption refuses rather than guesses in three cases:

- the compose file is called something other than `docker-compose.yml`. The
  deploy writes that name, so adopting would leave the original **and** put a
  second compose file beside it, and compose would then use whichever its own
  rules prefer. Rename it, or add it as a stack yourself.
- the file does not name the image being updated — then the project at that path
  is not the one this container came from, and rewriting it would edit somebody
  else's stack.
- the recorded directory is not there, which usually means the project was
  deployed from somewhere else.

**If your compose files are deployed from somewhere else** — a git repository, an
rsync target — be aware that adopting one gives you two sources of truth for the
same file, and the next deploy from that source will overwrite what Provenance
wrote. Delete the stack afterwards if you want that host left alone; rebuilds
still work without one.

Two cases still report rather than guess:

- a container started with plain `docker run`, whose run arguments were never
  recorded. Recreating it would mean inventing the parts nobody told us, and one
  that comes back missing a volume is worse than one never touched.
- a compose project whose recorded directory holds no readable project — usually
  one deployed from inside a container, where the path is that container's. Acting
  blind could apply to a *different* project that happens to live at the same path.

Where a stack **is** adopted, it wins: that is the definition of record, and the
one with a history and a rollback.

### A rollout touches only the service it is updating

A stack **deploy** — the button on the Stacks tab — brings up the whole compose
project, because that is what deploying a file means.

A **rollout** is about one image, so it pulls and recreates only the service that
runs it. On a host where one compose project holds a model server, a vector
database and six other things, updating `curl` restarts `curl`. It also does not
pass `--remove-orphans`: removing containers the file no longer defines is a
whole-project decision, and making it as a side effect of updating one image
would delete things nobody mentioned.

If the compose service cannot be established, the whole project is brought up
instead — a deploy that touches more than it needed is recoverable, and one that
touches nothing because a name was guessed wrong is an update reported as applied
that never happened.

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

## Provenance's own containers

The containers that make up Provenance are **shown but never offered for update**.
They carry a **upgraded by bundle** badge, and "Update all" skips them.

This is not only its own images — those are built locally and are excluded
anyway, having no registry digest. It is the third-party containers the
application is *made of*: the PostgreSQL holding its data, the Redis holding its
sessions, the guacd carrying its remote-desktop connections. Those are ordinary
registry images and would otherwise be offered like any other.

They are excluded because upgrading this application is not the same operation as
pulling a newer image. A bundle verifies a signature, takes a pre-upgrade database
backup, applies migrations in order, keeps a `:rollback` anchor, and restarts the
stack in a sequence that survives the backend replacing itself. A container
rollout does none of that — and could not even report what it did, because the
backend running the rollout is what gets restarted.

Upgrade them from **Settings → Updates** instead.

They stay visible on purpose. What the instance is running, and what is wrong
with those images, is exactly what an operator should be able to see — the
vulnerability scanning of postgres or guacd is some of the most useful this does.
Only *updating* them this way is refused.

Recognised by compose project, defaulting to `fleet-terminal`. A deployment that
renamed its compose project should set `containers.selfProject` to match, or its
own database would be offered for update.

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
