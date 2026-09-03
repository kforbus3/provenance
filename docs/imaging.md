# Imaging and OS updates

Blackfriars manages a machine's whole life. Most of this product manages
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

Rollouts target **host groups** — the same groups access control and policy use.
Not a second set of groups naming the same machines. Keeping two in step is work
nobody would have done, and a stale copy of "which machines are production" is
how the wrong fleet gets an update.

The consequence worth knowing: a machine reaches a rollout through its pairing.
An unpaired machine is in no group and so is targeted only by *the whole fleet*.

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

## Configuration

| variable | meaning |
| --- | --- |
| `FLEET_ARTIFACT_DIR` | where the builder writes images and bundles, and the provisioning server serves them from (default `/output`) |
| `FLEET_CONTROL_URL` | the base URL **machines in the field** use to reach this server |
| `FLEET_AGENT_INTERVAL` | seconds between agent check-ins (default 300) |
| `FLEET_AGENT_TOKEN` | optional shared token required on the heartbeat endpoint |
| `FLEET_IMAGING_NUDGE` | `true` (default) to reach machines a rollout is waiting on; `false` to leave rollouts to poll |

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
| `Imaging.View` | see images, bundles, rollouts, and each machine's OS version |
| `Imaging.Manage` | start and steer rollouts, pair and hold machines, nudge and install |

`Imaging.Manage` means the ability to change what operating system a managed
host is running. It is a high-privilege grant and should be treated like
`Command.Run` — which is in fact how the reach half of it is enforced
underneath: every nudge and direct install goes through the same gateway,
certificate issuance and audit path as any other command, and a caller cannot
act on a host they cannot already see.

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
  go away — it means they are one deployment's concerns rather than two products'.

## A note on names on disk

Machines already in the field carry paths from this code's earlier life as a
separate project: `/usr/lib/flipside/version`, `ab-agent`, `ab-update`. They are
compiled into every image that has already been built, so they are kept. A
rename would make this server unable to read a version off any machine imaged
before it, for a cosmetic gain.
