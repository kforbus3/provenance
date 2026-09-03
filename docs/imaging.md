# Imaging and OS updates (Flipside)

Moorgate manages machines that already exist. [Flipside](https://github.com/kforbus3/flipside)
builds the operating system they run and puts it on their disks: A/B image
builder, PXE imaging server, signed RAUC update bundles, and a control plane
that rolls those bundles out in stages.

This is the two of them as one product. Moorgate is the pane of glass and the
transport; Flipside is the image and update authority. Neither absorbs the
other, and there is exactly one place to look.

## Why they need each other

Flipside's control plane is a **pull**: each machine runs an agent that checks
in every five minutes and is told whether to install anything. That design is
forced by how machines are provisioned — a machine is imaged on a private
switch and then moved to wherever it lives, and from that moment the imaging
server does not know its address and usually cannot route to it. Flipside cannot
push, so it does not try.

Moorgate has exactly what Flipside lacks. Every enrolled host is reachable
through the jump host over the overlay, and `Command.Run` already executes on
them. So:

- **A rollout that would take hours of polling finishes in minutes.** Moorgate
  nudges the machines a rollout is waiting on, and they check in at once.
- **Machines that can never reach Flipside can still be updated.** Moorgate
  reaches *them*, installs directly, and reports what it saw.

And in the other direction, Flipside gives Moorgate the half of a machine's life
it never had: what image it was built from, what is inside that image, and what
version it is running now.

## What decides what

**Flipside owns the rollout.** Canary, soak, batch size, failure budget,
maintenance window, and the rule that a machine counts as updated only when it
comes back on the new version and healthy — all of that stays in Flipside, which
is where it is implemented and tested. Moorgate does not re-decide any of it.

**Moorgate owns reach, identity and the record.** Who may start a rollout, which
hosts they may touch, what gets written to the audit log, who is notified when a
rollout halts — Moorgate's, as for everything else it manages.

The rule of thumb: if a second copy of a decision would have to be kept in step,
it does not get made twice. Moorgate makes machines *ask sooner*; it does not
decide what the answer should be.

## The three ways a machine gets an update

Chosen per host, best first.

### 1. Nudge (the normal case)

The host runs the Flipside agent and can reach Flipside. Moorgate runs

```
ab-agent --now
```

over the SSH gateway. The agent checks in immediately, Flipside applies the
rollout's rules exactly as it would have five minutes later, and the machine
installs if it is that machine's turn.

Nothing about the rollout changes — this only removes the waiting. If the nudge
fails (host asleep, overlay blip, sshd busy) the agent polls on its own timer
anyway, so a failed nudge costs latency and nothing else.

### 2. Direct install

The host cannot reach Flipside at all — a site with no route back, or a machine
imaged before the agent existed. Moorgate runs

```
ab-update <bundle URL>
```

and the bundle is fetched through the overlay the host already trusts. RAUC
verifies the signature against the certificate inside the image exactly as it
would on any other path; nothing about the trust chain is different because
Moorgate carried it.

### 3. Attested report

A machine updated by (2) still cannot tell Flipside what happened, so the
rollout would never see it finish. Moorgate reports on its behalf — but only
about things it has *observed on the host itself*: the version file the bundle's
install hook wrote, and `systemctl is-system-running`.

That is deliberately not the machine's self-report relayed onward. It is
Moorgate saying "I looked, and this is what is there", which is better evidence
than a machine's own word, and Flipside records which operator identity said it.
The endpoint requires an operator token and is separate from the machine
heartbeat, so the two can never be confused.

## Matching hosts to machines

A Flipside machine is identified by what the imager saw — usually a MAC address.
A Moorgate host is a hostname and an overlay address. They are matched, in
order:

1. an explicit link, recorded once and thereafter authoritative;
2. a MAC in the host's inventory that equals the machine's id;
3. the hostname the agent reports equal to the host's hostname.

Only the first survives a machine being renamed or re-imaged, which is why
matching by 2 or 3 offers to record a link rather than re-deriving it every
time. Unmatched machines are still shown — a machine Flipside knows about and
Moorgate does not is usually one that was imaged and never enrolled, which is
worth seeing rather than hiding.

## Configuration

| variable | meaning |
| --- | --- |
| `FLEET_FLIPSIDE_URL` | Flipside's API base, e.g. `https://flipside.example.com` |
| `FLEET_FLIPSIDE_TOKEN` | a Flipside API token (`flt_…`) with the **operator** role |
| `FLEET_FLIPSIDE_NUDGE` | `true` (default) to nudge waiting machines; `false` to leave rollouts to poll |

With no URL set the subsystem is entirely inert: no pages, no polling, no
routes that do anything. Moorgate runs exactly as it did before.

Give the token the operator role, not admin. Operator is enough to build images,
build bundles and run rollouts; admin would add Flipside's own user and secret
management, which Moorgate has no business reaching through a shared token.

## Permissions

| permission | grants |
| --- | --- |
| `Imaging.View` | see images, bundles, rollouts, and each host's OS version |
| `Imaging.Manage` | build images and bundles, start and steer rollouts, nudge and update hosts |

`Imaging.Manage` implies the ability to change what an operating system on a
managed host is running. It is a high-privilege grant and should be treated like
`Command.Run`, which is in fact how it is enforced underneath — every direct
install and nudge goes through the same gateway, policy and audit path as any
other command.

## What this does not do

- **It does not make Flipside optional.** Flipside stays a separate deployment,
  because the image builder needs privileged containers and the PXE server needs
  to sit on the provisioning segment. Moorgate drives it; it does not contain it.
- **It does not image machines from Moorgate.** Imaging happens over PXE on the
  provisioning network, before a machine is a Moorgate host at all. Moorgate
  shows what was imaged and takes over from the first boot.
- **It does not replace the agent.** A fleet where Moorgate manages every host
  could in principle run without one, but the agent is what makes a rollout
  correct when Moorgate is down, and correctness that depends on a second system
  being up is not correctness.
