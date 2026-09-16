# Host topology

Provenance models hosts as a flat set. On a real estate they stand on each
other, and the gap between those two facts has broken this fleet twice.

## The failure this exists to prevent

An "Update apt packages" run covered a host group that contained both a set of
guests and the NAS serving their root filesystems over NFS. The NAS rebooted
mid-run. Four guests failed with:

```
Timeout (12s) waiting for privilege escalation prompt
```

That is `sudo` hanging, because the filesystem it needed had gone away. The
guests answered SSH throughout — the network was fine, only I/O was stalled — so
the run recorded `unreachable=0` and the failure presented as a sudo problem on
four unrelated machines. Nothing in the output pointed at storage, because
nothing in the system knew storage was involved.

The workaround is a hand-tuned clock: guests at 03:00, NAS at 03:45, jump host
at 04:00, hypervisor at 04:30, with a ten-minute deferred reboot buying margin.
It works. It also contains a race that was accepted deliberately — the guest run
is bounded by a ninety-minute timeout, so it *can* still be running when the NAS
window opens. Ordering by arithmetic on wall-clock times is the only tool
available when the system cannot be told what depends on what.

## What is being added

One fact: **which hosts stand on which**, as a typed edge.

`host_dependencies` records that `host_id` depends on `depends_on_host_id`, with
a `kind`:

| kind | meaning | what happens when it goes down |
|---|---|---|
| `hypervisor` | runs this host as a guest | the host stops entirely; no degraded mode |
| `storage` | serves this host's disks | the host keeps answering the network while every write blocks |
| `network` | routes or resolves for this host | varies; usually looks like unreachability |
| `other` | an application-level dependency | recorded for humans |

The `storage` case earns its own kind precisely because it is the one that does
not look like what it is.

Direction is "dependent first" because that is how every question is asked. *What
does this host stand on* is the primary key; *what stands on this host* is the
reverse index.

## What is deliberately not here yet

The table is the foundation, not the feature. Two things will read it, and
neither can be built on a schema that cannot express the relationship:

**Schedule ordering** — now built. A playbook schedule can be set to *Order by
dependencies*, which runs its hosts in waves instead of all at once: dependents
first, whatever carries them last. Storage is never rebooted out from under
guests that are still patching, because the guests' wave has to finish first.

Each wave is its own run, so the history shows what happened at each stage rather
than one row that hides the sequence. **A wave that does not complete stops the
rest** — if patching the guests went wrong, rebooting the NAS underneath them is
the last thing that should happen next.

Off by default. It turns one run into several, and on a fleet that has recorded
no topology that is identical behaviour with more rows — so a selection that
produces a single wave falls through to an ordinary run.

This replaces ordering by clock arithmetic. Hand-timing means choosing a gap and
hoping the earlier run fits inside it, which is a race: a guest run bounded by a
ninety-minute timeout can still be going when the storage window opens.

**Blast-radius preview.** Before an action that disrupts a host, say what it will
actually reach:

> This targets 15 hosts. 13 of them have their disks served by `nas`, which is
> also in this batch.

That is the shape of an outage that already happened here, where the control
plane was inside the batch it was operating on.

## Why it is tenant-scoped rather than allowlisted

Child tables reachable only through an RLS-scoped parent are allowlisted out of
row-level security, because a second `tenant_id` would be a second place for two
copies to disagree. This table is not one of those. A row names **two** hosts, so
it is the one place a cross-tenant edge could be written, and a dependency graph
that can be poisoned across a tenant boundary would let one customer's topology
withhold another customer's rollout. It carries its own `tenant_id` and the
standard isolation policy.

## Recording an edge

Topology is **asserted, not collected**. A host cannot report that it is a guest
of a particular hypervisor, or that its disks arrive over NFS from a particular
NAS — those are facts about the estate, not about the machine.

So it is entered by hand, on the host's detail dialog under **Dependencies**,
which shows both directions: what this host *stands on*, and what it *carries*.
The empty state says the consequence rather than just "none", because a host with
nothing recorded is not a host with no dependencies — it is one nothing can warn
about yet.

`GET`, `POST` and `DELETE` on `/api/v1/hosts/{id}/dependencies`. Reading is
`Host.View`; writing is `Host.Edit`, because an edge changes what a bulk action
warns about and what an ordered schedule does. It is a property of the host, not
a note about it.

## Cycles

A host cannot depend on itself; that is a `CHECK` constraint.

Longer cycles are refused in code, and the rejection **names the path it found**:

```
that would make a loop: nas → hypervisor → guest-a → nas
```

Saying only "that would create a cycle" sends an operator looking for it by hand
across a graph they cannot see.

The check is a recursive walk from the proposed target, asking whether it can
already reach the dependent — run **inside the same transaction as the insert**,
so two operators adding opposite halves of a loop at the same moment cannot both
pass their check and both commit. Depth is bounded at 32: a malformed graph, one
predating this check or written directly to the table, must not turn an insert
into a runaway query.

A constraint cannot express reachability, and a trigger that tried would run that
walk on every insert to prevent something an operator does by mistake roughly
never.

## Where the preview appears, and where it deliberately does not

It is shown before anything that can **disrupt** a host, because that is what
propagates along an edge:

- deleting hosts (especially with teardown)
- running a playbook for real — not a dry run, which changes nothing
- running an ad-hoc shell command, the bluntest bulk action there is
- retiring a superseded login account, where losing access to a host that carries
  fourteen others is not the same as losing access to a leaf

It is **not** shown for refreshing facts, editing tags, or setting a maintenance
window. Those change nothing on the host, so nothing propagates, and a warning
that appears when it does not apply is how people learn to skip the one that
does.

A run targeting a **group** is previewed too, resolved from group membership. A
fleet upgrade is aimed at a group, so leaving that unpreviewed would miss the
case the preview exists for.
