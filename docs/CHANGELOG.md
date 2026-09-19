# Changelog

Notable changes to Provenance, newest first. Dates are release dates. Database
schema migrations apply automatically on startup; deploy notes call out anything else.

---

## Unreleased

**Forwarded audit events carry a stable hostname.** The syslog HOSTNAME field was
`os.Hostname()`, which inside a container is the container ID and changes on every
recreate — so a collector that groups by host would collect a new meaningless host per
deployment, with the audit trail scattered across all of them. It is now
`PROV_PUBLIC_URL`'s hostname, the name people already call the install by, falling back
to the OS hostname where no public URL is set.

Worth knowing alongside it: enrolling your hosts in log collection does **not** cover
Provenance's own audit trail. Its containers log to Docker's logging driver, not to the
host's syslog, so the trail reaches a collector only when audit forwarding is switched
on — see [Operations](operations.md#audit-forwarding-siem).


## v1.8.0 — 2026-09-19

**Provenance reads the logs and the mount tables it was already collecting.** Three
of the four changes here have the same shape: Provenance held a fact and never
volunteered it, so the operator had to go and ask. A host that starts logging errors
now says so on the dashboard; a host that mounts its disks from another machine now
corroborates — or contradicts — the dependency graph somebody typed in by hand; and
enrolling a fleet into log collection is a bulk action rather than a trip to
Automation.

**The dependency graph is now checked against the machines.** Host topology is
entered by hand, and a hand-entered graph that nothing ever checks drifts in
silence — a host gains an NFS mount, nobody records it, and the blast-radius
preview and wave ordering built on that graph state something false with complete
confidence. That is worse than having no graph, because a warning that has been
right nine times is believed the tenth.

Part of it was collectable all along, and the documentation's claim that none of it
was is what kept this unbuilt: `/proc/self/mounts` names the server a filesystem
arrives from, in plain text, without root. The monitor now reads it in the same
sweep as everything else, along with `systemd-detect-virt`, and the host's
**Dependencies** section marks a recorded edge **seen on the host** (hover for the
mount), offers an observed dependency nobody has recorded with a **Record it**
button, and names a storage server that is not an enrolled host as the one gap
careful data entry cannot close.

Nothing is written automatically: an observation is evidence, an edge is an
assertion about the estate, and a person makes it. Accepting a suggestion keeps the
evidence as the edge's note. A recorded edge with **no** observation is deliberately
*not* flagged as wrong — a guest's disks reach it through the hypervisor's mount,
not its own, so almost every true `storage` edge in a virtualised estate is
invisible from the dependent, and flagging those would bury a correct graph in
false doubt. The hypervisor guess is offered only when the fleet has exactly one:
a coin toss between two would be recorded as a fact and read back as one by
something deciding what to reboot.

**The dashboard reports a host that has started logging errors.** Provenance was
collecting every host's logs and never mentioning them unless someone went to the
Logs page and searched. A host is now surfaced under **Needs attention** — and in
the digest — when it logs 30+ errors an hour *and* at least 4x its own average over
the previous week. Both halves bind: the ratio alone fires on a machine that went
from one error a day to six, and the floor alone fires forever on a machine that
always logs loudly, which is how a dashboard teaches people to ignore it. The
comparison is per host, against itself, so a noisy build server stays quiet and a
database that normally logs nothing is reported at five. Senders with no matching
host (a switch, a firewall) are reported to super-admins by the name they use in
their logs. One aggregation query covers both windows, and a collector that is down
or empty costs the dashboard nothing but these cards.

**The fleet-health digest is on by default**, daily at 08:00. It was off until
someone found the setting, which meant most installs never got it and the insight
engine went unread. Nobody is newly emailed by this: delivery still depends on
routing the `fleet.digest` event to a channel, so an install with no channel
configured sends nothing — and an operator who had turned the digest off stays off.

**Hosts → Bulk actions → Send logs to collector.** Enrolling a machine into log
collection meant going to Automation, finding the right playbook, and picking hosts
there. Select hosts on the **Hosts** page instead and it runs the imported
enrolment playbook over the selection as one ordinary playbook run. It runs *your*
playbook rather than a copy embedded in Provenance — a second copy would drift from
the one that gets fixed when a new host type turns out to have no rsyslog, and you
would have no way to tell which had just run on your fleet. RouterOS devices in the
selection are named and skipped rather than failed, and an install with nothing
imported is told which file to import.

**The package count on the Images tab works, and now shows the packages.**
Clicking it answered `missing access token`: it was a link straight at
`/api/v1/imaging/images/<name>/sbom`, and a browser navigation carries no
Authorization header — the code assumed "the cookie carries the auth", but
Provenance's session cookies are scoped to `/api/v1/auth` and never reach that
route. The count now opens a filterable list of package names and versions, which
is the question a click there is asking. **The Download button had the same defect
and answered 401**; it authenticates from a short-lived token in the URL like the
backup download, because a multi-gigabyte image should stream rather than be
buffered in the browser — and that download is now audited with the actor's name
rather than anonymously.


**Every data-backed picker can be typed into.** Host, group, image, bundle, user
and credential selectors were plain menus, so choosing one host out of nineteen
meant opening a list and hunting — and it got worse with every machine added. They
are now typeahead pickers: type three characters and press Enter. Fixed
enumerations (severity, protocol, day of week) are deliberately unchanged, because
filtering a four-item list you can read at a glance is slower, not faster.
Converted: Logs (host), Stacks (host), Certificates (user, host), Ad-hoc command
(group), Command policy (group), Imaging (bundle ×2, group, image).


**`make redeploy-single` now rebuilds every service it should.** It rebuilt
backend, frontend, grype-scanner, ansible-runner and prov-updater — but not
builder-runner or dockerproxy, both of which are built from this repo. The failure
mode is the worst kind: the fix is committed, the deploy reports success, and the
old code keeps running because nothing rebuilt it. A sidecar-cleanup fix was
"deployed" to a container that had been up for 27 hours. A test now compares the
compose file's `build:` services against the recipe, so a service added later
cannot be forgotten.


**Deleting an image now takes its SBOMs with it.** `delete_image` removed a
hardcoded `.sha256` and `.json`; the SBOM step had since started writing
`.cdx.json`, `.spdx.json` and `.packages.tsv`, and nothing updated that list. Four
deleted builds had left their SBOMs in the output directory — nothing failed, so
nothing said so. Sidecars are now found by prefix, with the `.` boundary keeping a
sibling build (`foo-2.img.zst`) safe.

**The vulnerability scanner no longer leaks its scratch space.** A scan that
exceeds its timeout is SIGKILLed, so stereoscope's deferred cleanup never runs and
the image layers it extracted stay on disk. That reached **6.6 GB** inside the
scanner container here, with nothing in any log pointing at it. Each scan now gets
its own `TMPDIR` removed in a `finally` — which is what makes a killed scan clean
up — and each run first sweeps trees older than twice the scan timeout, so
anything an earlier version left is reclaimed without waiting for a restart.


**"Open log console" lands on a dashboard with data in it.** It opened
Dashboards' home screen, in the viewer's own private tenant, which is empty — a
console that signs you in and then asks you to choose an index pattern is a tool
you have to assemble before it answers anything. The console is now pinned to the
shared (global) tenant and opens the *Fleet logs — overview* dashboard Aldgate
ships with: volume over time, severity mix, noisiest hosts, error sources, and
saved searches for errors, authentication and SNMP traps.

**A host that answered is no longer reported offline because another address
didn't.** The probe races a host's overlay address, management address and
hostname, and the first error to arrive was overwriting the success that had
already cleared it — so the verdict depended on which reply landed last. A device
whose bare hostname the jump host cannot resolve therefore flapped between online
and offline, sending paired disconnect/recover notifications for something that
never went anywhere. Reachability is now decided by whether any candidate
answered, and the first error is kept only as the reason when none did.


**A container whose compose project uses an overlay can be updated again.** The
in-place path `cd`-ed into the project's working directory and let compose
rediscover files by their default names — so a project assembled from
`docker-compose.yml` **plus** an overlay, with the service defined only in the
overlay, reported "no such service". Every rebuild of that image was then written
off as an orphaned container no rollout could ever fix, while the container was
perfectly ordinary and Docker had recorded both files on it the whole time. The
container's own `com.docker.compose.project.config_files` label is now collected
and used, verified to exist on the host first (a project deployed from inside a
container records paths this host does not have, which is why they were skipped
originally) and falling back to discovery when it does not. Every compose
invocation goes through one wrapper, so the check, the pull and the recreate
cannot act on different projects.

**The log console signs you in, and your Provenance role decides what you can do
there.** `/aldgate/` was a bare proxy: Dashboards asked for its own username and
password, so the only credential that worked was the collector's `admin` account
— every privilege there is — and a Provenance role had no bearing on any of it.
Now **Open log console** mints a short-lived scoped session, nginx checks it on
every request, and the backend answers with the collector credential for the
tier the person's permissions earn: `Logs.View` opens a read-only console,
`Logs.Administer` (new, Administrator and above) opens the full one. The
credential travels in a header from an internal location and never reaches the
browser, and the tier is evaluated per request — so a role change takes effect on
the next request rather than when a twelve-hour cookie expires.


**An orphan container is no longer reported as "already past" the update.** A
rebuild rollout of `caddy:2-alpine` skipped its only host saying "this host was
already past every image in this rollout — its compose files name newer tags than
this rollout's target". Every part of that was false: the host ran an *older*
digest than the registry, its compose file named nothing newer, and no rollout
could ever change it, because the container is an orphan — the compose project no
longer defines that service, so there is nothing for `up -d` to recreate. The
engine had the right explanation and logged it, then replaced it with that summary
on the host's row, so the rollout looked complete while the Updates page went on
correctly offering the update. Orphans are now a distinct outcome carrying the
real reason and the command that resolves it; a rollout that updated some images
and could not update others says so instead of reporting only the successes.

**The monitor no longer logs into network devices to see if they are up.** It
probed every host over authenticated SSH each 30 seconds. On a RouterOS device
the probe collects nothing — every fact command is a syntax error — so the login
existed only to prove reachability, while writing "admin logged in" and "admin
logged out" into the device's own log twice a minute: about 5,700 lines a day per
device, all of it Provenance, and all of it now shipped to the log collector
where it buried everything real. Those devices are checked by reading the SSH
identification string instead, which is silent on the device (measured on the
hardware). The trade is explicit: a device with a rotated credential now reads as
online, because it is — the terminal, a command run or a playbook will say
otherwise the moment anyone uses it.


**RouterOS output on the Commands page now says why it looks wrong.** RouterOS
sizes its tables by asking the terminal where the cursor is and waiting for an
answer; an exec channel cannot answer, so it wraps to roughly one column and
`/system/identity/print` returns one letter per line. The command worked. The
output now carries a short note pointing at the `:put` form, the terminal, or a
RouterOS playbook — all of which format properly. (Requesting a pty was tried
and is worse: it still wraps and then hangs on an interactive prompt.)

**Run command now works on hosts that authenticate from the credential vault.**
It dialled with Provenance-issued certificates only, so any host with
`vault_password` or `vault_ssh_key` — in practice the network gear, since a
switch will never trust our CA — failed with "unable to authenticate, attempted
methods [none publickey]". The terminal and the playbook runner both inject the
credential, so the same device was reachable from one page of the product and
unreachable from another, with an error that blamed the device. The requester is
passed through, so a credential with a check-out policy is only used while that
person holds an active check-out, exactly as in the terminal.


**The Logs page now covers SNMP traps as well as syslog.** Aldgate normalises
traps into the same fields, so one search spans the network gear and the
machines: `severity_code <= 3` finds a switch port dropping next to the kernel
message from the host behind it. Searching only syslog meant a page that could
report a quiet network while the trap saying otherwise sat one index away.


**A log filter that matched nothing blanked the page.** Search results returned
`null` for their host and severity aggregations when nothing matched, the page
called `.map` on null, and React unmounted the whole tree — a blank screen with
no error, for the most ordinary case there is. `entries` was guarded against
this and the two aggregations were not, which only moved the crash. Every list
is now an empty array at the source, and the page treats a missing list as empty
regardless: no amount of server-side care is worth betting a whole page on.


**Logs: the fleet's logs, in the same place as the fleet.** Provenance now
searches an [Aldgate](https://github.com/kforbus3/aldgate) collector — syslog
from every host, SNMP traps from network devices, stored in OpenSearch. A new
**Logs** page searches by text, host, severity and time range, and shows which
hosts and severities a match is spread across, which is how you get from
"something is wrong" to "it is that machine". **Open log console** frames
OpenSearch Dashboards under Provenance's own origin at `/aldgate/` for the
analysis a table should not attempt: visualisations, alerting, Security
Analytics.

Searches are brokered server-side rather than from the browser, for the same
three reasons the Kubernetes broker exists: the collector's credential never
reaches a browser, every search is recorded as `logs.search` with its query and
filters, and `Logs.View` decides who may run one. There is deliberately no write
permission — changing a log is not something an audit trail should offer.

`PROV_ALDGATE_URL` empty disables the page, and it says how to point at a
collector instead of reporting a fault. See **[Logs](./aldgate.md)**.


**An orphaned container no longer halts a rollout.** A container keeps the
compose service label it was created with, so renaming or replacing a service in
the file and bringing the project up without `--remove-orphans` leaves the old
container running under a name the file has forgotten. Provenance still offers to
rebuild it — it is a real container on a real image — and `compose up -d <that
service>` cannot work, because there is nothing to bring up. That failed the
host, which halted the whole fleet-wide run over one stale container. It is now
reported as inapplicable, like a host that has already moved past an image.

The message was wrong too: it said "this is not the project they came from", when
it *was* that project — the project had moved on without the container. It now
says the service is no longer defined, and how to clear the orphan.

---

## v1.7.1 — 2026-09-18

**What a person may do to a Kubernetes cluster is now decided by their
Provenance role.** Every operator reaches a cluster through one registered
credential, so the cluster cannot tell them apart — to it, every call is the same
ServiceAccount. `Kubernetes.Access` was therefore all-or-nothing: whoever held it
could do whatever that cluster's RBAC allowed, identically for an administrator
and a read-only operator. Provenance sits in the middle of every call, so it is
the only thing that *can* tell them apart, and now it does — checked per request,
before the cluster credential is attached.

- **`Kubernetes.Operate`** covers workload lifecycle; **`Kubernetes.Administer`**
  covers the cluster itself and Secrets; `Kubernetes.Access` now means read.
  Secrets need `Administer` **even to read**, because a console that can read
  them is a second secrets manager with different rules. `exec` is not a read
  either: it opens with a `GET` that upgrades the connection, so classifying by
  HTTP method would have handed every read-only operator a shell in any
  container.
- **The console's buttons follow the same rules.** Headlamp renders what the
  *cluster* says it may do, which is the ServiceAccount's answer — so a read-only
  operator was shown every destructive control and each one then failed. That is
  worse than an absent button: it cannot be told apart from a broken console.
  Provenance now intersects those `SelfSubjectAccessReview` answers with the
  caller's permissions on the way back. It can only narrow, never widen.
- **A third onboarding level, `administer`**, grants the cluster — namespaces,
  CRDs, RBAC, storage, Secrets. Withholding it did not make the console safer, it
  made it incomplete: a console that cannot create a namespace sends the operator
  back to a terminal, where nothing is recorded. Headlamp reveals the create
  affordance once RBAC allows it — a `+` beside the page heading opening a typed
  form, not a YAML editor. `read` and `operate` are unchanged, and it is not the
  default.
- **Helm is enabled on the Headlamp backend** (`-enable-helm`) but is **not
  reachable from the console**: the bundled web frontend ships no Helm section,
  and the backend's Helm endpoints are gated behind an internal
  `X-HEADLAMP_BACKEND-TOKEN` that only Headlamp's desktop build sends. Use `helm`
  with a downloaded kubeconfig, which goes through the same broker and is audited
  the same way. The flag is left on so a later Headlamp that ships a Helm UI needs
  no redeploy; such a UI would require a cluster joined at `administer`, since
  Helm keeps release state in Secrets.

> **Upgrade note.** The built-in Operator, Administrator and Super Administrator
> roles are seeded with the new permissions and keep exactly what they had. A
> **custom** role holding only `Kubernetes.Access` can now only read — grant it
> `Kubernetes.Operate` to restore writes. This is a deliberate tightening in the
> safe direction.

**Verification asks about the services the deploy named, not just the
repository.** The readback filtered `docker ps` by matching each container's
image string against the rollout's repository — so a container recreated from an
untagged image, which reports a bare `sha256:…` and names no repository, was
dropped before a single check ran, including "is anything still on the old tag".
That is how a partial update passed: `nextcloud-cron` moved to 35 and reported
its tag, the Nextcloud app stayed on 34 and reported a digest, and the host was
recorded as verified with the app and its cron job on different major versions
against one data directory. A deploy knows which services it named, and a compose
service can be found by its labels whatever its image says, so those are now
checked by name — absent, wrong image, or not running all fail the host.

**A narrowed deploy no longer reaches into the service's dependencies.**
`docker compose up -d <service>` also brings up that service's `depends_on`, and
recreates any of them that have drifted from the file — so a deploy asked to
touch one service reached into its database. A Keycloak rollout, correctly
narrowed to the `keycloak` service, recreated `keycloak-db`, the new Postgres
refused the existing data directory, and the deploy failed with "dependency
failed to start: container keycloak-db is unhealthy" with Keycloak down. Nothing
in the rollout had been a Postgres change. Narrowed deploys now pass
`--no-deps`; the services that genuinely must come along — anything sharing the
service's network namespace — were already named explicitly, and a whole-project
deploy is unchanged, because there dependency order is the point.

**A failed deploy says what went wrong first.** The message was the last 600
characters of the output, which for a deploy that pulls anything is as likely to
be progress bars as a reason: the Keycloak failure above was reported as
`…6.3MB b021fe485c81 Pull complete dcee140b22ee Extracting [====>] 546B/546B …`
with the one line that mattered at the very end. The cause is now extracted and
put first, preferring the specific phrase over the generic one that accompanies
it, with the full transcript kept after it.

**A container recreated from a digest no longer hides its service from an
update.** Narrowing a deploy matched containers by repository and tag, and only
consulted the compose file when *nothing* matched. A container recreated from an
image referenced by digest records its repository as `sha256`, so it matches no
repository at all — and in a project where one service does match and another
does not, the file was never consulted and the unmatched service was left behind.
On the Nextcloud stack that recreated the cron container onto 35 and left the app
on 34 against one data directory, and the verification could not see it either,
for the same reason, so the host was recorded as verified. Service selection is
now the **union** of what the containers say and what the compose file says: the
file is the authority on which services use an image, the containers only say
what is running.

**A deploy is refused when the compose file pins a stateful image across a major
version from the data on disk.** The existing guard checks the image a rollout is
*changing*; this one checks what the deploy is about to *apply*, which is not the
same thing. `compose up -d <service>` brings up that service's `depends_on` too,
so a Keycloak upgrade recreated its database from a file still pinning Postgres
18 against a version-17 data directory — Postgres refused the directory,
crash-looped, the dependency never went healthy and Keycloak never started.
Nothing in the rollout was a Postgres bump, which is exactly why the old rule did
not see it. Refused rather than repaired: the file may be right and the container
merely old, and rewriting somebody's pin would be a guess with a service behind
it.

---

## v1.7.0 — 2026-09-17

**Kubernetes management, end to end.** Provenance brokered access to clusters but
could only list five resource kinds. It is now somewhere a cluster is operated,
without Provenance becoming a Kubernetes dashboard — the upstream Kubernetes
Dashboard is archived, and its successor **Headlamp** (Apache-2.0, a Kubernetes
SIG project) is embedded and routed through the broker instead of
re-implemented.

- **The proxy carries watches and shells.** It was `client.Do` plus a body copy,
  which cannot do a watch (events sat buffered), an `exec`, `attach` or
  `port-forward` (those are connection upgrades — there is no body to copy), or
  `logs -f`. It also had a 30-second timeout on the whole request, when every one
  of those is *supposed* to stay open. Rewritten on `httputil.ReverseProxy`, with
  the deadline moved to the response headers.
- **The console is embedded, not linked.** Framed under Provenance's own origin
  from the cluster row. Provenance tells Headlamp which clusters exist — names
  and server URLs pointing at the broker — and deliberately gives it **no cluster
  credential**; the operator's own identity is what reaches the broker, so the
  audit log names a person rather than a shared account. Newly registered
  clusters appear within seconds: Headlamp watches the cluster list, so there is
  nothing to restart.
- **The console signs itself in, and opens in a tab.** There is no token to paste.
  Provenance mints a per-user token scoped to `/api/v1/k8s`, valid 12 hours, and
  hands it to Headlamp's own `set-token` endpoint, which stores it in an HttpOnly
  cookie. Because that cookie belongs to the origin rather than to the frame,
  **Open in new tab** gives a full window that is already signed in, with nothing
  secret in the URL. Access is governed by `Kubernetes.Access` — the permission
  that gates minting — so Provenance's roles control the console with nothing
  separate to keep in sync, and **signing out revokes the console token** so a
  shared browser leaves no working cluster access behind. Minting supersedes the
  operator's previous console token, so each person has at most one live at a
  time. Where minting is refused, Headlamp's own token prompt still works.
- **Download kubeconfig** mints a token and returns a working config in one
  action, for `kubectl`, `k9s`, Lens or a desktop Headlamp. The token is
  **scoped to `/api/v1/k8s`** — it can reach the Kubernetes broker and nothing
  else in Provenance, not a host, not a credential, not a playbook — and it
  expires. A scoped token cannot mint another, so a leaked file cannot renew
  itself past its own expiry.
- **Cluster RBAC** generates the ServiceAccount, roles, bindings and long-lived
  token Secret a cluster needs before it can be joined, at a **read** or
  **operate** level. Neither is `cluster-admin`, and neither is the built-in
  `edit` role — `edit` grants Secrets read *and* write, which is rarely what
  anyone wants from a management UI and never what they expect.

**Durable API tokens can belong to a person, and can be confined.** Tokens were
service-account-only. They can now be owned by a user, and carry an optional
**scope**: an API path prefix outside which the token is refused, enforced in
middleware before the permission check. Scopes match on path *segments* — a token
scoped to `/api/v1/k8s` must not reach `/api/v1/k8superadmin`.

**A container update now recreates every service on the image, not the first.**
The tag rewrite has always been file-wide — it changes *every* `image:` line
naming the old tag — but the deploy that followed was narrowed to the first
container found running it. In a project where one image backs several services
(a worker and a web process from one build; a model router and a dedicated
embedding server from one llama.cpp image) that recreated one of them and left
the rest running the old image, while the compose file on disk already claimed
the new tag for all of them. Declared state and running state disagreed, and the
next unrelated `docker compose up -d` in that project would have resolved it by
silently recreating the stragglers at a moment nobody chose.

This reached production and the post-deploy verification caught it — the host
failed with "deployed, but *x* is still running *the old tag*" and the rollout
halted itself, which is the only reason it was found. Both paths are fixed: the
adopted-stack deploy and the in-place rebuild through the host's own compose
project. Narrowing is still narrow — services sharing the image and anything
sharing their network namespace, never the whole project.

**A revocation that revoked nothing is no longer reported as success.** 137 store
writes ran an `UPDATE` or `DELETE` and returned only the database's error, so
they could not tell "I changed the row" from "I matched nothing". For a
revocation that is the difference between an account being disabled and an
operator being told it was — and under row-level security a write blocked by
tenant isolation matched zero rows and looked identical to success. The
revocation class now reports it, and handlers answer `404` naming what did *not*
happen. Bulk and idempotent writes are unchanged, because zero rows there is a
real answer.

Bootstrap no longer ignores the result of granting the first account its
Super Administrator role — that wizard permanently self-disables, so a silent
failure left an instance whose only user could not administer it. SCIM no longer
ignores the default-role assignment or the disable on an `active:false` create.

**Container update rollouts** verify what they claim, and a major-version bump of
an image that owns its on-disk format (postgres, mysql, mariadb, mongo,
elasticsearch) is refused rather than applied and then reported as verified.

**Dependency-ordered schedules.** A playbook schedule can run its hosts in waves
— dependents first, whatever carries them last — so storage is never rebooted
out from under guests still patching.

---

## v1.6.0 — 2026-09-16

**Provenance can be told which hosts stand on which, and act on it.** Hosts were
modelled as a flat set. On a real estate they stand on each other — seventeen guests
on one hypervisor, every root disk served over NFS by a single NAS — and nothing in
the schema could say so, so nothing could act on it.

What that cost, concretely: an apt run covered a group holding both a set of guests
*and* the NAS serving their root filesystems. The NAS rebooted mid-run and four guests
failed on `Timeout waiting for privilege escalation prompt` — `sudo` hanging because
its filesystem had gone away. They answered SSH throughout, so the run recorded
`unreachable=0` and it presented as a sudo problem on four unrelated machines.
**Storage is the one dependency whose failure does not look like itself.**

A host's detail dialog now has a **Dependencies** section showing both directions —
what it *stands on* and what it *carries*. Topology is asserted rather than collected:
a host cannot report that it is a guest of a particular hypervisor. Cycles are refused
and the rejection names the path it found (`nas → hypervisor → guest-a → nas`), checked
inside the same transaction as the insert so two operators adding opposite halves of a
loop cannot both commit.

**A blast-radius preview appears before anything that can disrupt a host** — deleting
hosts, running a playbook for real, running an ad-hoc command, retiring a superseded
account — including runs aimed at a *group*, which is the shape a fleet upgrade takes:

> `nas` is in this action, and 14 hosts have their disks served by it — they keep
> answering the network while every write blocks, so this does not present as a storage
> failure. 11 of them are not in this selection.

Dependents *outside* the selection are collateral and read as critical; dependents
*inside* it are an ordering hazard and read as a warning. It is deliberately absent
from refreshing facts, editing tags and setting a maintenance window: those change
nothing on the host, and a warning shown where it does not apply is how the one that
matters gets skimmed past.

**A playbook schedule can now run in dependency order.** Its hosts go in waves —
dependents first, whatever carries them last — so storage is never rebooted out from
under guests still patching. This replaces ordering by clock arithmetic, which is a
race rather than an order: a guest run bounded by a ninety-minute timeout can still be
going when the storage window opens. Each wave is its own run, and **a wave that does
not complete stops the rest**. Off by default, and a selection yielding a single wave
falls through to an ordinary run.

**Container update rollouts no longer report a broken container as verified.** Three
defects, all found after an "update all" reported success on every host while two of
them had not taken the update and one had been broken by it:

- `docker ps` lists a container in `restarting` exactly like a healthy one, carrying
  the new image and the new digest. A `postgres` image bumped across a major version
  never starts — it exits on the old data directory and restarts forever — yet
  verification read the image, saw what it wanted, and recorded the host as verified.
  Verification now reads each container's **state**, and one that is not running fails
  the host.
- A repository can run in several containers on one host. The check stopped at the
  first container matching the target tag, so a host where one had moved and another
  had not was recorded as verified. A container still on the tag being moved away from
  now fails the host.
- A rebuild republishes the *same* tag, so the cached registry answer kept matching the
  container it described and went on reading "rebuilt" for up to twelve hours after the
  rebuild was applied — indistinguishable from a rollout that silently did nothing. A
  host reaching verified now drops the cached answers for both tags.

**A major-version bump of a stateful image is refused.** `postgres`, `mysql`,
`mariadb`, `mongo`, `elasticsearch` and friends own their on-disk format: pulling the
next major does not migrate it, it takes the service down until someone runs
`pg_upgrade` by hand with both versions present, which a rollout cannot do. Refused at
rollout creation *and* per host, so a rollout created before this rule cannot still be
applied by a later tick. Minor and patch moves are untouched — those carry the security
fixes — and an unorderable tag is never guessed at. Like this application's own
containers, these updates stay **visible**; only applying them this way is refused.

MINOR: new table, new endpoints, new surfaces; nothing removed. A deployment that
records no topology behaves exactly as before — every preview renders nothing and every
ordered schedule collapses to a single wave.

---

## v1.5.0 — 2026-09-14

**OpenBao is a supported external secrets manager.** It is a fork of Vault 1.14 and
serves the same KV v2 routes, so it shares the client and the connection settings —
but it is a distinct provider *name* rather than an alias. That name is stored on
every external-backed credential and shown in the UI: an operator who chose OpenBao
should see OpenBao, an error should name the server they actually run rather than
sending them to look at a Vault they do not have, and if the two ever diverge every
existing credential already records which one it was created against.

**The connection to that manager is now configurable in the UI** — Settings →
Infrastructure → *External secrets manager*. It was environment-only, which meant
changing it was a redeploy and seeing it was reading somebody's `.env`. It is stored
like the OIDC and LDAP connections: one settings row, with the token and the AWS
secret key sealed at rest and never returned to the browser. The screen is told only
*whether* each credential is set, so a blank field unambiguously means "keep the
stored one"; clearing a connection is done by clearing its address, which is visible
and therefore deliberate. A **Test** button checks reachability and, given a
reference, reads it — proving the token has access rather than only that the server
answers.

The environment stays the baseline and saved values are layered over it **field by
field**, so a deployment that predates this screen has no row at all and keeps working
untouched, and filling in only the address does not unset the token `.env` supplies.
Skip-TLS-verify is the exception: it is OR-ed rather than overwritten, because `false`
is indistinguishable from "not set" for a boolean, and silently turning off a
verification bypass the environment asked for would change how the connection is
authenticated with nobody saying so.

Every existing consumer — the monitor, terminal, SFTP, playbooks, Windows scripts and
imaging — resolves through the saved connection unchanged, via one overlay installed
where the store and the configuration both exist, rather than each of them learning
that settings exist. A credential that cannot be unsealed (a rotated CA passphrase, a
corrupt row) resolves to *empty* rather than to garbage: empty falls back to the
environment, which is a connection an operator can reason about, where a wrong value
would authenticate as somebody else.

---

## v1.4.0 — 2026-09-13

**Ask can talk to an OpenAI-compatible model server.** It spoke only Ollama's native
API — `/api/tags` and `/api/chat`, with the model's context length read out of
`/api/tags`. llama.cpp serves no `/api/*` routes at all, so a deployment that moves
to it cannot be repointed by changing a URL: the protocol has to change with it.
Select **OpenAI-compatible (/v1)** in Settings → AI assistant, and the same screen
takes an optional bearer token for a server that wants one.

Everything above the client stays written against Ollama's shapes, because that is
what the tool loop, the fast paths and the direct answers were tuned against; the new
client adapts to those shapes rather than the reverse. Three differences had to be
translated and each one is silent when it is wrong: tool-call arguments are a JSON
string on this wire and a JSON object in Ollama's, every tool call carries an id that
the result must quote back, and sampling options are top-level fields rather than a
nested map.

A setting saved before this release has no `provider` value. That is not a choice to
run OpenAI, so it resolves to Ollama — which is necessarily what such a deployment
was talking to — and the protocol is never inferred from the URL or the port, because
an OpenAI-compatible server on `:11434` is perfectly legal and guessing wrong fails
as a connection error naming the wrong cause. `baseUrl` supersedes `ollamaUrl`; both
are read, and the settings page writes both, so a rollback still finds its server.

**The context warning had to change with it.** On Ollama the number that matters is
the model's trained length, and an overlong prompt is silently truncated from the
front — which is why Provenance sends an explicit `num_ctx`. An OpenAI-compatible
server fixes its window when it starts and no request can raise it, so `num_ctx` is
dropped rather than sent (sending it would let the caller believe it had asked for a
window it never got), and the comparison is against the **prompt floor** instead: the
system prompt plus every tool schema, about 10,200 tokens before a single row of
data. Below that the assistant cannot work at all, and the settings page now says so
with the number the server reported, the number required, and the setting to change —
on the server. llama.cpp also *errors* on an overlong prompt rather than truncating,
and the server's own message is surfaced, since "model not found" and a context
overflow are both actionable and both arrive as a bare 400 otherwise.

Also handled: a reasoning model that spends its whole token budget thinking returns
empty content with `finish_reason: length`. Returned as a successful blank answer it
is indistinguishable from a broken model — nothing errors and the log says nothing —
so it is reported as the configuration problem it is.

**An upgrade bundle now has to say which product it is.** The updater asked only
whether a bundle was *newer* than the running version, and newer is not the same
question as the same product: this repository carries tags from two earlier product
lines it was forked from whose numbering runs **ahead** of the current one, so a
Moorgate-era `v2.0.2` bundle outranks a running `v1.3.0` by semver and would have
been accepted — replacing the whole stack with an older, different codebase. It was
not hypothetical; that bundle was sitting in a deployment's updates volume.

Every bundle now declares its product lineage, and the updater checks it **before**
comparing versions — otherwise a foreign bundle with a high version number never
reaches the check. A bundle that declares no lineage is refused as well: the ones
that predate the field are exactly the ones from the other lines, and a bundle that
cannot say what it is cannot be shown to be the same product. Rebuild it with a
current `provctl release build`, which stamps it. No legitimate upgrade path
narrows — a bundle installed onto this release must be newer than it, and so was
built with the field.

---

## v1.3.0 — 2026-09-13

**Every Fleet identifier is now a Provenance one.** The product has been called
Provenance since v1.0.0, but the identifiers still said Fleet: 187 `FLEET_`
settings, the `fleetctl`/`fleetd` binaries, the `fleet-terminal` compose project,
the managed-host `fleet` account and its SSH principals, two row-level-security
helper functions, and the brand text throughout the docs and UI. Earlier rebrands
left all of it deliberately, on the grounds that renaming breaks running
deployments. This release renames it and carries the running deployment across.

Settings are `PROV_`, the binaries are `provd`/`provctl`/`prov`, bundles are
`.provup`, the compose project is `provenance`, and the managed-host account is
`prov`.

**Nothing that outlives a deploy answers to one name only.** Settings resolve
through a single lookup that falls back to the `FLEET_` name and warns once at
boot naming what to rename; the Compose files forward the old names too, so a
stack started against an un-migrated `.env` boots normally. Certificates carry
both spellings of every principal and enrollment writes both into each host's
`AuthorizedPrincipalsFile`, so **an enrolled host keeps working without
re-enrollment**, in either direction, including against a rolled-back server.
Teardown removes both generations, because removing only the current spelling
would leave a trusted CA and a NOPASSWD sudoers entry on a host an operator
believes is clean. `/api/fleet/heartbeat` stays mounted permanently beside
`/api/prov/heartbeat`: it is compiled into every agent image ever built, and
reaching those machines is what it is for.

**Moving a managed host to the new account is a two-pass operation in the UI**
(Hosts → Bulk actions), and the passes are separate because one of them is
irreversible. The first creates the new account, **proves a certificate login as
it works**, and records it against the host — deleting nothing. The second,
confirmed separately, retires the superseded account. A failure at any point
leaves the host exactly as it was, still reachable on the account it has. Hosts
whose login account Provenance did not create (`root`, or an operator-nominated
account such as `admin`) are refused rather than having that account deleted, and
so is any host Provenance's own access depends on — the jump host, the machine the
stack runs on, anything tagged `control-plane` — unless confirmed for that host
alone. That last check is the same one scan remediation uses, not a second copy.

Three failure modes found by running it on a real fleet, each of which could
strand a host long after the change that caused it:

- Removing a host's KRL while `sshd_config` still carried
  `RevokedKeys /etc/ssh/<name>_krl` passed `sshd -t` — the file was still there —
  and failed on the host's *next* reboot. On a host with no
  `/etc/ssh/sshd_config.d`, that directive lives in the main config, nowhere near
  the block a teardown strips.
- On those same hosts, the old and new CA blocks both sit in the main config under
  a marker, and stripping "the marker block" took the **current** CA trust with the
  old one. `sshd -t` passes on a config that trusts no CA at all, so the reload
  went ahead. The cleanup now edits by CA path and makes a positive assertion that
  the current trust survived, rather than trusting a syntax check.
- Recording the new account used a store helper that only ever fills a blank, so
  it matched no rows, reported success, and left every migrated host's row naming
  the account that had just been removed. The row is now written *before* anything
  is removed, by a function that fails if it changed nothing.

**Deploy note — this release cannot be applied as a `.provup` bundle.** It renames
the Postgres role and database and the Docker Compose project, and a bundle
installs images into the project that is already running. Upgrading is a
deployment swap: stop the old project, copy its volumes to the new prefix, rename
the role and database, rename the `FLEET_` keys in `.env` (the values are
unchanged), and start the new project. `docs/compatibility.md` has the full
procedure, including what keeps working untouched and what does not.

---

## v1.2.35 — 2026-09-13

**An update that has just been applied stops saying it is available.** Running
containers are collected on a ten-minute cadence, which suits a sweep and does
not suit the moment immediately after something has deliberately changed them.
For up to ten minutes after a rollout, every screen built on that inventory
described what the host was running BEFORE — so an update that had just
succeeded went on reading "update available", which looks exactly like one that
failed.

A host's containers are now re-read as soon as they are changed, by both routes
that change them: deploying a stack, and updating an image in place. It uses the
same script and the same reader the monitor uses rather than a second copy, since
two of those would eventually disagree about what a host is running — the one
question this feature rests on.

Only a reading that actually reached the host replaces the list. A script that
died, or a container runtime that could not be reached, produces an empty list
with a reason attached; recording that would blank the host's containers and turn
a momentary hiccup into "this host runs nothing" everywhere. Those cases stay
with the sweep, which records them deliberately.

---

## v1.2.34 — 2026-09-13

**The Discovered tab works.** It has been empty since the release that added it,
because the query behind it could not be parsed: a comma where it needed CROSS
JOIN LATERAL put one table out of scope for the join that referenced it, and the
server rejected it on every single call. The screen reported that as "no compose
projects found yet… they are discovered by the monitor sweep as it reaches each
host", which reads as a fact about the fleet and describes a sweep that had
already happened. It now lists what is actually there — sixteen projects across
seven hosts on this deployment — and a request that fails says so instead of
showing an empty list.

**Every read query in the store package is now executed against a real database
as part of the tests.** Nothing had ever run them. A Go compile error is caught in
milliseconds; SQL sits in a string and gets none of that, and the screen's own
test mocked the call, so a query that could not run passed the whole gate twice
over. The new check applies the migrations to an empty PostgreSQL and runs each
query, failing only on the class of error that means the query itself is wrong —
missing rows prove nothing either way.

---

## v1.2.33 — 2026-09-13

**Deploying a stack now survives long enough to finish, and says so while it
runs.** A deploy that pulls images takes minutes, and it was running inside the
HTTP request that asked for it — behind a sixty-second timeout. Past that the
deploy was killed mid-pull and the attempt to record what had happened was
cancelled with it, so the screen went on showing the previous outcome. Pressing
Deploy looked like it had done nothing, which is precisely what it had done. It
runs detached now, the way the registry sweep already did, and answers straight
away.

A deploy in flight is recorded as such before it starts, so there is something to
look at while it runs — and recorded WITHOUT changing the revision the host is
known to be running, because claiming the target before it is running would be a
success reported minutes early. The screen shows "deploying r12…" and follows it
to the outcome rather than leaving anyone to guess when to reload.

One consequence worth stating: while a deploy runs, the recorded revision and the
wanted revision disagree, which is what drift normally means. A deploy in
progress is not drift — it is the answer to drift, happening — so it no longer
puts a stack into the needs-attention list for the minutes it takes to pull.

---

## v1.2.32 — 2026-09-13

**A rollout that wrote the compose file but never deployed it can now finish the
job.** A rollout does two things: it rewrites the file to the target version,
then applies it. One that did the first and failed the second — and was then
resumed — went looking for the version it was moving away from, and by that point
the file named the target, no container ran either version, and the version it
was looking for existed nowhere. Seven of them reported "this host was not
running any of the images by the time its turn came" about a host where every one
of them still had a container to recreate. Nothing to match was being reported as
nothing to do.

An image now also applies when a compose file on the host names the target and no
container is running it yet, which is exactly "the file landed, the deploy did
not". Everything after that point already handled it — the stack is recognised,
the service is read from the file, and the deploy is narrowed to it. Bounded so
that once a container IS on the target the work counts as done, and a resumed
rollout will not restart a service for nothing.

---

## v1.2.31 — 2026-09-13

**A check that found nothing newer no longer reads as a check that failed.**
Thirty rows on the Containers screen said "cannot compare"; twenty-two of them
were up to date. The verdict was being inferred from the explanation — and
"nothing newer with the same shape as 10.11.11; the repository carries other
version tags that cannot be ordered against it" means the image is current,
while rendering identically to a registry that would not answer. A check now
records what it concluded as a value, and the screen reads that; the sentence
stays as the explanation a person reads. Rows checked before this arrived fall
back to the old reading, so an upgrade does not empty the page while it waits.

**A tag listing is reused instead of fetched again.** Reading a repository's
tags in full made the answer correct and made it cost up to thirty-two requests
instead of one. A sweep of the fleet is then several hundred requests to a single
registry, and pressing the button a few times within an hour is enough to be rate
limited — which was reported as "could not list tags" against eight images that
were perfectly fine. Listings are now kept for an hour: long enough that pressing
the button repeatedly costs one listing rather than one each, short enough that a
check made because something was just published still sees it. A registry that
refuses falls back to the last listing it gave, at whatever age — what was
published this morning is a better answer than none.

**A rate-limited registry no longer says a host pulled something it did not.**
The digest held against a tag a compose file names is the running container's,
because it is the only one there is, so "this host is running an older build"
cannot be said about a tag the host has never pulled. That was guarded on the
ordinary path and unguarded when a listing failed, so a single rate limit put the
sentence on every such row at once.

---

## v1.2.30 — 2026-09-13

**A deploy is narrowed using the compose file it is about to apply, and no longer
fails on a flag that command does not take.** Seven rollouts failed with "unknown
flag: --remove-orphans" — a flag that belongs to `up` and was being handed to
`pull`, killing the deploy before a single image was fetched. It only ever fired
on a whole-project pulling deploy, which is why it had gone unnoticed.

The deploy should not have been whole-project. The service to narrow to was
looked up from a running container matching the repository AND the tag being
moved away from — and no container runs that tag when the file is pinned ahead of
the container, which is the state every pinned-but-not-yet-recreated service is
in. All seven found nothing, and nothing means the whole project. On a media
stack that would have recreated the VPN container and, with it, every container
sharing its network namespace, in order to update one service. The flag error is
the only reason it did not; fixing the flag alone would have turned seven
failures into one very large restart.

The compose file is the better authority in any case — it is the thing about to
be applied, and it names the tag the rollout is moving to. It is read anchored on
the services block, so an anchor carrying an image line cannot be mistaken for a
service; narrowing to the wrong name is worse than not narrowing, because it
reports an update that never touched what it named. The whole project remains the
fallback when neither the container nor the file can name the service.

---

## v1.2.29 — 2026-09-13

**An update the screen offers can now be started.** Rolling out one of the
versions a compose file names was refused with "no host is running
lscr.io/linuxserver/bazarr:v1.6.0-ls356" — for an update that had just been
offered on the screen above it. Pinning a compose file to the version a container
is already on recreates nothing, so the file names the version while the
container still carries the floating tag, and the update therefore has a
from-tag no container has. The rollout engine already understood that; the code
that CREATES a rollout did not, so the two disagreed and the offer could never be
taken. Both now apply the same rule, restricted to repositories the host actually
runs so a compose file cannot start a service that is down.

**Finished rollouts can be cleared.** A rollout that is over is history, not
state, and an evening of single-image rollouts leaves thirty finished rows above
the one actually running. A "Clear finished" button removes the completed,
cancelled and halted ones together, in a single request rather than one per row.
Paused rollouts are deliberately kept: a paused rollout looks inert and is not,
because the hosts it has claimed are mid-update and resume is a button somebody
may still intend to press. The containers a rollout updated are untouched — this
clears the record, not the state.

Also backfills the `declared` flag added in v1.2.27, which defaulted to false on
upgrade and so hid exactly the rows an operator had upgraded to see until the
next registry check happened to rewrite them.

---

## v1.2.28 — 2026-09-13

**A container recreated onto the version its compose file names is reported as
updated, not skipped.** Rolling out a rebuild of `wyoming-piper:latest` against a
host whose compose pins `2.2.2` pulled the image, recreated the container on
`2.2.2`, and left it healthy — the drift between the running tag and the file
resolved, which is the whole point. It was then reported as "this host was
already past every image in this rollout that it runs", which says nothing
happened and sends an operator looking for the change somewhere else.

An update applied without a managed stack runs the host's OWN compose file, so
the tag it lands on is that file's choice and landing there is the job done. An
update applied through a managed stack is the opposite case: the rollout wrote
the tag itself, so coming back on a different one means somebody re-pinned the
service underneath, and reporting it as superseded is right. The two are now told
apart rather than judged by the same rule.

Coming back on the tag it was moving away from is still a failure either way — a
deploy that reports success and changes nothing is what this feature exists to
catch.

---

## v1.2.27 — 2026-09-13

**The row that can actually be applied is now the one you are shown.** A
container running `:latest` whose compose file names `v1.6.0-ls356` produces two
entries, and they behave in opposite ways. Rolling out the `:latest` one can only
skip — the host's compose has already moved past `:latest`, so the image is
superseded, the container is never recreated, and the next check reports the same
rebuild again. Rolling out the one the compose file names rewrites that file,
recreates the container, and is what finally moves it off `:latest`.

Only the first was ever listed, because the screen is built from what the fleet
runs and nothing was running the pinned tag yet. Six services were in that state.
The rebuild row was the only thing on offer for each of them, it was rolled out,
it completed, and nothing changed.

Both rows appear now. The one a compose file names is offered against the hosts
running that repository — the same rule the rollout engine applies, so what is
offered and what a rollout will do cannot disagree. The one still running the old
tag reads "superseded by v1.6.0-ls356" rather than "rebuilt", drops out of the
actionable count, and says which row to use instead.

---

## v1.2.26 — 2026-09-12

**Check now checks everything.** A pass was capped at forty images, so a fleet of
sixty-four left twenty-four unchecked — and the count went to a log line while
the screen said only that a check had started. Two of the images in that
remainder had real updates waiting behind them. Nothing told anyone a second
press was needed.

The cap is about a registry's rate limit, and for the unattended sweep that runs
every twelve hours it is exactly right: a fleet-wide pass must not exhaust a
limit nobody is watching. A press is rare, deliberate and waited on, and applying
an unattended bound to it made the button do part of its job in silence — the
same mistake as applying the twelve-hour freshness window to a press, which was
fixed earlier for the same reason. Batching is a budget now: one batch for the
sweep, ten for a press, bounded either way, and a pass that reaches its bound
still says what is left.

---

## v1.2.25 — 2026-09-12

**A repository's tag list is now read in full, and an answer says so when it
could not be.** The listing stopped after one page of a thousand tags. That was
never a bound, it was a wrong answer: registries return tags in roughly insertion
order, so the current release is at the END. The first page of
`lscr.io/linuxserver/bazarr` is a thousand tags from 2019 and does not contain
the tag the host is running, let alone anything newer — and "nothing newer
exists" was then reported with complete confidence about a list that never
reached the present. That repository has 9,261 tags across ten pages; jackett has
31,667 across thirty-two. The Link headers saying so were being sent and ignored.

Pagination is followed now, bounded at forty pages, and a listing stopped by that
bound reports itself incomplete. An incomplete list can only support "this is
what was found", never "this is everything there is", and the note says which.

Two smaller corrections came out of checking real registries rather than a
fixture. A row for a compose-declared tag dropped the REASON when nothing newer
was found, so "nothing newer exists" and "nothing here could be compared" looked
identical. And a suffix stem may contain digits: qbittorrent is tagged
`5.2.3_v2.0.13-ls469`, where those digits are the bundled libtorrent version, and
refusing them left it unorderable against the very next build. Every refusal that
matters still holds, because the stem must match exactly — `-alpine` against
`-bookworm`, `-alpine3.` against `-alpine4.`, a release against a prerelease.

Eleven of this fleet's images resolve to a real newer tag as a result, where
before they reported having no comparable tag in their own repository.

---

## v1.2.24 — 2026-09-12

**A forced recheck now reaches the images it was pressed for.** A pass checks a
bounded number of images, because a registry's rate limit does not care why the
request was made. Which images waited for the next pass was decided by where they
happened to sit in a list — ordered by name, with the tags a compose file names
appended after them. On a fleet of sixty-four images against a cap of forty, that
put every one of those rows past the cut, every time; and on a forced pass, which
deliberately ignores freshness and so re-offers the same first forty, it would
have put them there permanently. The pass reported "checked 40, failed 0" each
time, which is why nothing looked wrong.

A pass is now ordered by what has waited longest, with images never checked at
all going first. That is the right rule irrespective of the bug: an image that
has just appeared is the one somebody is most likely waiting on.

---

## v1.2.23 — 2026-09-12

**Updates are now found for the version you pinned, not just the tag that
happens to be running.** Pinning a compose file to the version a container is
already on recreates nothing — the digest does not change, so there is no work
for Docker to do. Between that pin and the next deploy the file says
`bazarr:v1.6.0-ls356` while the container is still on `:latest`, and thirteen
services across two hosts were sitting in exactly that state. The check followed
the container, so those were only ever asked about under `:latest`, where the one
available answer is "latest moved again". The version actually chosen was never
compared against anything, and the upgrade waiting in the registry could not be
seen. Tags a managed stack names are now checked in their own right, and a
rollout built from one applies to the hosts whose compose files name it.

**Every linuxserver.io image was permanently unupdatable, and now is not.** They
are tagged `v1.6.0-ls356`, and the next build of the same image is
`v1.6.0-ls372`. The rule that keeps `15-alpine` from being offered as an upgrade
to `16-bookworm` read that build number as a variant, so seven images here were
each reported as having no comparable tag in their own repository while being a
plain version behind. A suffix now matches on its stem and orders the number
after it as the count of builds it is. The stem may not itself contain digits, so
`-alpine3.21` against `-alpine3.22` is still refused: that number is the base
image's own version, and changing the operating system inside a container is not
a patch bump.

One consequence worth knowing: a service pinned but not yet recreated will now
show its real update, and applying it is what finally brings the container onto
the version its file has named all along.

---

## v1.2.22 — 2026-09-12

**Saving a compose file no longer moves the stack somewhere else.** The compose
editor sent the text and no directory, and the server read that silence as a
choice — filling in `/opt/stacks/<name>` and relocating a stack that had been
adopted from somewhere on the host. The next rollout created the new directory,
wrote the compose file into it, and ran `docker compose` beside none of the files
the project needs. The operator was then told their compose file was invalid
("required variable WIREGUARD_PRIVATE_KEY is missing a value") when the file on
the host was perfectly good, and the rollout halted on a host that was doing
nothing wrong.

An empty path now means "not saying", not "move it". The default applies only
when a stack is first created, because that is the only time there is no
directory to keep. A stack whose recorded directory has already drifted repairs
itself from the compose labels of the containers actually running — so a
deployment that hit this does not need anything done by hand. And the editor
shows the directory and sends it back, since a path nobody can see is a path
nobody can notice is wrong.

**A skipped host says which kind of skip it was.** "This host was not running any
of the images" was also reported to a host that ran one and was skipped because
its own compose file already names a newer tag. Those point in opposite
directions — one at the host, one at a rollout that has gone stale — and only one
of them was ever said.

---

## v1.2.21 — 2026-09-12

**A compose project the host cannot reach is explained, and no longer halts a
fleet-wide rollout.** A container created from inside another container — a
Portainer stack, for instance — records a directory that exists only in whatever
deployed it. Trying to update one produced the shell's own error and stopped every
remaining host. The directory is checked before it is entered now, the message
says what kind of thing it is and where to go instead, and the image is treated as
inapplicable rather than failed: nothing will make it work from here, so halting
everything else achieves nothing.

---

## v1.2.20 — 2026-09-12

**Every compose project on the fleet is now visible, and none of it needs setting
up.** The Containers screen listed only the compose files Provenance had taken a
copy of — and it takes one as a side effect of a rollout that needs it. So a
working deployment showed one row, or none, and read as an empty product with a
configuration task attached. In fact sixteen projects across seven hosts were
already discovered, in five different parts of the filesystem, because every
compose-managed container records its own project and directory. A Discovered tab
now lists them and is the default, and says plainly that updates work without
adopting anything: a rebuild is pulled and recreated in place, and a version
change takes a copy of the file by itself. A short Managed stacks list is the
normal state of a working deployment, not a backlog.

**A calendar version is no longer compared with a semantic one.** One repository
publishes both `2.8.3` and `2021.11.28`; every ordering rule passed and then 2021
was larger than 2, so a four-year-old image was offered as an upgrade over a
current one. Mixing the two schemes now reads "cannot compare". Dates still order
against dates.

---

## v1.2.19 — 2026-09-12

**A deploy no longer strands containers that share another's network.** A service
declared with `network_mode: "service:something"` has no network stack of its own
— it lives inside that other container's. Recreating the owner destroyed the
namespace and left every container attached to it running, reporting healthy, and
with no network at all. On one fleet a rollout that recreated a VPN gateway
stranded three containers behind it, including a torrent client that carried on
reporting "Up 35 hours" with no route out. A narrowed deploy now brings those
along. `depends_on` is not followed: that is start order, and a container whose
dependency restarts is not broken by it.

**A rollout detects an expired premise from what is actually running.** The
previous release compared against a host's adopted stack, which works only where
one exists — and the host this kept failing on had none. The arbiter is now what
the host is running, which the verification step already reads. A container still
on the tag the rollout was moving away from remains a failure: that is a deploy
which reported success and changed nothing.

---

## v1.2.18 — 2026-09-12

**A rollout no longer fails on an image the host has been re-pinned past.** An
"update all" is a snapshot of what the fleet was running; on a fleet somebody is
actively working on, that snapshot expires. One created while a service was on
:latest, reaching a host after that service had been pinned to a version,
deployed correctly and then failed verification against a tag no longer in the
compose file — halting the whole operation on its failure budget for something
nobody did wrong. The engine now checks the host's own compose first and skips an
image the file names at some other tag. Only a repository the file actually names
counts: a file that says nothing about an image tells us nothing about whether the
host moved past it.

---

## v1.2.17 — 2026-09-12

**A rollout no longer fails itself after succeeding.** The target digest was taken
from the updates row, which records what the *current* tag points at — the same
thing for a rebuild, and the old image's digest for a version change. So a
container that had been updated correctly was compared against the bytes it had
just moved away from, and the rollout reported failure for work it had done. The
server now resolves what the target tag points at rather than accepting it from
the caller.

**"Check registries now" now means now.** It ran the same pass as the scheduler,
twelve-hour freshness window and all, so pressing it after changing something —
the only reason to press it — re-asked nothing and reported success. The batch cap
still applies, since that one is about a registry's rate limit rather than
staleness, and a pass that could not cover everything says how many images are
still waiting.

**A verdict is no longer held after the facts change.** Images checked while
container digests were briefly not being collected were recorded as "built
locally", and the freshness window then held that answer for twelve hours after
the digests arrived — on one fleet, forty images out of forty-eight. An image with
no digest is now always re-checked, which costs nothing because it is answered
without asking a registry anything.

**The updates summary no longer counts two different things as one.** A newer
version and a rebuild at the same version are reported separately, so a count of
eight over a list showing one version number is no longer confusing.

**Support bundles: masking is now a choice.** Hostnames and IP addresses are
included as they are unless you ask for them to be masked, which suits a bundle
going to somebody who already knows the estate. Credential removal is not part of
the choice and always happens. With masking on, hostnames are replaced
consistently the way addresses already were — and the manifest names any hostname
that is also an ordinary word, since those are replaced wherever they appear.

---

## v1.2.16 — 2026-09-12

**Provenance can now produce a support bundle about itself.** There was one for a
managed host but none for the application, so reporting a problem meant knowing
which container to exec into and which table to query. Settings → Support bundle
gives one file: versions and cluster members, applied migrations, non-secret
configuration, scheduled job results, dependency health, a fleet summary, and
recent logs from every Provenance container. Nothing is stored on the server.
`provctl support-bundle` produces the same thing without the backend, since a
diagnostic tool that needs the thing being diagnosed to be healthy is not much of
one — and a source that cannot be reached is recorded in the manifest rather than
losing the rest of the bundle.

Hostnames are kept; IP addresses are replaced with placeholders from the ranges
reserved for documentation, and the same address becomes the same placeholder
throughout so that relationships between machines are still readable. The mapping
is unique to each bundle. Configuration is reported from a fixed list of
non-secret fields rather than from the environment, secrets as set or not set, and
free text is scrubbed for credential shapes. Generating a bundle is audited.

---

## v1.2.15 — 2026-09-12

**A deploy will no longer write a compose file that does not parse.** The
previous release stopped an adoption saving the command runner's trailing
"[exit code 0]" line into a stack's compose — but a stack already holding it
stayed broken, because the deploy writes the stored copy without looking at it.
Every retry rewrote the same unparseable file onto the host. The deploy now
validates with compose's own parser first and restores the previous file if the
new one fails, so a bad record fails the deploy rather than breaking the host,
and a migration cleans the records already stored.

---

## v1.2.14 — 2026-09-12

**A rollout no longer writes an invalid compose file to a host.** Every command
result carries a trailing "[exit code N]" line, and adoption took everything after
its marker as the file — so that line was swallowed into the compose content,
saved as the stack's definition, and written to the host, where it is not YAML.
The adopted content is now bounded on both sides, so anything appended afterwards
is ignored by construction, and a read that did not finish is refused rather than
written as half a file.

The end-to-end harness had the same gap: it ran scripts through a shell and
returned raw output, modelling the host faithfully while stubbing the runner —
and the runner is what broke. It now reproduces the runner exactly, which makes
five of its cases fail against the old parser.

---

## v1.2.13 — 2026-09-12

**A rollout can now finish a change it had half-applied.** When a compose file
has already been edited to the new tag while the container still runs the old one
— by hand, or by an earlier attempt that wrote the file and failed before
deploying — adoption asked only whether the file named the OLD tag, concluded it
was not the right project, and refused. It was the right project; the file was
simply already where the rollout wanted to get to, and the work left was to
deploy it. Every partially-applied change is in that state, including one a
rollout produced itself, so a rollout could not finish its own work.

**The rollout is now tested against a real Docker.** Four separate failures
reached an operator before a test, and all four were the same shape: a script, a
shell and a parser that are only correct together, checked by unit tests that fed
the parser hand-written strings. The container-update suite now runs the real
scripts and the real engine against a real daemon and a real compose project —
adopt, rewrite, deploy, verify, and the sequencing through all of it — as part of
the normal test run, skipping loudly where Docker is unavailable rather than
appearing to pass.

---

## v1.2.12 — 2026-09-12

**Container digests were being dropped on every bash host, and are not any
more.** The line that reported them used `echo` with a tab escape, which dash
expands and bash does not — so on most hosts it emitted a literal backslash-t,
the parser found no tab, and every digest was lost. Nothing failed; every
consequence was a silence. Rebuild detection compares digests, so rebuilds were
invisible. Container vulnerability scanning is keyed by digest, so it scanned
nothing. And an image with no digest is treated as built locally and never asked
about, so the updates page had nothing to show for any of them.

**Scripts run on a host now use sudo where the account has it.** A "privileged"
run means the connection lands in the host's privileged account rather than its
login-only one — sshd decides which account opens — but it never meant the
commands ran as root, and every script written for the container features assumed
it did. A rollout reported that a compose directory "is not there" when it was
there with exactly the file being looked for, under a home directory mode 700 that
the account could not traverse. The same applied to writing a compose file into a
directory owned by a deploy account, and to reading docker on a host where the
account is not in the docker group. Scripts re-exec under non-interactive sudo
when it is available and run unchanged when it is not, so a host whose account has
no sudo behaves exactly as before. Missing and unreadable are also reported
separately now, rather than both as missing.

---

## v1.2.11 — 2026-09-12

**Every image the fleet runs now has a row on the Updates tab.** It listed only
images a registry had already been asked about, and the check ran twice a day — so
a host whose containers had just become visible contributed nothing to the screen
for most of a day, with no row saying so. Twenty-four containers appeared on a
host and the page showed none of them. An image nobody has asked about now reads
"not checked yet" rather than being absent, and never "up to date", which is a
claim nobody has verified. The check also ticks hourly rather than twice a day; a
result still lasts twelve hours, so a tick where everything is current costs one
database query and no registry requests.

**An hourly inventory refresh no longer blanks the reason a host is not
reporting containers.** Writing the status unconditionally was right while that
statement was the only writer. Once containers moved to their own cadence it ran
without collecting them, so a refresh whose container check was not due wrote an
empty status over a real one — and an empty status renders as no container
section at all, so seven hosts looked like they had nothing to say.

---

## v1.2.10 — 2026-09-12

**Resume now actually retries.** It marked failed hosts as forgiven — which stops
them counting against the failure budget — but left them failed, and this engine
pushes, so a failed host was never picked up again. The rollout found nothing
pending, marked itself completed, and had updated nothing. Failed hosts go back to
pending now, with the forgiveness, error and attempt count cleared, so the budget
measures failures since the resume and a host whose cause has been fixed is not
refused for having used its attempts.

**Containers are collected using sudo where the account has it.** Six hosts of
nineteen reported that the monitor account could not reach the Docker socket, and
the advice was to add it to the docker group — which is root-equivalent, and a
strange thing to require merely to see what is running. Those accounts already had
passwordless sudo; the probe never used it. It tries unprivileged first, then
non-interactive sudo, and only then reports that it cannot look — naming both ways
out rather than only the group. The commands are read-only either way.

**The host filter is its own control.** Searching for a host name also matched
image names, so typing "docker" found a container on a different host entirely.
There is now a host picker listing every host reporting containers, which also
accepts typing to narrow it, and the text box searches images only. An empty
result says a filter is hiding things rather than looking like an empty fleet.

---

## v1.2.9 — 2026-09-12

**A rollout now restarts only the container being updated.** The stack deploy
brings up the whole compose project, which is right for a stack deploy and wrong
for a rollout: on a host where one project holds a model server, a vector
database, a speech recogniser and five other things, updating curl restarted all
of them. It also no longer passes --remove-orphans, because removing containers
the file no longer defines is a whole-project decision and making it as a side
effect of updating one image would delete things nobody mentioned.

**Provenance's own containers are shown but never updated this way.** Not only
its own images — those are built locally and already excluded — but the
third-party containers it is made of: the PostgreSQL holding its data, the Redis
holding its sessions, the guacd carrying its remote-desktop connections. Those
are ordinary registry images and were offered for update like any other, and
restarting the database under the running backend is the least bad thing that
would have happened. A rollout of them could not even report what it did, because
the backend running it is what gets restarted. They are upgraded from Settings →
Updates, by signed bundle, which verifies the signature, backs up the database,
applies migrations and keeps a rollback. They stay visible — what the instance is
running, and what is wrong with those images, is exactly what should be visible —
and carry an "upgraded by bundle" badge.

---

## v1.2.8 — 2026-09-12

**The upgrade page no longer waits forever for a result it stopped listening
for.** For the few seconds between starting an upgrade and the updater writing
its first line, the status file still holds the previous run's result. The page
stopped polling on any finished upgrade, so it stopped on that one — and the
check added in v1.2.5, which correctly refuses to announce a version the page did
not start, then had nothing left polling and waited for a result that could no
longer arrive. It showed "waiting for the updater" permanently while the upgrade
had in fact succeeded.

Fixed at both ends, because either alone leaves the window open. The page now
stops polling only on a result for the version it started. The server no longer
serves a finished result for a different version than the one it has just
started — it knows what it started, which is what makes that status the previous
run's rather than an answer. And after ten minutes with no result, the page shows
whatever the server does say and becomes usable again: a check that protects a
screen must not become a screen nobody can leave.

---

## v1.2.7 — 2026-09-12

**A version bump adopts the host's compose file instead of refusing.** A rollout
that had to change a version stopped with "adopt its compose file to make it
updatable" — correct, and a dead end: the operator was told to do by hand the one
thing the product is for. The file is now read off the host and recorded as a
stack, and the change applied as a normal revision with an author, a note and a
rollback. It refuses rather than guesses when the file is called something other
than docker-compose.yml (adopting would leave the original and put a second one
beside it), when it does not name the image being updated, or when the directory
is not there. Rebuilds still need nothing adopted. If your compose files are
deployed from a git repository or an rsync target, adopting one gives you two
sources of truth for the same file — reversible by deleting the stack.

**An upgrade status the updater never finished writing is now settled.** The
updater's last act in a successful upgrade is replacing the backend, so the run
that succeeds is the run that may not get to record it. Only terminal states were
aged out, so a "running" left over from a previous boot was reported as though an
upgrade were in flight. A status written before this process started describes an
upgrade that is over; if it was moving this instance to the version it is now
running, it worked.

---

## v1.2.6 — 2026-09-12

**Containers can be updated without adopting them first.** Every compose-managed
container records which project and service it is and where that project lives,
so a rebuild — the same tag republished on a patched base image — needs nothing
adopted: go to that directory, pull that service, bring it back up. A version
bump still needs a stack, deliberately: the new version is written into the
compose file, and editing a file Provenance does not own is reverted on the next
deploy for any host whose compose files come from a git repository or an rsync
target — silently, leaving the fleet on an image nobody can explain. Where a
stack is adopted it still wins; it is the definition of record and the one with a
history.

**Update all.** One rollout covering every image with something available,
instead of one rollout per image started by hand. That was not a cosmetic
difference: ten separate rollouts each paced themselves, so a canary of one meant
ten hosts taking an unproven update at the same moment. One rollout paces the
whole operation, by host — a host takes every update that applies to it, then the
next host follows, so a host is either current or it is not rather than
half-updated across the fleet. An image a host does not run is not a failure, and
a host running none of them by the time its turn comes is marked skipped rather
than claimed as updated.

**A host that cannot be collected now says why.** "No access" reported that
something was wrong and nothing about what to do, and its two causes need
opposite actions: an account missing from the socket's group is a one line fix, a
daemon that is not running is a different problem. Six hosts on a nineteen host
fleet reported it with no way to tell which, and finding out meant an SSH session
per host. The probe now reports the socket, its group, the command that fixes it,
and the daemon's own error — and no longer hides the case where a daemon is
running but no client is installed for that account.

---

## v1.2.5 — 2026-09-12

**The Containers page no longer blanks after an upgrade.** An image no host runs
any more came back with `hosts: null` rather than an empty list, and one
`.filter` on that unmounted the whole app — a white screen on a page that worked
a moment earlier. It was not an edge case: upgrading this product replaces its
own containers, so the tags it just superseded keep their rows until the next
check pass prunes them. Every upgrade produced several, so the page broke right
after every upgrade. Fixed in the query, in the page, and behind a per-tab error
boundary, because the next null will be a different field. Those leftover rows
also said "up to date" — a claim about something you are running; they say
"no longer running" now.

**Install no longer needs clicking three times.** The status endpoint reports
the previous run until the updater picks the new job up, so the spinner appeared,
then vanished a poll later when the old run's result arrived, and the Install
button came back with nothing on screen to say anything was happening. It stays
in progress now until the server reports a result for the version this page
dispatched, and says it is waiting for the updater rather than echoing the last
run. A duplicate apply is refused with a clear message instead of returning
"applying" and being discarded out of sight — three upgrades were dispatched in
sixteen seconds, two of which did nothing but write audit rows.

---

## v1.2.4 — 2026-09-12

**Containers are collected on their own cadence.** v1.2.3 shipped container
detection inside the hourly host-facts refresh, which is gated on a timestamp
every host already had — so on upgrading, every host whose facts were still fresh
skipped container collection entirely. A 19-host fleet showed containers for
three of them: the three whose hourly refresh happened to fall after the upgrade.
Nothing failed and nothing logged it. Containers now refresh every ten minutes,
independently: a kernel version changes at a reboot, what a host runs changes
whenever somebody deploys, and a rollout picks its targets from that list.

**"Check now" said it would do something it cannot.** It re-asks registries about
images already discovered; it never reaches out to hosts. The empty state offered
it as the way to collect container lists, which is the one thing it does not do.
It is "Check registries now", and the page says so.

**Images built on the host are no longer reported as authentication failures.**
Docker records a repository digest only for images it pulled, so a locally built
one has none — including this product's own containers. A bare name resolves to
Docker Hub, the repository is not there, and Hub answers 401, which surfaced as
"this registry needs credentials" and would send you to configure credentials
that cannot help. On the host running Provenance that was ten rows out of
thirteen. They read "built locally" now.

---

## v1.2.3 — 2026-09-12

**Provenance can see containers.** Nothing in it knew a container existed:
vulnerability scanning reads the host's package database, so a machine running
twenty containers looked like a machine with almost nothing on it, and everything
inside those images was invisible. On a fleet whose `docker`, `ai`, `containers`,
`gitlab`, `grafana` and `prometheus` hosts are mostly containers, that is most of
the attack surface.

Running containers are now collected over the connection the monitor already
holds — hourly, without `sudo`, alongside bound sockets — and shown in host
details: name, image, resolved **digest**, state and ports. The digest rather than
only the tag, because a tag moves: "nginx:1.25" does not say which nginx:1.25, and
both vulnerability scanning and update detection need the answer rather than the
label.

Crucially, **"nothing is running" and "we could not look" are recorded
separately**. Docker's socket is root-owned and every monitor probe runs without
`sudo`, so a host whose monitor account is not in the `docker` group answers
nothing — and an empty list there would report a clean host for exactly the
machines carrying the most software. Host details says which it was, and what to
do about it.

This is the first half of managing containers rather than only observing them:
you cannot roll out an update to something you cannot see.

**Container images are scanned for vulnerabilities.** The same grype sidecar the
host scans use, keyed by image **digest** and deduplicated across the fleet: the
same image on twenty hosts is fetched and scanned once, because the answer is
identical. A digest's contents never change, so a result is re-scanned when the
vulnerability *database* moves — which is what turns a clean image into a
vulnerable one without anybody touching the image. An image that could not be
pulled records why, because that must never read as an image with no findings.

**Compose files can be held by Provenance and deployed to their hosts.**
Provenance holds the definition and writes a rendered copy to the host, so a
stack keeps running when Provenance does not — you lose the ability to change it,
not to run it. Every row shows both the revision that *should* be deployed and
the one the host last confirmed, because a tool that showed only the first would
report success for a deploy that never landed.

**Registries are asked what is available.** This is the half a renovate bot did,
without the half that opened merge requests nobody read. Two signals, reported
separately because they answer different questions: a newer version tag exists,
and the tag a host runs now points at *different bytes*. The second is the one a
version comparison can never see — a base-image security rebuild republishes the
same version number, so a tool comparing only version strings says you are
current while you run months-old bytes.

The ordering **refuses to guess**. Tags are compared only when their prefix,
suffix and component count all match, so `15-alpine` is never offered
`16-bookworm` and `v2` is never ordered against `release-3`. When tags cannot be
ordered the row says "cannot compare", not "up to date" — silence there reads as
an answer, and it would be the wrong one.

Registries are asked directly over their HTTP API, with no Docker daemon: an
anonymous token per repository, cached for the pass, and `HEAD` for manifests so
no body is transferred. Rate limits are the binding constraint — Docker Hub
counts per IP across every image the whole fleet runs — so a pass checks at most
40 images, results last 12 hours, and only the leader checks. A registry that
will not answer is recorded against that image and the pass continues.

**Updates roll out in stages, and a host counts as done only when it is running
the target.** Canary, soak, batches and a failure budget — the same rules image
rollouts obey, now shared code rather than a second copy that would drift.

Verifying against what the host is actually running is the point. When a tag has
moved, `docker compose up -d` finds it already present locally, starts the old
bytes again and exits zero; a rollout counting the exit code would march that
no-op across the fleet, report every host updated, and leave every host on the
vulnerable image. An update deploy pulls first, and every host is read back and
compared against the digest the rollout targets.

Compose files are edited line by line rather than parsed and re-emitted — a YAML
round-trip drops your comments, renormalises your quoting and reorders your keys,
burying a one-line tag bump in a diff nobody can review. Only exact
repository-and-tag matches move, so `nginx-extras:1.24`, `ghcr.io/nginx:1.24` and
`nginx:1.24-alpine` are all left alone when `nginx:1.24` is rewritten.

A host running the image outside a managed stack is **reported, not guessed at**:
recreating a container whose run configuration was never recorded would mean
inventing the parts nobody told us, and one that comes back missing a volume is
worse than one never touched.

Extracting the shared pacing rules surfaced a defect in them: `canary - flying`
ignores the canaries that already verified, so a canary of 2 started two more the
moment the first passed — three machines taking an unproven update where two were
asked for. Every existing test passed either way, because every one of them used
a canary of 1, where that branch is unreachable.

**New documentation:** [containers.md](./containers.md), covering all of the
above, in the in-app Help and answerable by Ask Provenance.

---

## v1.2.2 — 2026-09-11

**Installing a bundle now cleans up after itself.** This product is installed once
and upgraded by bundle from then on, so anything an install leaves behind stays
forever — nobody runs `docker image prune` on an appliance. Every bundle since the
first had been leaving its predecessor: a fleet upgraded since 0.70 was holding
**152 stack images across five components, 9.2GB**, 49 tags of the backend alone,
and the first sign of it was a disk-filling alert. An upgrade now removes the
images it superseded, keeping the version just installed and anything tagged
`:rollback` — the anchor it would revert to. Only images this product publishes,
and never with `--force`: Docker refusing to remove an image a container is using
is the backstop if the keep rules are ever wrong. It cannot clean up
retroactively; installs before this one still need a manual prune.

**A restart no longer signs you out.** The token refresh treated *every* failure
as "you are not signed in" — so being unable to REACH the backend was
indistinguishable from being rejected by it. Every bundle install restarts the
stack for a few seconds, and refreshing the page in that window showed the login
screen for a session that was valid the whole time. Only a definitive 401/403
ends a session now.

**Signing in again ends the session you are replacing.** Login created a session
and never looked at the one the browser already held, so signing in from the same
tab left the previous session alive: its cookie had been overwritten, so nothing
could reach it, but the server was never told and kept it valid for its full
lifetime. It is revoked now — on proof of ownership, requiring the browser to
present the refresh token whose hash that row stores, because without that check
it would be a way to end somebody else's session by naming it.

**An upgrade no longer announces the previous one's result.** The updater keeps
its last status on disk, so a finished upgrade still reads "success" days later —
and an upgrade dispatched now flipped back to that stale banner the moment
polling returned it. An operator was told "Upgraded to 1.2.0. Reload" while 1.2.1
was still installing, and reloading into the middle of the restart is what
produced the sign-out above. A success is only announced if it names the version
that page dispatched.

**Active sign-ins can be searched** by username, display name or address. Filtered
in SQL rather than in the browser: the endpoint returns at most 200 rows, so
filtering afterwards would search only the page that came back and could miss the
person being looked for — which is the failure the search exists to prevent.

---

## v1.2.1 — 2026-09-11

**Active sign-ins listed SSH recordings instead.** `GET /sessions` already
belonged to the session-recordings API, and the new browser sign-ins screen
registered it a second time. That does not fail: chi takes one route and the
other never runs. The recordings route won, so the panel showed recorded SSH
sessions as sign-ins — dozens of rows for one user, every device "unknown"
because a recording carries no user agent, and every row badged "no MFA" because
it carries no `mfaPassed` either. Three symptoms that all read as defects in the
sign-in data, and none of them were.

Moved to `/active-sessions`. Two different things in this product are called a
"session"; the path now says which one it means.

The tests that existed asserted the admin route was mounted and gated correctly,
which it was — a test can only see the module it reads. Route collisions are now
checked across every module, and the permission mismatch is part of why it
matters: whichever registration loses, its permission gate is not the one being
enforced.

---

## v1.2.0 — 2026-09-11

**Image options that cannot produce a working machine are now refused at build
time.** A *keep* is a carve-out from a *reset*, and two ways of writing one
produced a machine that looked healthy and was not: keeping a path that is
itself reset cancels the reset, so an update installs a new slot whose binaries
are never seen and reports success; keeping the package database leaves it
describing the other slot's image, so every later `dnf`/`apt` transaction
reasons from a package list that is not what is installed. Both fail the build
instead. A keep containing a file the image ships is refused as well, checked
against the built tree rather than a list of known-safe paths.

Encryption options that would have been silently ignored are refused too.
`--unlock`, `--luks-passphrase`, `--tang-url` and `--tpm2-pcrs` only ever applied
on an encrypted image; asking for TPM unlock and forgetting `--encrypt` produced
an unencrypted disk with no indication the flag had been dropped. Options
belonging to one unlock method given with another are refused for the same
reason.

`build-image.sh --check-only` validates the options and builds nothing, and the
build dialog applies the same rules as you type.

Three related bugs are fixed: `--keep-path`/`--reset-on-update` were silently
discarded by the `stateful` and `appliance` models; the package-database paths
were added twice on `stateful` and redundantly on `appliance`; and the keep that
protects LUKS enrollment sat on the one model that never reset `/etc`, so it did
nothing there and was missing everywhere it mattered. Documentation described a
state model named `paths` that does not exist.

**Writable state is now reset when a slot's image changes, not when the slot
changes.** With a per-slot upper layer, booting the other slot and back cleared
state that nothing had invalidated — so the one thing `--slot-private-upper` is
for, each slot keeping its own state, was the thing it did not do. The machine
now keys on the slot's filesystem UUID, which changes when an update rewrites
that slot and at no other time. Slot-private path stores were being re-seeded on
every slot change too, and follow the same rule now; that applies to shared-upper
images as well.

**The audit chain can no longer be downgraded to a keyless one.** Each row records
which algorithm hashed it, so that rows written before the HMAC key existed still
verify. Verification trusted that column — and a party with database write access
writes it. Reading the tail hash, appending a row tagged as keyless and hashing it
with plain SHA-256 produced an event the chain reported as intact; the same move
rebuilds an entire tail, erasing what it replaces. That is the threat the keyed
chain exists to stop.

Keyless rows appearing after the chain was keyed are now reported, and reported
**separately from breakage**: such a row cannot be repaired — rewriting it means
rewriting every hash after it, the operation the chain exists to make impossible —
so folding it into "broken" would park an unfixable failure at the head of the
report and hide every genuine break behind it. `/audit/verify` returns
`weakFromSeq`, `weakCount` and a reason alongside `intact`.

**`provctl` now keys the chain it writes to.** It loaded the key and never
installed it, so every row it wrote used the legacy keyless hash — and its
commands are the most sensitive in the product: `create-admin`, `rotate-ca`,
`reset-mfa`, `enable-user`. It surfaced only as a warning that read like a missing
setting ("audit chain is UNKEYED") on deployments whose server had the key
configured all along.

**Root can now be granted for a bounded time instead of permanently.** `Host.Sudo`
decides which account a connection lands in — the privileged one or the host's
login-only account — and it was a standing permission with nothing else feeding
it. So the only route to root for a login-only user was an administrator adding
`Host.Sudo` to their role: fleet-wide, indefinite, and with nothing to take it
back. In practice that left two outcomes, both of which defeat the tier — either
operators hold sudo permanently, or they are granted it once and never lose it.

An access request can now ask for root as well, and an approver decides the two
halves separately: **Approve + root** or **Approve access only**. A granted
request is scoped to one host or group, expires on its own, and carries the
reason, ticket reference and decider the approval workflow already recorded.
Checked per connection, so an expiry actually ends root rather than only applying
to sessions opened afterwards; SFTP applies the same check, so a transfer is not a
way around either the restriction or the expiry. A grant lookup that fails denies.

**Active sign-ins are visible and can be ended individually.** Administrators
could see a user's login *history* and terminate *all* of their sessions, but had
no way to see who was signed in right now or to cut off one session — a laptop
left logged in somewhere meant signing that person out everywhere. Users →
Active sign-ins lists every current session with device, address and last
activity; terminating one closes any terminal open on it and revokes its
certificates rather than only marking the row revoked. Requires
`Session.Terminate`, the same permission the existing bulk action carries.

---

## v1.1.0 — 2026-09-11

Two gaps in what the scanners can see. Neither needed a new scanner: both are
answered over the SSH connection this already has.

**Nothing knew what a host was listening on.** Vulnerability scanning reads the
package database and reports which installed packages have CVEs; it has no way to
say whether any of it is reachable. A vulnerable library nothing has bound and
one serving on `0.0.0.0` produced identical findings. Bound sockets are now
collected with the host's other facts — hourly, over the connection the monitor
already holds, without `sudo` — and shown in host details as **exposed** or
**local**. Binding to one interface rather than all of them still counts as
exposed: treating it as safe is how a database ends up served to a network
somebody forgot was attached.

**Software outside the package manager was invisible to scanning.** The SBOM was
built purely from `dpkg`/`rpm`, so a `pip install`, an `npm install` or a vendored
dependency never reached grype — and that is where a large share of real
vulnerabilities live. A host could be reported clean while serving a Django with
a published RCE, because Django came from pip. Scans now enumerate Python and
Node packages in the directories those ecosystems install into and add them to
the same SBOM. Bounded on purpose — fixed locations, shallow depth, a result cap
— because it runs on every scanned host; measured at a quarter of a second on a
real one.

Two details that would each have made this silently useless:

- **PyPI names are normalised (PEP 503) before they become purls.** A dist-info
  directory is named `python_dateutil-2.9.0.dist-info`, while advisories use
  `python-dateutil`. Found on a real host. An unnormalised purl matches nothing,
  and a package that matches nothing looks exactly like a package with no
  vulnerabilities. npm names are deliberately left alone — that ecosystem is
  case-sensitive and does not normalise.
- **Ecosystem purls carry no distro namespace or architecture.** Those belong to
  the deb/rpm form; grype's pypi and npm matchers key on the bare shape.

Considered and rejected: adding OpenVAS or another network scanner. It duplicates
grype for the authenticated case with a worse false-positive rate, needs a
multi-gigabyte feed and its own stack, and fights the topology — every host here
is reached *through* the jump host, whose connection limits the monitor's own
fan-out cap exists to respect. If an unauthenticated outside-in view is ever
needed for evidence, that is the case for it, scoped to on-demand scans of
selected hosts rather than the fleet.

## v1.0.2 — 2026-09-11

**Deleting a host left its SSH host-key pins behind.** `ssh_host_keys` is keyed
by the text a host is dialled as — overlay address, management address, hostname
— because that is what the gateway holds when it verifies a key. No foreign key
reaches it, so nothing cascaded. Nine orphans were found on a deployment of
forty-three pins.

That matters because an overlay address is allocated by scanning
`hosts.wg_address` for what is in use, so deleting a host **returns its address
to the pool**. The next host enrolled can be handed it, present its own key, be
compared against the deleted host's pin, and be refused with

    host key for <host> does not match the pinned key
    (possible MITM, or the host was rebuilt — remove its pin to re-trust)

on a host that was never rebuilt and is not under attack — a message that sends
whoever reads it hunting an intrusion.

Deletion now removes the pins in the same transaction as the host. Existing
orphans are not cleaned up automatically: they are indistinguishable from a pin
for a host added back under the same name, and deleting trust records on a guess
is not something this should do by itself. Find them with the query in
[operations.md](operations.md).

## v1.0.1 — 2026-09-11

The three performance limits v1.0.0 documented rather than fixed.

- **The evidence pack loaded five whole tables to print fourteen numbers.** Every
  session, certificate, scan, finding and audit event in the window — with the
  audit detail JSON untruncated — materialised at once so the pack could call
  `len()` on them. The date range came from the caller and had no maximum, so
  `?from=1970-01-01` was a supported request. Counted in SQL now, from the same
  tables with the same filters, so the pack still cannot disagree with the CSVs
  it attaches. The window is capped at two years, clamped rather than rejected.
- **Command search could never use its index.** The query matches a term as
  full-text OR as a substring, on purpose, so both `systemctl restart` and
  `rm -rf` work — but Postgres cannot build a bitmap over an OR unless both
  branches are indexable, and `ILIKE '%…%'` is not without trigrams. So every
  search sequentially scanned `session_commands`, the table that grows by one row
  per command typed in every recorded session and has no retention path of its
  own. With pg_trgm the plan is a `BitmapOr` over two index scans; verified on a
  real database.
- **The monitor probed a host's three addresses one at a time**, each waiting a
  full SSH timeout before the next, inside a sweep capped at 16 workers — a cap
  that exists to protect the jump host and so cannot be raised. An unreachable
  host cost three timeouts of a slot instead of one. The dials now race and the
  first answer wins, turning the sum into the max; the overlay address still wins
  a tie, because reaching a host over the overlay is what proves the overlay
  works. Each probe also has a deadline now: the sweep's own context is the
  server's and had none, so a host that completed its handshake and then went
  silent held a worker slot indefinitely.

Also: an upgrade bundle is published with this release.

## v1.0.0 — Provenance — 2026-09-10

**First release of the combined product.** The version starts again at 1.0.0
because this is the first release of Provenance — one codebase that builds a
signed image, images a bare machine, enrolls it and then operates and updates it
for life. Nothing before this was ever published: no tag of this repository has
ever been pushed and no release has ever existed outside it.

The number was used once before, by [the August 2026
release](#v100-2026-08-05-a-compatibility-promise-and-the-dependency-audit-that-had-never-run)
of the SSH control plane this grew out of. That entry is still below, and the
tag now points here.

**The product is now Provenance.** Brand and Go module path only — every
`PROV_*` setting, binary name, `.provup` bundle, compose project, container
name and database object is unchanged, so nothing on a deployed machine has to
change because the product got a name. The container names in particular stay
`provenance-`: the Docker socket proxy's allowlist keys off that prefix to
decide what may be created, and renaming it would turn a security control into a
refusal to build anything.


### Updates that could never have worked

Four defects each left an A/B machine unable to update, and every one of them let the
machine image, boot and run perfectly first — rauc is used for nothing else, so
nothing failed until the first update was attempted.

- **rpm images shipped without the libraries rauc links against.** `dnf remove` of
  the build toolchain took `json-glib` with it, because rauc is built from source
  and rpm has no record that anything needs it. The build even verified rauc —
  *before* the cleanup that broke it. Verified after it now, fatally.
- **rpm images shipped without `tar`.** A bundle's payload is a tar archive, and
  `dnf --installroot` installs exactly what it is told. Updates failed at 99%,
  after a full download and a verified signature. The same family difference as
  the resolver: tar is Essential on Debian, so the deb path never had to ask.
- **A machine's old failure decided every subsequent rollout.** The agent
  remembers what it is mid-way through and keeps reporting it; it sends the
  rollout id alongside and nothing read it. So a machine that failed once failed
  every rollout afterwards, instantly, with `attempts=0` — and fixing the cause
  could not clear it.
- **Every enrolled machine dropped off the VPN on its first update.** Enrollment
  installs the overlay client with the package manager, into `/usr`, which is
  exactly what an update replaces. The config, certificate and key survive in
  `/etc`; the binary does not. Images now carry the client.

### Reaching machines that have moved

A machine is imaged on a provisioning segment and then moved. `PROV_CONTROL_URL`
tells it where the server lives afterwards — but setting it does nothing unless
something serves `/bundles/` at that address, and the provisioning listener is
bound to the imaging segment on purpose. `UPDATE_IP` switches on a second
listener for exactly this. Both are now documented; neither was.

- **Rollouts can target individual hosts**, not only a group or the whole fleet.
  The backend always accepted it; only the dialog was missing.
- **An enrolled host can be registered as an updatable machine** from its own
  page, reading its real slot and version over SSH rather than assuming them. A
  host with no machine record is invisible to every rollout including a
  fleet-wide one, and that is the way out.
- **Bundle builds take the LUKS passphrase from the vault** rather than asking
  for one the server filed itself fifteen minutes earlier.
- **Finished rollouts can be cleared.**

### Recovery keys you can still find

A machine's LUKS header is written once, at imaging time, and no update touches
it — so a machine keeps the passphrase of the image it was *imaged* from for
life, and its current version tells you nothing about which credential opens it.
Deleting a retired image's credential therefore destroys the only recovery key
for every machine imaged from it, silently.

Credentials now show how many machines depend on them, and the server refuses the
deletion while any do (`?force=true` overrides, audited separately). The
relationship needed no new data — machines already record the image they came
from — only for something to look.

### Security

- **Every client IP behind the proxy was being discarded.** The trusted-proxy
  list was used to decide both "may this peer set XFF" and "is this entry a
  proxy" — and it defaults to all of RFC1918, so every private client was
  classified as a proxy and thrown away. One shared auth rate-limit bucket for an
  entire organisation, and an audit log recording where requests were relayed.
  It was also spoofable in the case it existed to prevent. Replaced with a hop
  count, `PROV_TRUSTED_PROXY_HOPS`.
- **Audit IPs could be forged.** Four handlers read the left-most
  `X-Forwarded-For` entry — the one the caller writes — so any authenticated user
  could choose the address recorded against their Kubernetes exec, database query,
  SFTP transfer or ad-hoc command.
- **Two imaging routes skipped the access check their siblings enforce**, letting
  a host-group-scoped operator hold or delete a machine they cannot see.
- **Production refuses to boot misconfigured**: a localhost `PROV_PUBLIC_URL`,
  or `PROV_COOKIE_SECURE=false` while serving https. Both booted cleanly before
  and failed later, somewhere else.

### Performance and correctness

- `ListHosts` returned 100 rows when asked for 10000 — over-limit collapsed to the
  default rather than the maximum, so machines paired to hosts later in the
  alphabet rendered as unpaired.
- Manual vulnerability scans fanned out one unbounded goroutine per host.
- The session list scanned the whole recordings table on every page load.
- Indexes for the growth tables that were being sequentially scanned;
  `sftp_transfers` had none at all beyond its primary key.

### Fit and finish

- **The sidebar is grouped.** Thirty-five items in one flat list became seven
  sections. Two pages were also in the wrong place: `/security` is your own
  two-factor and passkeys, not fleet posture, and Approvals is a personal inbox.
- **A failed playbook alert names the hosts that failed**, rather than every host
  it ran against with ansible's exit code as the reason.
- **An `ab-update` playbook template**, with the parts that are easy to get wrong
  already decided — the reboot is opt-in, and a machine that returns on the slot
  it started on has *failed*, because that is GRUB falling back.

### Known and deliberate

- **Data retention ships off.** Turning it on would silently delete audit history,
  which is not a default anybody should inherit. Set `PROV_AUDIT_RETENTION` and
  `PROV_ACTIVITY_RETENTION` deliberately.
(The three performance limits listed here before release are now fixed in
v1.0.1.)

**Provenance is Provenance and Flipside as one program.** Not one product driving
the other over an API — one codebase, one database, one set of host groups, one
permission model, one audit log. That distinction is the whole of this release.

An imaging control plane on its own has to be a **pull**: a machine is imaged on
a private provisioning switch and then moved to wherever it lives, so the imaging
server never learns its address and cannot route to it. An operator who starts a
rollout can only wait. This server already reaches every enrolled host through
the jump host, so the pull stays — it is what makes a rollout work for a machine
behind a firewall nobody here controls — and reaching out becomes the fast path
on top of it.

The rollout engine decides everything: canary, soak, batch size, failure budget,
maintenance window, and the rule that a machine counts as updated only when it
comes back on the new version and healthy. Reaching a machine decides nothing —
a nudge makes it ask sooner, and the answer is the one it would have got on its
own timer. One set of rules governs a rollout however it was started.

**What that buys, concretely**

- **Rollouts target host groups** — the same groups access control and policy
  use, not a second set naming the same machines. A stale copy of "which machines
  are production" is how the wrong fleet gets an update.
- **A machine is its own record**, keyed by what the imager saw, with a nullable
  link to a host. A machine exists *before* it is a host, and that window is
  exactly where "imaged perfectly and never came back" lives — the failure the
  imager's own reports cannot cover, because the last of them is sent before the
  reboot.
- Pairing a machine to a host is recorded by an operator, never inferred from a
  hostname. Hostname matching works until somebody renames one, and then it
  silently re-points at a different machine.

**New**

- **Imaging** page: machines being written right now, the fleet's OS versions,
  rollouts with live progress, the image and bundle libraries, and builds.
- **Image building**, behind the `builder-runner` sidecar and the Docker socket
  allowlist. The backend never touches the socket: building means a privileged
  container that loop-mounts a disk, and that privilege does not belong in the
  process that also holds the SSH certificate authority. Opt-in —
  `make up-imaging`, or `docker compose --profile imaging`.
- Four permissions, split because they are different acts: `Imaging.View`,
  `Imaging.Build` (produces an artefact, reaches no host), `Imaging.Manage`
  (changes what a machine boots), `Imaging.Provision` (reconfigures a network
  segment). Everyone who could build before still can.
- A rollout halting on its failure budget is a notifiable event.
- SBOMs (SPDX + CycloneDX), optional Secure Boot and LUKS, PXE/iPXE imaging.

**Fixed, and worth naming**

- **A maintenance window that wrapped past midnight permitted updates at every
  hour of the day.** `22:00–04:00` fell through to "was yesterday an allowed
  day", which with no day restriction is always true — the exact opposite of what
  the window was set for, and invisible until a machine rebooted mid-shift.
- **The imaged and first-boot moments were written to nothing.** Both were set by
  the imager endpoints and named in no SQL statement, so the only record that
  answers "did the machine come back" was silently discarded.
- An observation read off a host no longer blanks an update state it never
  claimed.

**Configuration.** `PROV_CONTROL_URL` is the one to get right: the address
machines **in the field** reach this server on, routinely not the address a
browser uses. Also `PROV_ARTIFACT_DIR`, `PROV_AGENT_INTERVAL`,
`PROV_AGENT_TOKEN`, `PROV_IMAGING_NUDGE`, and — only if you build here —
`PROV_BUILDER_RUNNER_URL` with a matching `PROV_BUILDER_RUNNER_TOKEN`. All are
in `.env.example`.

**Not shipped:** there is no Kubernetes manifest for the builder, deliberately.
See [deployment.md](./deployment.md).

### Encrypted builds generate and file their own recovery passphrase

An encrypted build needed a passphrase typed into the dialog, which meant it then
lived wherever the person who typed it put it. It is now generated — 256 bits — and
**filed before the build starts**, with the build refused if it cannot be stored.
Storing afterwards would mean a failed write had already produced an encrypted
image nobody holds the key for, which looks exactly like a success.

- **External secrets manager when one is connected** (Vault KV v2 or AWS Secrets
  Manager), under `PROV_IMAGING_SECRET_PREFIX`; **Provenance's own credential vault
  otherwise**, sealed at rest. Either way a credential record is created, so it is
  found the same way in Credentials — an external-backed record carries a
  reference rather than a sealed blob.
- `extsecret.Provider` gained an optional `Writer` half. Reading and writing are
  different trust levels, so a deployment that only brokers existing secrets is
  still asked for nothing more than a read-only token; callers fall back to the
  local vault when the provider cannot write.
- **Neither backend overwrites.** Vault writes with `cas: 0` and AWS uses
  `CreateSecret`, so a name in use is refused. The value that would be destroyed
  is the only copy of a recovery key for machines already in the field.
- The **image name is settled by the backend** before the build, because the
  secret is filed under it. It reads the same output directory the image library
  comes from and passes the name explicitly, instead of letting the builder pick
  one the backend cannot see until the build is already running. The sidecar's
  build model now accepts `name`/`replace`, which `resolve_output_name` always
  read but `extra="ignore"` silently dropped.

### The imaging keys have a backup page, and the key stays on the host

The RAUC signing key, the MAC→hostname assignments and the provisioning stack's
configuration are files, not rows, so the encrypted database backup does not and
cannot contain them. There was a script and no page.

**Imaging → Keys** shows what exists and what does not, writes an archive, and
lists what is in one. It says plainly when there is no signing key at all —
because if this server ever had one, a backup taken now would not contain it, and
machines already deployed accept only bundles signed by the original.

**The archive is written on the server and stays there.** There is deliberately
no download: a signing key fetchable over HTTP is one whose custody is whoever
holds a session cookie, and losing this key means no deployed machine can ever be
updated again — not "until we re-key", ever, because each verifies against a
certificate baked into its own image. Copy it off with `scp`, as a decision
rather than a click. Inspecting an archive returns entry *names* only.

**Restore is not here either**, and that is not an omission: the moment you need
it is the moment this server is not running, so it stays as
`scripts/imaging/imaging-keys-backup.sh restore` on the host. A button that only
works when you do not need it is not a recovery procedure.

Also raised the minimum root slot for the RPM family from 2560 MiB to 5120. It
was inheriting Debian's floor, and the RAUC build installs a whole toolchain into
the slot before removing it — transient, but it has to fit. A 3 GiB slot ran out
partway through and failed as "No space left on device": a true message about the
wrong thing.

### Images and their SBOMs can be downloaded

The Images tab showed "N packages" for an image with a bill of materials and gave
no way to get it, and no way to take a copy of the image either. Both were
Flipside endpoints with no counterpart here.

Served by the backend straight from the output directory — no sidecar
round-trip, so they work when the builder is not deployed — and streamed rather
than buffered, because an image is several gigabytes and reading one into memory
to hand it to a browser is how a backend with plenty of memory runs out of it.

Gated on `Imaging.View`, not `Imaging.Build`: reading an artefact is not producing
one, and whoever has to hand an SBOM to an auditor is not necessarily allowed to
start a build.

The name comes from a URL and ends at `os.Open`, so it is refused unless it is a
plain image filename that resolves inside the output directory. `filepath.Base`
alone would not do: it turns `../../etc/shadow` into `shadow` and serves whatever
happens to have that name. The directory also holds the RAUC signing key and the
provisioning server's env file, so the route serves images and nothing else.

### The build dialog exposes every option the builder takes

An audit rather than another single fix. `build-image.sh` accepts 40-odd flags;
the sidecar modelled them, the Go layer forwarded them, the API client typed
them — and the dialog sent **twelve**. Everything else was reachable only from
the API, which is not a feature anybody has.

Added: **image name**, **image and root slot size**, **compression**, **desktop
environment**, **SSH key-only**, **customization script**, and the whole
**writable-state** section — model, per-slot upper layer, and all six path
directives (persist, slot-private, volatile, reset-on-update, keep, own).

Paths must be absolute and the dialog now refuses to submit otherwise. The
builder *silently skips* a non-absolute path, so a typo was a setting that looked
accepted, was not in the image, and would be discovered on a machine.

docs/imaging.md now carries the flag-to-control table, so the next flag added has
somewhere obvious to be listed — and something to be checked against.

### The bootstrap no longer depends on the builder's own distribution

Three failures in the same step, each hidden behind the last.

- **`Couldn't open file /etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-10`.** The release
  package puts its keys inside the installroot, but the repo definitions
  reference them as `file:///etc/pki/rpm-gpg/...` and dnf resolves a `file://`
  URI against the **builder's** root. They are now copied out so the URI
  resolves, and imported into the installroot's rpmdb so packages are actually
  checked against them. My earlier check built Rocky 9 on a Rocky 9 builder,
  where the key happened to exist on both sides — which is why this got through.
- **`No match for argument: almalinux-release`.** A Rocky builder has no such
  package. The bootstrap now defines its own repository with `--repofrompath`
  pointing at the *target* distribution's mirror, so the builder's own
  distribution decides nothing about which distributions it can build.
- **`nothing provides almalinux-repos`.** AlmaLinux splits repository
  definitions out of its release package; Rocky ships them inside. Installing
  only the release package left an installroot with a distribution identity and
  no repositories to install the distribution from.

Verified from one Rocky builder: AlmaLinux 9.8, Rocky 9.8 and Rocky 10.2 all
bootstrap and complete their GPG-verified second transaction. Verification is
real rather than nominal — with the wrong key in place, that transaction is
refused.

### Formatting probes what mke2fs knows instead of assuming

A Rocky build died at *Formatting filesystems* with
`Invalid filesystem option set: ^orphan_file,^metadata_csum_seed`.

Those two features are disabled deliberately — older GRUB cannot read them, so
`grub-install` fails with a bare "unknown filesystem". But the list was written
for Debian trixie's e2fsprogs 1.47. Rocky 9 ships **1.46.5, which predates
`orphan_file` entirely**, and mke2fs rejects a feature name it does not
recognise. So "make the image readable by older tooling" became "cannot format a
filesystem at all" on precisely that older tooling.

Each feature is now probed with `mke2fs -n` against a throwaway sparse file and
kept only if this mke2fs knows it. A feature it has never heard of is one it also
cannot enable, so dropping it is not a compromise — the reason for disabling it
does not exist there. Debian selects both, exactly as before; Rocky selects
`metadata_csum_seed` alone. Verified on both.

Also: `glibc-gconv-extra` in the RPM builder. RHEL 9 split the CP850 iconv
converter out of glibc, so every `mkfs.vfat` printed two "Cannot initialize
conversion from codepage 850" lines and fell back to an internal table — harmless
in itself, and exactly the sort of expected noise a real error hides behind three
hundred lines later.

### RPM images build in an RPM builder

A Rocky build partitioned the disk, set up LUKS, formatted, mounted — and then
died on `dnf: command not found`, twenty minutes in, at the first step that was
actually distribution-specific. `build-image.sh` had grown an rpm family and the
orchestrator was still running the Debian builder for every build.

- New `builder/Dockerfile.rpm`, a Rocky-based builder. Separate rather than
  adding dnf to the Debian one: Debian does package dnf, but pointing it at a
  RHEL release with that rpm and those GPG keys is the fragile path, and it fails
  exactly where the old one did.
- Selected by **tag** (`debian-ab-builder:rpm-amd64`), not a new image name. The
  socket proxy already matches `debian-ab-builder` with any tag and allows it
  privileged; a new name would mean widening that allowlist for an image the
  repository already builds itself.
- Bundle building stays on the deb builder, whatever family the image came from:
  it signs with `rauc`, which is a package there and is **not packaged at all**
  for the RPM family.
- **No `qemu-user-static` in the RPM builder**, and none is needed — it is not
  packaged for this family, and the host's binfmt registration uses the `F` flag,
  which opens the interpreter at registration time so containers execute foreign
  binaries without the emulator inside them.

16 tests, including a cross-check that the orchestrator's list of RPM
distributions still agrees with `build-image.sh`'s own `FAMILY` case — they
disagree only when somebody adds a distribution to one and not the other, which
is precisely how this broke. `make imaging-test` mounts the repo root so that
check can see both sides; a cross-check that cannot see the other side is a test
that cannot fail.

### AlmaLinux and Rocky are selectable in the build dialog

The builder has understood them for two releases; the dropdown still offered only
Debian and Ubuntu, so the only way to build one was the API.

The **release field follows the distribution**. Switching to Rocky and leaving
`trixie` in the box is a build the builder refuses, and the reason would arrive
minutes later from a container — so the suite changes with the choice, and for the
RPM family it becomes a list (8/9/10, the closed set the builder validates
against) rather than free text. The wrong answer is unreachable instead of merely
discouraged.

Choosing one also says, in the dialog, that RPM images have not been booted on
real hardware yet — before a twenty-minute build rather than after it.

### The A/B root boots under dracut, so RHEL images are buildable

The RPM family could bootstrap, install packages and build RAUC, but the A/B root
itself was initramfs-tools scripts with no dracut equivalent — so the build
refused rather than produce an image that boots read-only with no rollback.

The two boot scripts are now **shared between both harnesses** rather than
reimplemented. They moved to `/usr/lib/ab/initramfs/`, and one line reconciles the
only difference that reaches them: initramfs-tools calls the mounted root
`$rootmnt`, dracut calls it `$NEWROOT`. New dracut modules `90ab-overlay`
(`pre-pivot`) and `91ab-luks-key` (`initqueue/settled`) install them, the way the
`hooks/` scripts do on the other side.

- `initqueue/settled` for the key because `pre-trigger` is too early (no devices
  yet, so the `blkid` that finds the BOOT partition finds nothing) and
  `pre-mount` too late (the unlock is what the initqueue is already waiting for).
- The build now **checks the generated initramfs actually contains the hook** and
  fails if not. dracut does not error when a module it was told to add
  contributed nothing.
- Verified against real dracut on Rocky 9: both modules are discovered, an
  initramfs generates, and the hooks land at `pre-pivot/90-ab-overlay` and
  `initqueue/settled/10-ab-luks-key` with `rm`, `cp`, `blkid` and `mount` present.
  The Debian harness was re-checked with the shared scripts in place.

RPM builds now proceed, with a build-time note that no such image has been booted
on hardware yet — both failure modes are recoverable (a passphrase prompt, or a
read-only root, which `ab.state=off` does on purpose) rather than a machine that
will not start.

### Cross-architecture builds fail with the reason, and can be enabled

An arm64 imager build died with `exec format error` inside a Dockerfile `RUN`.
The cause was four hundred lines earlier: the socket proxy refused
`tonistiigi/binfmt`, which registers the qemu interpreter, and the build **warned
and carried on** into a failure that says nothing about binfmt.

- The build now **aborts** when no interpreter is registered, naming both
  remedies. It checks the **host's** registrations first — through a read-only
  bind of `/proc/sys/fs/binfmt_misc` at `/host/binfmt_misc` — so a host that
  already has them, as Debian's `qemu-user-static` does permanently, skips the
  step and needs no exception at all. The bind is required rather than tidy: a
  container's own view of that directory is empty whatever the host registered,
  so without it the check refused to build on a correctly configured host.
- Automatic registration is now available but **off by default**
  (`BINFMT_ALLOW=1`, with `BINFMT_IMAGE` pinnable to a digest). It stays off by
  default because it means running a third-party Docker Hub image as host root,
  and everything else the proxy permits is built from this repository.
- Enabling it also permits pulling exactly that image and nothing else.
  `/images/create` is otherwise absent from the proxy's rules on purpose, and
  without this the setting would have failed at the pull instead of the create —
  looking applied while doing nothing.

### Encrypted images can say how they unlock

`--unlock` has always taken `passphrase | keyfile | tpm2 | tang`, the sidecar has
always passed it through, and the API client already had the field — the build
dialog just never offered it, so every encrypted image was built with the default
keyfile whether that was wanted or not.

The dialog now asks, and says what each choice costs: `keyfile` boots unattended
anywhere but keeps the key in an unencrypted initramfs; `tpm2` seals it to the
machine; `tang` needs the network it was enrolled against; `passphrase` cannot
reboot unattended at all, which makes it the wrong choice for anything a rollout
manages. Tang additionally takes its server URL, which the builder requires.

### The netboot imager can be built

`POST /imaging/builds/imager` existed, the sidecar's `/build/imager` existed, and
the API client already typed `"imager"` as a valid build kind — but nothing in the
interface ever called it. So the one artefact without which PXE cannot work at all
could not be built here, and the provisioning preflight told you to go and build it
on a page that had no such button.

- **Imaging → Images → Build netboot imager**, with an architecture choice. The
  imager is a kernel, so an amd64 one cannot boot an arm64 machine however it is
  served; both can be built and neither interferes.
- The Images tab now shows which architectures have an imager, and says so plainly
  when none do — instead of leaving it to be found in the provisioning preflight
  after a network has been chosen and Start pressed. `GET /imaging/images` gained
  `imagerArches` for it, read from the artefact directory the same way the image
  library already is.

### The overlay takes uploads, including binaries and whole folders

The Overlay tab could only create and edit text typed into the browser. That was
not merely a missing button: the write path was `content: str`, so a certificate,
a compiled tool or a firmware blob — the things an overlay is *for* — could not be
put in an image at all.

- **Upload files, or a whole folder** with its tree kept beneath a chosen path.
- **Download** anything, including what the editor cannot open.
- **Rename/move** and **change mode**, which the sidecar has always supported and
  nothing exposed.
- Bytes travel **base64 in JSON**, in both directions and for every upload rather
  than only ones that look binary: a browser cannot know whether a file is UTF-8,
  and guessing wrong corrupts it silently. It also keeps the sidecar, the Go proxy
  and the browser on one contract instead of adding multipart to all three.
- 16 MiB cap each way (`MAX_OVERLAY_BYTES`). Uploads run one at a time, so the
  count is honest and a refusal stops the run instead of leaving a half-written
  tree with no indication of which half.

The mode is its own operation because **a browser cannot read a file's
permissions**: an uploaded folder of scripts arrives unexecutable, and `cp -a`
preserves that onto every machine built from the image.

### Provisioning and overlay files reach the UI

The imaging backend and its sidecar carried the whole provisioning API — pick an
interface, configure the PXE stack, start it, target a MAC at its own image, edit
the overlay — and none of it had a page. `Imaging.Provision` existed as a
permission that nothing in the interface could exercise.

- **Imaging → Provisioning.** One choice with everything else derived from it:
  which interface the machines are on. DHCP and TFTP bind to that NIC alone; the
  list marks the NIC carrying the default route as the main LAN, because a
  standalone DHCP server there competes with the one already on it. A NIC with no
  address gets a proposed free subnet (assigned at runtime only, so a reboot
  reverts it); one that has an address gets a lease range inside its own subnet.
  Status, preflight and configuration load together because they are individually
  useless. Per-machine images assign a MAC its own image — keyed on MAC because
  the machine has no hostname yet.
- **Imaging → Overlay.** The files layered into an image at build time, with their
  modes: `cp -a` preserves the mode, so a script that lands without its executable
  bit is a boot that does nothing.

**Fixed: the socket proxy refused the runner its own image, and the symptom was an
empty interface list.** Host NICs are enumerated by running a throwaway container
from the runner's own image in the host network namespace. The compose images were
renamed to `provenance-` and the proxy's allowlist was not, so that `docker run`
was denied, the orchestrator swallowed the error, and Provisioning offered nothing
to choose from and no reason why. The allowlist now covers both naming eras, and
the runner's `_self_image()` fallback no longer names a Flipside container that
does not exist here. Allowing it to *run* did not allow it to run privileged —
that stays confined to the builder and imager.

Deploying any of this needs the `imaging` profile (`docker compose --profile
imaging up -d`) plus `PROV_BUILDER_RUNNER_URL`, `PROV_BUILDER_RUNNER_TOKEN` and
`HOST_PROJECT_DIR`. Without them the build routes answer 501 and Provisioning has
no server to start — the deployment being incomplete, not the page being broken.

### The Vulnerabilities page leads with what can actually be fixed

Ported from Provenance v2.1.0, which shipped it separately; it belongs here too and
Provenance has not had a release of its own to carry it.

The roll-up was answering the wrong question. A fully-patched fleet rendered as a
wall of red — one host showed **1,646 CVEs, 86 critical, 461 high** — while the
only number that meant anything, **Fixable: 0**, sat in a small chip six columns
to the right. Nothing was miscounted: on a patched Debian host roughly 60% of CVEs
are `not-fixed` (acknowledged upstream, no patch shipped) and 40% are `wont-fix`
(assessed and deliberately not fixed), and severity comes from **NVD**, not from
the distribution — so "Critical, won't-fix" is normal. The page had no way to say
so, and the figures it made prominent were the ones that never change.

- **The roll-up splits into "Actionable now" and "Exposure (no fix available)."**
  Scans record their severity breakdown scoped to the **fixable** subset, so the
  table leads with fixable count, fixable critical/high and the worst *fixable*
  CVSS; raw critical/high move right and render muted. A headline banner states
  the fleet's position before any row is read.
- **"Max CVSS" is replaced by "Worst fixable."** The old column read 10.0 on
  essentially every Linux host — the worst NVD score of any CVE touching any
  installed package — so it sorted nothing and said nothing.
- **Kernel CVEs are attributed to the kernel.** Distribution trackers key on the
  **source** package, so every binary built from a source inherits that source's
  whole CVE list. Debian builds the kernel's userspace helpers — `cpupower`,
  `linux-headers-*`, `linux-kbuild-*`, `linux-libc-dev` — from the same `linux`
  source its tracker files kernel CVEs under, so the entire kernel CVE list was
  matched against a CPU-frequency utility: 227 of one host's 547 critical+high
  CVEs. The installed `linux-image-*` packages matched nothing at all, because
  Debian's signed images build from `linux-signed-amd64`, which the tracker does
  not key on. Findings now carry their source package; the drill-down groups on
  it by default, labels these findings `kernel`, and shows the host's running
  kernel beside the version grype actually matched.
- The Ask assistant's roll-up leads with the same columns and explains that a
  high critical count with zero fixable means there is nothing to patch.
- The SDK's `VulnScan` gains `fixable`/`wontFix` (previously missing entirely)
  and the four new fixable fields; `VulnFinding` gains `sourcePackage`.
  Automation should gate on `fixableCritical` rather than `critical`.

The migration is additive. Existing scan rows keep their values until re-scanned:
the fixable severity counts read 0 — which is also what a patched host reports, so
the roll-up stays honest — and findings show no source package, falling back to
the binary name for grouping. **Re-scan to populate them.**

The `PROV_*` names, the `provd`/`provctl`/`fleet` binaries, the `.provup`
bundle format and the container names are unchanged. The Go module path is now
`github.com/kforbus3/provenance`.

See [imaging.md](./imaging.md).

---

## v2.0.0 — Provenance — 2026-08-16

The product is now **Provenance**. Alongside the rename, this release closes every
blocker and security finding from the enterprise-readiness audit and adds the
hardening an enterprise deployment expects. It is the first release verified by
deploying the Helm chart to a real Kubernetes cluster, not just by rendering it.

**Action required for existing production deployments.** Two new secrets are
**required** in production and the backend fails closed at boot without them. Set
both before upgrading (generate each with `openssl rand -hex 32`):

- `PROV_AUDIT_HMAC_KEY` (≥32 bytes) — keys the tamper-evident audit chain.
- `PROV_ANSIBLE_RUNNER_TOKEN` (≥16 bytes) — authenticates the backend to the
  ansible-runner sidecar; set the same value on both.

Optional but recommended: `PROV_RECORDING_KEY` (≥32 bytes) encrypts session
recordings at rest. The `PROV_*` variable names, the `provd`/`provctl`/`fleet`
binaries, and the `.provup` bundle format are unchanged, so nothing else about an
existing deployment moves.

**Security.** Closed an LDAP account-takeover (a directory identity can no longer
bind onto a local-password account or the bootstrap super-admin). The audit log is
now HMAC-keyed and tamper-evident, binding sequence, timestamp, and tenant.
Multi-tenancy row-level security now covers the tables it had missed, with isolation
tests and a build-time guard against future gaps. Ansible hardening: the
inventory-injection RCE is closed, SSH host-key verification is restored, and the
backend authenticates to the runner. CSRF is enforced, HSTS and security headers and
WebSocket-Origin checks are added, session-watch is tenant-scoped, ABAC fails closed,
and the SSRF guard pins the validated IP at dial time. SAML Single Logout (SP- and
IdP-initiated) with an SP signing-key surface; session recordings (SSH and RDP) can
be encrypted at rest; SIEM forwarding gains TLS, auth, and a bounded retry queue.

**Scale.** Overlay addressing follows the configured subnet — a `/16`
(`PROV_WG_SUBNET`) lifts the old ~240-host ceiling to tens of thousands — and
allocation is race-safe. The host-list query is no longer N+1 (401 → 5 queries per
100 hosts), and the monitor sweep uses an adaptive cadence with configurable
concurrency.

**Deployment.** The default Kubernetes/Helm deploy now works, verified on a real
cluster: the backend runs unprivileged under `runAsNonRoot`, the frontend proxies to
the in-cluster backend Service, containers run read-only-root with the writable
mounts they need, and the chart ships all required secrets. A tag-triggered release
pipeline publishes signed container images to GHCR with SBOM attestations.

**Tooling & docs.** Go toolchain and vulnerable dependencies bumped (govulncheck
clean); `golangci-lint` and frontend `eslint` are now blocking, clean CI gates. The
documentation, the in-app help, and the Ask assistant's knowledge are updated for the
rename, the new configuration, and the new features.

---

## v1.6.1 — A fleet-wide upgrade could not finish inside its own budget — 2026-08-15

A weekly "apt dist-upgrade" across a 14-host group failed with **exit 124** and a recap
showing **zero failed and zero unreachable hosts**. Nothing was wrong with the fleet. A
playbook run was bounded at a hardcoded **30 minutes**, and the run is *sequential* across
its inventory: seven of those hosts took a new kernel, and each one added a reboot plus a
`wait_for_connection` on top of its own upgrade. The budget scales with host **count**, not
with per-host work, so the run was killed waiting for the last host to come back — 13 hosts
upgraded, the 14th left mid-reboot, and the whole run reported as a failure.

The bound was not raisable without editing the binary, which pushed operators toward
splitting a fleet into batches — trading one honest run for several that each hide a
partial picture.

- **`PROV_PLAYBOOK_TIMEOUT`** (default `30m`, unchanged) now bounds a playbook run, matching
  the existing `PROV_SCAN_TIMEOUT` shape. Raise it rather than batching a large fleet.
- **The run's ephemeral SSH credential is derived from the bound** instead of being fixed at
  45m. Raising the timeout past 45m would previously have expired the certificate underneath
  a run that was still legitimately in flight, killing it on authentication somewhere in the
  middle of the fleet and leaving hosts half-upgraded. Tests pin both ends.
- **Documented the hypervisor case** in `docs/operations.md`: rebooting a host Provenance runs on
  top of kills the run that asked for it, and the run is later reconciled as `interrupted`
  even though the upgrade succeeded. Defer that reboot past the end of the play
  (`shutdown -r +10`) and skip the wait — there is nothing left alive on Provenance's side to
  wait with.

## v1.6.0 — Ask was answering with no instructions at all — 2026-08-11

> **Note.** The `v1.6.0` git tag was later reused for the Provenance release of the
> same number (top of this file), under the same policy as `v1.0.0`, `v1.1.0`,
> `v1.3.0`, `v1.4.0` and `v1.5.0`: no inherited tag of this repository has ever been
> pushed — the remote carries only the Provenance line — so moving it breaks nothing
> outside a working copy. Verified with `git ls-remote --tags` before doing it rather
> than assumed. This entry is the release that originally carried the number and stays
> here as the record of it; its commit is `660432d`.

Asked for "the latest security scan result for each host", Ask replied with a chatty
preamble, asked which host, and then produced *vulnerability* counts. Told "I want the
security scans, not the vulnerability scans", it answered that it had no tool for
OpenSCAP results — while `recent_scans` sat in its tool list.

None of that was the model. Ollama defaults `num_ctx` to **4096** tokens and does not
error when a prompt exceeds it — it silently discards the oldest tokens. Ask's system
prompt plus its tool schemas are ~9,200 tokens, so on every single request the *entire*
system prompt was thrown away before the model saw it: no tool-selection guidance, no
"answer only what was asked", no follow-up rules. Measured against the live model, the
same question routes to the CVE tool at 4096 and to the scan tool at 32768.

- **Provenance now always sends an explicit `num_ctx`** (default 32768, floored at 16384,
  configurable as `numCtx` in the `assistant` setting and in **Settings → AI
  assistant**). `GET /assistant/status` reports the effective `contextWindow`, the
  `promptFloorTokens` the instructions cost, and warns when the selected model's
  trained context is shorter than what Provenance requests. A test fails the build if the
  prompt and tool schemas grow past half the default window.
- **Tool results are capped before they reach the model** (~24 KB, largest list
  trimmed, with the true total and an explicit "N of M" note). `audit_log` alone asks
  for 500 rows; an oversized result re-created the same truncation mid-conversation.
  The table shown to the user still carries every row.

With the instructions restored, the coverage gaps behind the rest of that exchange are
closed:

- **`compliance_scans`** — the latest OpenSCAP scan *per host*, with profile, score,
  pass/fail counts, and an explicit marker for hosts that have **never been scanned**.
  `recent_scans` is a recency-capped log and could omit hosts entirely; a host nobody
  has scanned is a finding, not an absence. The fleet-wide answer is built in code, so
  the list is never truncated or miscounted.
- **`scan_findings`** — the individual benchmark rules a host is failing, worst first,
  flagging rules whose remediation could sever Provenance's own access to that host.
- **"Security scan" is disambiguated deterministically.** It routes to compliance, says
  which kind it reported, and a correction ("not the vulnerability scans") now switches
  datasets instead of repeating the mistake.
- **`access_control`** — groups and their hosts, roles and their permissions, service
  accounts and API tokens, and access reviews.
- **`expiring_credentials`** — API tokens, vault credentials, passwords, CA keys and
  SSH certificates that are expired, expiring, stale or overdue for rotation.
- **`platform_status` gained** federation site link state and database replication
  role/lag; **`security_events` gained** behavioural (UEBA) anomalies.
- **"I have no tool for that" is now generated from the tool set**, not hand-written —
  the old sentence had already drifted and omitted compliance scans, which is exactly
  what got denied. A test fails if a tool has no catalogue entry, or is offered to the
  model without a dispatch case (which returned `unknown tool`).
- **Fixed a latent host-extraction bug**: "results for **the** security scans" parsed
  `the` as a hostname, so the tool answered "nothing found for host 'the'" — a false
  negative that reads exactly like a real empty result. Provenance-wide phrasings ("for each
  host") no longer collapse to a single host.

**Deploy note.** A 32k context window needs more VRAM for the KV cache than the 4096
Ollama was quietly using. If your Ollama host is tight, set a smaller `numCtx` in
**Settings → AI assistant** — but note that below ~16k the system prompt cannot fit
alongside the tool schemas, which is why that is the floor.

---

## v1.5.2 — A torn-down host cannot come back — 2026-08-11

v1.5.1 brought the tunnel down but left a working way back onto it. On a certificate
overlay the teardown reused the transport-switch retire, which renames `client.ovpn`
to `.prov-disabled` and **deliberately keeps** `ca.crt`, `client.crt` and
`client.key` next to it — so what was left in `/etc/openvpn/prov` was a complete,
valid config whose key material was intact. Pointing openvpn at it, or simply moving
it back, rejoined the overlay.

The server would accept it, too. It carried `client-config-dir` but no
`crl-verify` and no revocation of any kind, so it authenticated every certificate the
overlay CA had ever signed. Retiring a host removed its *pinned address* and nothing
more: it would have reconnected and been handed an address from the pool.

- **Teardown now purges instead of retiring.** A new `PurgeHostScript` stops the
  client and destroys the material it could reconnect with — everything Provenance wrote
  under `/etc/openvpn/prov`, including the renamed config — while `RetireHostScript`
  keeps its transport-switch behaviour, which is the case that legitimately wants the
  certificate kept. WireGuard is purged the same way: its config and private key are
  removed rather than set aside.

- **The overlay CA has a CRL, and the server verifies it.** Deleting a host with
  teardown revokes its client certificates, and the refreshed list is published to the
  jump host. Revocation is what makes a decommission final: wiping the host's copy
  does nothing about a key copied off it beforehand. Revocation happens before the
  host row is deleted, because `overlay_clients` cascades with it — the record lives
  on in a new `overlay_revocations` table that is keyed only by serial, mirroring how
  `cert_revocations` works for the SSH CA. The list is re-read per connection, so it
  takes effect without a server restart.

- **`scripts/prov-unenroll.sh` never touched `/etc/openvpn` at all**, so on an
  OpenVPN host neither path removed the credential. It now removes the client and its
  certificate material, and takes the WireGuard private key with it as well. It says
  plainly that it cannot revoke — only Provenance can.

**Deploy note.** The OpenVPN server config now carries `crl-verify`, and openvpn
refuses to start when that file is missing, so the CRL is written to the jump host
before the config that names it. The change lands on the next enrollment or overlay
provision. A WireGuard-only deployment is unaffected; nothing needs doing by hand.

---

## v1.5.1 — Teardown takes the tunnel with it — 2026-08-11

Two bugs in v1.5.0's host teardown, reported from a real decommission: the accounts
came off and the VPN stayed up and operational. Both ends were at fault, for
different reasons.

- **The teardown never touched the overlay.** It removed the sudoers grant, both
  accounts, the CA trust, the principal files and the sshd drop-in, and left the
  WireGuard interface running and enabled at boot — so a host deleted from Provenance kept
  a live tunnel onto the fleet's network with nothing on it that Provenance managed or
  audited. `scripts/prov-unenroll.sh` retired the transport from the start and the
  documentation described that behaviour for both paths, so the gap was invisible
  unless you read the generated script. The teardown now retires the host's transport
  — WireGuard, or a certificate overlay's client via its own retire script — as its
  last step, after the accounts are gone. An overlay this deployment cannot provision
  now says so loudly in `/var/log/prov-unenroll.log` instead of being skipped.

- **The jump-host half of the cleanup had never run at all.** `CleanupHostOverlay`
  dialed the jump host with a session id it generated on the spot
  (`uuid.New().String()`), which by construction has no credential in the identity
  vault — so every call failed the vault lookup before a packet was sent. It runs in a
  goroutine that only logs a warning, so nothing ever surfaced: **every host deleted
  from Provenance, in any version with this code, kept its peer on the hub.** That is why
  the tunnel in the report was not merely up but still handshaking. It now dials with
  a short-lived system certificate, like every other background path.

  If you have deleted hosts before upgrading, their peers are still on the jump host.
  Enrollment retires a stale claim inline when the same overlay address is reissued,
  so they self-heal as addresses are reused — to clear them sooner, remove the peers
  on the jump host directly.

- **A requested teardown now reports the jump-host half too.** With teardown ticked,
  the peer retirement runs synchronously and a failure is named in the UI alongside an
  unreachable host, rather than going to a log line. Deleting without teardown keeps
  the background best-effort behaviour.

---

## v1.5.0 (2026-08-10) — Host.Sudo means what it says

> **Note.** The `v1.5.0` git tag was later reused for the Provenance release of the
> same number (top of this file), under the same policy as `v1.0.0`, `v1.1.0`,
> `v1.3.0` and `v1.4.0`: no inherited tag of this repository has ever been pushed —
> the remote carries only the Provenance line — so moving it breaks nothing outside a
> working copy. Verified with `git ls-remote --tags` before doing it rather than
> assumed. This entry is the release that originally carried the number and stays here
> as the record of it; its commit is `3aa91e4`.

**Behavior change.** Running an Ansible playbook, applying OpenSCAP remediation, or
collecting a support bundle now requires `Host.Sudo` in addition to the permission
that already gated it. All three execute as root on the target and have no
unprivileged mode. The builtin Administrator role holds both permissions and super
admins hold everything, so a default deployment is unaffected — only a custom role
that granted one of those permissions while withholding `Host.Sudo` changes, and it
was getting root against the operator's intent.

- **The login-only tier could not connect at all.** A user with `Host.Connect` and
  without `Host.Sudo` is supposed to land in the host's no-sudo account. Its
  certificate deliberately omits the fleet-wide `fleet` principal — that omission is
  what makes *sshd*, not just the backend, refuse it the sudo account. But both SSH
  hops presented that same certificate, and the jump host trusts only `fleet`, so the
  connection was rejected before it ever reached the managed host. The two hops now
  present different certificates: the session (or system) certificate for the jump
  host, the tier's certificate for the managed host. Until now the only tier that
  worked end to end was the privileged one, which means terminal access has in
  practice been root access on every host — `Host.Sudo` is seeded to Operator as well
  as Administrator, so no builtin role connected without it.

- **Ad-hoc commands honour `Host.Sudo`.** The command runner dialed the privileged
  account for everyone, so a user denied `Host.Sudo` still got a root shell by typing
  `sudo` into a run. It now uses the same tier a terminal does, and records which tier
  the run used in the audit event.

- **A failed revocation push is no longer counted as a success.** Distributing the KRL
  discarded the result of the install command and incremented the pushed count
  regardless, so a host that never received the list — unreachable, tightened sudoers,
  read-only `/etc/ssh` — was reported as updated while it went on accepting the
  certificates that had just been revoked. Installation is now verified, failures are
  counted and logged per host, the API returns `hostsFailed` alongside `hostsUpdated`,
  the Certificates page shows it, and the background loop retries instead of
  short-circuiting on an unchanged KRL hash.

- **Deleting a host can now remove Provenance from the machine.** Deletion took the host
  out of the inventory and left everything enrollment installed in place: the `fleet`
  account with its `NOPASSWD` sudo grant, the login-only account, the trusted CA, the
  principal files and the sshd drop-in, on a machine Provenance no longer manages or
  audits. The delete dialog now offers **"Also remove Provenance's accounts and SSH
  trust from the host"** (`?teardown=true` on the API), **unchecked by default** —
  it is destructive, and on a host whose only administrative access was Provenance it is
  a lockout, so it stays a deliberate choice rather than a side effect of tidying the
  inventory.

  Only what Provenance wrote is removed; `authorized_keys`, other sudoers files, and any
  sshd configuration Provenance did not write are untouched, and sshd is reloaded only if
  `sshd -t` still passes — a host whose remaining config is broken keeps the sshd it
  is running. The work runs detached on the host, because it deletes the account its
  own session is using, and the API reports that teardown *started*. A host Provenance
  cannot reach is named in the UI rather than silently skipped, and
  `scripts/prov-unenroll.sh` does the same cleanup locally on the machine.

**Known gap, unchanged:** `Schedule.Manage` can schedule a playbook run without
holding `Playbook.Run`. It is admin-only by default; treat it as equivalent when
composing custom roles.

---

## v1.4.1 — 2026-08-09

Follow-ups to v1.4.0, both found switching a real host between overlays.
No deploy note: this one is a plain bundle install.

- **Retiring the OpenVPN overlay takes its firewall rules with it.** Switching a host
  back to WireGuard stopped and disabled the client and set its configs aside, but left
  the peer-isolation chains on the host. They are scoped to the tunnel device, so once
  that device is gone they match nothing — but `tun0` is a name the kernel reuses, so
  the next VPN the host runs would inherit a DROP naming a jump host it has never heard
  of, and an operator auditing the host finds Provenance rules for an overlay Provenance no longer
  uses. The retirement now removes the jumps out of INPUT/OUTPUT and deletes the chains.

- **The enrollment progress dialog names the transport it is provisioning.** It said
  "Provisioning WireGuard and trust over SSH…" for every enrollment, including the
  OpenVPN ones — on screen, while the operator watched it happen — and the success
  banner said nothing about which overlay the host had landed on. Both now name the
  resolved transport, including what "deployment default" resolves to. The enrollment
  request still sends `""` for the default, so the backend remains the one that decides.

---

## v1.4.0 (2026-08-09) — One fleet, two VPNs, switchable per host

> **Note.** The `v1.4.0` git tag was later reused for the Provenance release of
> the same number (top of this file), under the same policy as `v1.0.0`, `v1.1.0`
> and `v1.3.0`: no inherited tag of this repository has ever been pushed — the
> remote carries only the Provenance line — so moving it breaks nothing outside a
> working copy. Verified with `git ls-remote --tags` before doing it rather than
> assumed. This entry is the release that originally carried the number and stays
> here as the record of it; its commit is `ead1030`.

**Deploy note.** The jump host publishes a new UDP port and mounts a new volume for
this release, and upgrade bundles do not manage the jump host. Run `make up-single`
on the deployment host after installing, and open `PROV_OVPN_PORT` (1194/udp) on the
firewall — otherwise the OpenVPN overlay runs on a port nothing reaches. Only needed
if you use, or intend to use, the certificate overlay; a WireGuard-only deployment is
unaffected.

- **Enrollment applies OpenVPN peer isolation instead of only writing it.** The `up`
  script is what installs the rules, and openvpn runs it only when a tunnel comes
  *up*. A re-enrollment almost never restarts the client — the unit is enabled and
  active, so starting it is a no-op — so the script was rewritten on every enrollment
  and applied on hardly any of them. A host that first connected without iptables, or
  under a build whose rules named the wrong jump address, stayed unisolated through
  every later enrollment with the script sitting unused on disk.

  Enrollment now runs it directly once the tunnel is confirmed, with `dev` set to the
  device holding the assigned address, and then reports what is actually in place —
  the script fails open by design, so "it ran" and "this host is isolated" are not the
  same claim.


- **OpenVPN enrollment installs iptables, on the host and on the jump host.** Peer
  isolation on this overlay *is* iptables — OpenVPN has no `AllowedIPs`, so a filter on
  the tunnel device is the only thing isolating a host at its own end, and a forwarding
  deny is the only thing isolating them at the hub. Both fail open when iptables is
  absent (a failing `up` script would abort the tunnel under `script-security 2`, and an
  unreachable host is worse than an unfiltered one), so a host without it joined the
  overlay silently unisolated with the only trace a line in its own OpenVPN log.

  Enrollment now provides iptables the same way it provides openvpn itself
  (apt/dnf/yum/apk), before the tunnel is started so the first connect is already
  filtered. If it still cannot be installed the enrollment succeeds — but the step
  carries a warning naming the host as unisolated, rather than reading identically to
  a host that is.

- **The overlay verification retries instead of deciding on one attempt.** Restarting
  the jump host drops every client tunnel, and OpenVPN's `persist-tun` keeps the
  device and its address on the host across that — so the host-side check passes on a
  tunnel with no data plane, and this dial is what notices. A single 12-second attempt
  in the reconnect window failed enrollments whose overlay was seconds from working
  and, because the WireGuard teardown is gated here, left those hosts on both
  transports. It now retries to a 90-second deadline, which covers the server's pushed
  `ping-restart`, and the failure says which of the two causes it is.

- **Host-side peer isolation is self-correcting when the jump address changes.** The
  rules name the jump host by address and were inserted straight into INPUT/OUTPUT:
  idempotent, but not self-cleaning. Moving the OpenVPN overlay onto its own subnet
  changes that address, and the rule left over from the old one matches everything
  from the new jump host — blackholing the tunnel with nothing logged anywhere. The
  rules now live in Provenance's own `PROV-OVPN-IN`/`PROV-OVPN-OUT` chains, flushed and
  refilled on every connect, so a stale address is retired as a side effect of writing
  the current one.

- **Enrollment no longer gives up on an OpenVPN tunnel that is still coming up.** The
  bring-up waited 20 seconds for the host's tunnel address, which is short: the first
  connect has to resolve DNS, hairpin through the router when the host shares the jump
  host's LAN, and survive openvpn's retry backoff after any attempt that lands while
  the server is restarting. Enrollments failed while the tunnel came up seconds later
  and stayed up — the worst outcome, since the operator is told it did not work when
  it did, and the WireGuard teardown (gated on the proof) is skipped.

  The window is now 60 seconds, and it waits for the address the server was told to
  pin rather than for any tun device, so a bring-up on a pool address — the ccd entry
  not applying — is still reported as the failure it is. The elapsed wait is reported
  either way.

- **The enroll dialog's endpoint port follows the VPN overlay you pick.** It was
  pre-filled from the WireGuard setting and stayed on `:51820` for an OpenVPN
  enrollment — while `ClientConfig` ignores that port entirely and always dials
  `PROV_OVPN_PORT`. So the field showed a port that was never used, and invited
  operators to hand-edit it to no effect. Selecting an overlay now rewrites the port
  to that transport's, keeping the host part; a port typed by hand survives
  everything except changing transport.

- **A host that cannot reach the OpenVPN server now says so.** The bring-up script's
  failure diagnostics ran under `set -e` and ended with `journalctl` — which exits
  non-zero for a unit that is merely inactive, killing the block before it printed
  anything. A failed enrollment showed `OVPN_HOST_NO_TUNNEL`, an empty log, and
  `Process exited with status 1`. The diagnostics are now insulated from their own
  exit statuses (the marker is the verdict, not the exit code), fall back to
  `systemctl status` when the client is managed by systemd and writes no log file,
  and report the endpoint the client was told to dial.

  The error explains the one thing that is never in the client's own log: its packets
  are not reaching the server. It names the port publish on the jump host (**a
  jump-host compose change needs `make up-single`, not `make redeploy-single`**), the
  firewall/router forward, and the case where a host on the jump host's LAN needs a
  LAN endpoint because the router will not hairpin a public one.

- **`make redeploy-single` warns when the jump host predates its compose file.** The
  target deliberately leaves the jump host running to avoid the overlay blip, so it
  cannot apply changes to its ports, volumes or entrypoint — which is how a
  deployment ends up running the OpenVPN server on a port the container never
  published. It now says so instead of finishing silently.

- **A host can be moved between the WireGuard and OpenVPN overlays by re-enrolling
  it, in either direction.** The per-host "VPN overlay" choice shipped before the
  machinery behind it did: both transports drew addresses from one pool, only one
  direction of teardown existed, and everything that reported overlay health asked
  WireGuard. Picking OpenVPN got you a host that was renumbered nowhere, still
  running WireGuard, and permanently reported as degraded. This is the rest of it.

  **Separate address plans.** `PROV_OVPN_SUBNET` / `PROV_OVPN_JUMP_IP` (default
  `10.101.0.0/24`, jump `.1`) now number the cert overlay's hosts. Both overlays
  terminate on the same jump host and each claims its own address on its own
  interface, so one shared subnet gave that host two connected routes for a single
  prefix — resolved once by the kernel, for the whole prefix — and every host behind
  the losing interface went dark. An install whose *default* overlay is already
  `openvpn` keeps `PROV_WG_SUBNET`, so an existing FIPS fleet is not renumbered
  underneath itself. Overlapping (but unequal) subnets are refused at startup.

  **Switching renumbers the host**, because its address cannot follow it across
  subnets. Enrollment resolves the address against the pool it is *joining*, and
  releases the SSH host-key pin held for the address it leaves — overlay addresses
  are recycled, and the next host to be given one would otherwise inherit a pin for
  the previous host's key and be refused every connection.

  **Both directions of teardown, gated on the same proof.** One entry point now
  retires whichever transport a host is leaving — WireGuard's interface and boot
  units, or OpenVPN's client and its pinned address on the server — and it runs only
  after a dial to the host's new overlay address **from the jump host** succeeds.
  Every other check in enrollment can fall back to the management address and pass
  over the LAN with no tunnel at all. Configs are renamed `*.prov-disabled` rather
  than deleted, and issued key material is left in place, so moving a host back does
  not need new credentials. If the new tunnel does not answer, the old transport
  stays and the step says so.

  **Deleting a host** now retires whichever overlay it was on. Previously it always
  removed a WireGuard peer, so an OpenVPN host left its pinned address behind on the
  server — answering for an address the next host could be given.

  **Everything that reported "WireGuard" now reports the host's actual transport.**
  The monitor's health probe asks the tunnel device for OpenVPN hosts instead of
  running `wg show` (which reported every one of them as permanently degraded); the
  offline/degraded alerts, the insight, the strict-overlay connection error, the
  status chips, the host-detail row and the enroll tooltips all name the transport
  the host is on and point at the right daemon on each end. `provctl fips check`
  prints both pools and counts the hosts still on the non-FIPS transport.

  **The UI shows the plan before you commit to it.** `/hosts/wg/next` reports both
  overlays' subnet, jump address, port and next free address; Settings lists them as
  a table, and the enroll dialog says which pool a host will land in — and, when the
  choice moves it, that it will be renumbered out of the address it has now.

  **Peer isolation covers the gap between the overlays**, not just within each: the
  jump host denies forwarding from either subnet to the other, so a host on one
  transport cannot reach a host on the other.

  Firewall: open **both** `PROV_WG_PORT` (51820/udp) and `PROV_OVPN_PORT`
  (1194/udp) on the jump host if any host uses either transport. Managed hosts always
  dial `PROV_OVPN_PORT` for OpenVPN, whatever port `PROV_WG_JUMP_ENDPOINT` names.

- **The OpenVPN overlay server was never started, and enrollment reported it
  healthy anyway.** `JumpServerScript` guarded the launch with `pgrep -f 'openvpn
  .*server.conf'`. Provenance runs these scripts as `sh -c "<the whole script>"`, so the
  script's own shell carries that exact command line in its argv — and `pgrep -f`
  matches command lines. The guard therefore always answered "already running", the
  launch never ran, and `EnsureServer` reported `openvpn server ready on jump host`
  for a server that did not exist. The Docker validation harness could not see this
  because it runs the script from a file, where argv is only the filename.

  Both guards (jump server and host client) now match on the process *name* and
  confirm the config from `/proc/<pid>/cmdline`, which cannot match the caller. The
  daemon also gets `--log-append`, and a failed start tails that log into the
  enrollment step — previously `--daemon` detached before the tun/bind work and its
  failures landed nowhere.

- **Enrollment onto a certificate overlay now has to prove the tunnel carries
  traffic.** Every check that should have caught the dead server passed:
  `configure_host_overlay` built its "OpenVPN tunnel up (addr …)" detail from the
  address Provenance *meant* to assign, off a host script that printed
  `OVPN_HOST_CONFIGURED` unconditionally after a fixed `sleep 2`; and
  `verify_certificate_login` falls back to the host's management address, so it
  passed over the LAN with no tunnel at all.

  The host script now waits for an address to actually appear on a tun device and
  reports what it observed, or reports `OVPN_HOST_NO_TUNNEL` with the client log. A
  bring-up at an address other than the assigned one is a failure too — that means
  the ccd pin did not apply. And a new `verify_overlay_tunnel` step dials the host's
  overlay address *from the jump host*, with no management-address fallback, because
  a check that can succeed without the overlay proves nothing about it.

- **The WireGuard teardown is gated on that proof.** Retiring the old transport on
  the strength of a step that merely reported ok is what took a host offline: it was
  moved onto an overlay that had never once come up, and lost the only tunnel that
  worked. The over-SSH path now retires WireGuard only after `verify_overlay_tunnel`
  passes; the no-install script joins the new overlay *before* retiring the old one
  (a failed join aborts the script with WireGuard untouched); and the finish step
  verifies the tunnel before removing the jump-host peer.

  A host whose cert overlay cannot be brought up now gets a failed enrollment and
  keeps the transport it had.

- **Deployment fixes without which the overlay could not work at all.** The jump
  host published only WireGuard's UDP port, so a host enrolled onto OpenVPN dialed a
  port nothing forwarded; `${PROV_OVPN_PORT:-1194}:1194/udp` is now published
  unconditionally (harmless when unused). `/etc/openvpn/prov` lived on the
  container's writable layer, so the overlay CA, server certificate and every
  per-host ccd pin would be destroyed by any upgrade — it is now on the `jump_ovpn`
  volume, and the entrypoint restarts a provisioned server on boot the way persisted
  WireGuard peers are already restored.

  **Known limitation:** the cert overlay still derives its subnet from
  `PROV_WG_SUBNET` and draws from the same address pool, so its server takes the
  address the WireGuard hub already holds on the same jump host. Running both
  overlays on one deployment is not supported; a mixed fleet needs a separate subnet
  for the cert overlay. With the verification above this now fails the enrollment
  rather than stranding the host.

- **Strict overlay mode named the wrong transport.** The connection error said
  "WireGuard address" whichever overlay the host was on, sending an operator to
  debug WireGuard while an OpenVPN server sat dead. It now names the host's actual
  overlay.

- **The no-install enrollment method honors the VPN overlay you picked.** Choosing
  **OpenVPN** in the enroll dialog and using **No install (ssh-pipe)** enrolled the
  host on **WireGuard** — silently, with no warning and nothing in the job log to
  say the choice had been dropped. The overlay reached only the over-SSH enrollment
  request body; the no-install flow fetches its script by URL, and that URL carried
  the endpoint but not the overlay. The script generator had no OpenVPN path at all,
  so it could only have produced WireGuard. A deployment whose *default* was
  `PROV_OVERLAY=openvpn` was affected the same way: every no-install enrollment
  came out on WireGuard.

  The overlay now rides the script URL (`?overlay=openvpn`), and the generator
  builds for it: Provenance issues the host's client certificate and pins its address to
  that certificate on the jump host while generating the script, then embeds the
  host-side bring-up in it. Because the tunnel authenticates as the identity Provenance
  just issued, there is no public key printed and nothing to paste back — the Finish
  step verifies certificate login instead of adding a peer. **The script is
  therefore a credential**: it holds the host's overlay private key. The copy-paste
  command already deletes it from the host after the run.

  Windows/RDP hosts are still WireGuard-only; `overlay=openvpn` is now rejected for
  them rather than silently falling back.

- **Switching a host from WireGuard to OpenVPN retires the WireGuard side.** Both
  transports address a host at the *same* overlay address (one `wg_address` column,
  so the gateway stays transport-agnostic), so a host re-enrolled onto OpenVPN ended
  up with two interfaces claiming one address — which answered came down to route
  metrics — while the jump host kept advertising the old peer for it. Re-enrolling
  onto a certificate overlay now brings the WireGuard interface down and disables its
  boot units on the host (the config is renamed to `<iface>.conf.prov-disabled`, not
  deleted, and the private key is left in place), removes the peer from the jump
  host, and clears the stored public key — which is what a standby jump host rebuilds
  its peer list from, so leaving it would restore the retired peer on the next
  failover. This runs only **after** the new tunnel is up: if that fails, the host
  keeps the transport it already had. Best-effort throughout, and reported as a
  `retire_wireguard` step.

  The reverse move (OpenVPN → WireGuard) re-provisions WireGuard but does not stop
  the OpenVPN client; take that down by hand.

- **OpenVPN overlays get the host-side half of peer isolation too.** v1.3.0 gave
  WireGuard hosts a second, independent layer (`AllowedIPs` pinned to the jump
  host) but left OpenVPN with only the jump host's forwarding deny — a single rule,
  on one machine, that fails open by design. Since OpenVPN exists here for FIPS,
  that left the most compliance-sensitive deployments with the weakest version.

  OpenVPN has no `AllowedIPs`, so enrollment now installs
  `/etc/openvpn/prov/peer-isolation.sh` and hooks it as the client config's `up`
  script: anything entering or leaving the tunnel that is not the jump host is
  dropped. Running on `up` is what makes it survive a reboot — a bare `iptables`
  rule does not — and what hands it the tun device name, which OpenVPN assigns at
  runtime.

  The rules are scoped to that device rather than the overlay subnet, because a
  subnet-scoped rule also matches the host reaching its **own** overlay address
  over loopback, which would break any local service bound to it. The config gains
  `script-security 2` (required for `up` to run at all); the script is root-owned,
  mode 0700, written before the tunnel starts so the first connect is already
  filtered, idempotent across reconnects, and always exits 0 — under
  `script-security 2` a failing `up` script aborts the tunnel, and failing open is
  the same choice made everywhere else in peer isolation.

  Follows `PROV_OVERLAY_PEER_ISOLATION`, and reaches hosts enrolled or re-enrolled
  after the upgrade.

---

## v1.3.0 (2026-08-08) — The overlay is a management network, not a flat one

> **Note.** The `v1.3.0` git tag was later reused for the Provenance release of
> the same number (top of this file), under the same policy as `v1.0.0` and
> `v1.1.0`: no inherited tag of this repository has ever been pushed — the remote
> carries only `v1.0.0` through `v1.2.35` — so moving it breaks nothing outside a
> working copy. Verified with `git ls-remote --tags` before doing it rather than
> assumed. This entry is the release that originally carried the number and stays
> here as the record of it; its commit is `a8e516e`.

**Deploy note.** Peer isolation is on by default and takes effect on upgrade. Read
the second entry before installing if anything outside Provenance relies on managed
hosts reaching each other over the overlay — `PROV_OVERLAY_PEER_ISOLATION=0`
preserves the old behaviour. Two further notes for existing deployments:

- The jump-host half lives in the **jump-host image**, which upgrade bundles do
  not manage (recreating it drops the overlay). It lands the next time the jump
  host is deliberately rebuilt; until then the host-side half carries the
  isolation on its own.
- The host-side half reaches hosts **enrolled after** the upgrade. Existing hosts
  keep their wider `AllowedIPs` and go on working; narrow them with
  `deploy/playbooks/overlay-peer-isolation.yml` (no tunnel downtime) or by
  re-enrolling.

- **Peer isolation is now enforced at the host end too.** The jump host's
  forwarding deny (below) is one machine's `iptables` — and it fails open with a
  warning on a jump host whose filtering Provenance does not control. A managed host's
  own WireGuard config now lists only the jump host in `AllowedIPs`, instead of the
  whole overlay subnet. In WireGuard that one value does two jobs: the host cannot
  *address* a sibling, and it **drops a decrypted packet claiming to come from
  one** — so a host stays isolated even if the hub-side rule is gone.

  WireGuard only; the OpenVPN client has no equivalent and relies on the jump host.
  Follows the same `PROV_OVERLAY_PEER_ISOLATION` switch, and applies to Linux and
  Windows enrollment alike.

  **Reaches hosts enrolled after the upgrade.** Already-enrolled hosts keep the
  wide `AllowedIPs` until re-enrolled, and a mixed fleet is fine — the two settings
  interoperate and the jump-host deny covers everything meanwhile. For operators
  who would rather not re-enroll a fleet,
  `deploy/playbooks/overlay-peer-isolation.yml` makes the change in place with **no
  tunnel downtime** (the live `wg set` needs no new handshake). It is idempotent,
  reverts itself if the jump host stops answering, and skips any config that is not
  a single-peer spoke, so it can be pointed at the whole inventory. The security
  guide also has the equivalent shell snippet for a one-off.

- **The overlay is hub-and-spoke now, not a flat network.** Managed hosts could
  reach each other over the overlay — ping, and just as easily each other's
  sshd/RDP/WinRM port. Every other control Provenance has exists so that reaching a host
  is brokered, authorized and recorded; the overlay was an unmediated path around
  all of it, handing the least-trusted component in the deployment (a managed host,
  running whatever it runs) direct L3 reach to every other host. It also undid at
  the network layer the separation multi-tenancy enforces in the database.

  The jump host now refuses to forward overlay traffic between two managed hosts,
  so a host can reach the jump host and nothing else. Applied when the WireGuard
  hub comes up and when the OpenVPN server is provisioned (FIPS mode), so it holds
  for both overlays. `PROV_OVERLAY_PEER_ISOLATION=0` turns it off for a deployment
  that genuinely needs hosts to talk to each other over the overlay.

  **On by default, including for existing deployments** — nothing in Provenance uses
  host-to-host reachability. Terminal sessions, SFTP, the health monitor, playbook
  runs (via `ProxyJump`), and the database and Kubernetes brokers all dial *from*
  the jump host, so none of them is a forwarded flow and none is affected. What
  changes is only what a host can do on its own behalf. If you have built something
  outside Provenance on top of host-to-host overlay reachability, set the variable to
  `0` before upgrading.

  A jump host with no usable `iptables` backend logs the failure and keeps serving
  rather than refusing to start — confirm with `overlay peer isolation ON` in the
  jump host's log.

- **Housekeeping.** Dropped a stale `react-router` advisory exception from the
  frontend audit allowlist; the advisory is no longer reported and the entry had
  become the kind of unaccounted-for noise that file exists to prevent.

---

## v1.2.0 — Which hosts are in this group, answered where you ask it

- **Host membership, from the group's side.** The Groups page could say whether a
  group was manual or dynamic, but not which hosts were actually in it — the only
  way to find out was to open each host's **Manage access** dialog in turn and read
  the answer backwards. Every group row now carries a **host count**, and **Manage
  hosts** lists the members (hostname, environment, owner, tags, enrollment) with
  add and remove in place.

  New endpoints: `GET /api/v1/groups/{id}/hosts` (`Group.Edit`), and
  `POST`/`DELETE /api/v1/groups/{id}/hosts/{hostId}` (`Host.Edit`). The mutations
  carry the same `Host.Edit` gate as the existing
  `/hosts/{id}/groups/{groupId}` routes, so neither direction is a cheaper way to
  change host access, and they return `409` on a rule-managed group exactly as the
  host-side routes do. Viewing needs only `Group.Edit`, so the listing returns
  identity fields — no addresses, overlay, or credential references.

  On a dynamic group the same dialog shows what the rule matched, read-only:
  checking a rule no longer means guessing from the host list.

  `GET /api/v1/groups` now includes `hostCount` per group. `fleet groups hosts
  <groupId>` and `Client.ListGroupHosts` cover the same ground from the CLI and SDK.

---

## v1.1.0 (2026-08-05) — Bills of materials, from data the scanner was already throwing away

> **Note.** The `v1.1.0` git tag was later reused for the Provenance release of
> the same number (top of this file), under the same policy as `v1.0.0`: no tag
> of this repository had ever been pushed, so moving it broke nothing outside a
> working copy. This entry is the release that originally carried the number and
> stays here as the record of it; its commit is `547c48f`.


- **Software bills of materials for every scanned host.** The vulnerability
  scanner already pulled each host's package database over SSH, handed it to
  grype and kept only the findings. The inventory itself is now retained and
  downloadable as a CycloneDX 1.5 document:
  `GET /api/v1/vuln-scans/latest/sbom?hostId=` for a host's current state, or
  `GET /api/v1/vuln-scans/{id}/sbom` for what a specific scan saw.

  "Give us a bill of materials for this system" is a compliance question — CMMC,
  FedRAMP, EO 14028 — and answering it needed a second tool, an agent, or a
  rebuild. Everything required was already being collected on the existing
  schedule; it was being thrown away.

  Linux components carry a **purl**, which names a distribution package
  unambiguously; Windows keeps the CPE it needs for its curated mapping. The
  Linux document lists **every** installed package rather than only the
  scannable ones, because a bill of materials and a vulnerability report answer
  different questions.

  No new agent, no rebuild, and one extra command per scan on the connection
  that was already open. Existing scans have no SBOM and return `404`; the next
  scan of a host produces one.

---

## v1.0.0 (2026-08-05) — A compatibility promise, and the dependency audit that had never run

> **Note.** The `v1.0.0` git tag was later reused for the first release of
> Provenance, the combined product (top of this file). *This* release was never
> published — no tag of this repository had ever been pushed — so moving the tag
> broke nothing outside a working copy. This entry is the release that originally
> carried the number and stays here as the record of it; its commit is
> `bda473b`.


The feature set has been past 1.0 for a long time; what was missing was a
commitment. From this release the version number is a statement about
compatibility rather than a running count.

- **[Compatibility, versioning and support](compatibility.md) is the contract.**
  What `/api/v1` guarantees — paths, methods, permissions, response shapes,
  authentication, permission names, environment variables, migration behaviour,
  bundle compatibility, enrollment surviving upgrades, the SDK and the Terraform
  provider. What is deliberately *not* covered: the UI, log-line text, unlisted
  metrics, the database schema itself, `internal/` packages, and the assistant's
  answers. Deprecation is announced in the changelog, kept working for at least
  two minor releases, and removed only in a major — with a runtime warning naming
  the replacement, so operators find out from their own logs.
- **Twenty reachable vulnerabilities are closed.** Nothing had been scanning
  dependencies. `govulncheck` reported sixteen reachable from Provenance's own code
  across ten modules, and four more in the Terraform provider that nothing had
  ever looked at. Among them: SQL injection via placeholder confusion in
  `jackc/pgx`, the driver every query and audit row goes through; acceptance of
  unsigned SAML `LogoutRequest`s and a signature bypass in the XML signing
  library, both in the SSO path; and a FIDO/U2F physical-interaction bypass plus
  five SSH issues in `x/crypto`, the library the gateway dials with.
- **A further twenty-nine came from the Go standard library**, because the
  toolchain was pinned to the module's floor version rather than a current
  release. The toolchain that compiles the binary is as much a dependency as
  anything in `go.sum`; every module now names a current one, and the images
  build on `golang:1.26-alpine`.
- **Tenant scoping reports why it failed.** The pgx upgrade deprecated
  `BeforeAcquire`, which is the hook that scopes every connection to its tenant
  for row-level security. It can only answer false, so a persistent failure to
  set the tenant GUC surfaced as "too many failed attempts acquiring connection".
  `PrepareConn` returns the error, so the query fails with the reason it could
  not be scoped.
- **The assistant no longer claims your data stayed home when it did not.** The
  settings page stated flatly that data never leaves your network; the URL field
  accepts any URL, so that held only by convention. Provenance now classifies where
  the configured Ollama actually is and warns when it is a public address. It
  classifies rather than blocks — a model server one rack over is legitimate.
- **CI enforces all of it**: `govulncheck` over every Go module, `staticcheck`,
  CodeQL over Go and TypeScript, Trivy over both images and the configuration,
  and an npm audit that fails at moderate and above unless an advisory is
  named in an allowlist with a reason and a review date. Weekly as well as per
  change, because an advisory can be published against a version that never
  changed. The build gained the race detector and a `gofmt` gate, and the
  frontend suite — which had never run in CI at all — now runs.
- **react-router 6 → 7**, closing an open redirect in `<Link>`/`useNavigate` and
  constructor injection in SSR hydration.
- `SECURITY.md` had claimed the current release was v0.1.0 and that v0.1.x was
  supported. It named the wrong versions for a long time; it now points at the
  support policy.
- Migrations: none.

### Upgrading

No configuration change is required. Two things to know:

- **Pre-1.0 releases are unsupported from here.** `0.x` made no compatibility
  promise, which is what this release changes.
- **If the assistant is enabled**, check Settings → AI assistant. A configured
  Ollama URL on a public address now raises a warning naming the host. This
  reports where your data is already going; it does not change where it goes.

---

## v0.71.1 — Jump-host rebuilds no longer leave the WireGuard hub mute

- **A jump-host rebuild no longer strands hosts that cannot be called.**
  Enrollment set each peer's endpoint at runtime, but only `PublicKey` and
  `AllowedIPs` were persisted, and the jump-host entrypoint stripped any
  `Endpoint` on restore. After a rebuild the hub could no longer initiate to any
  peer and could only wait to be called. Hosts whose own `wgprov.conf` carried a
  reachable endpoint re-handshook within about two minutes, which hid the
  problem entirely; a host whose configured endpoint was *not* reachable had
  been carried by the hub calling it, and went dark indefinitely. Observed in
  production as two hosts offline out of fifteen, with a healthy hub and nothing
  pointing at the cause. The hub-side endpoint is now persisted and restored.
- Migrations: none.

---

## v0.71.0 — Vulnerability roll-ups measure exposure, not package count

- **The Fixable column is meaningful again.** The scan sidecar kept grype's
  `fix.versions` but discarded `fix.state`, so "the distro assessed this and will
  never fix it" and "a fix exists and you are behind" both arrived as an empty
  `fixedVersion`. On a fully-patched `debian:12` that is 91 not-fixed, 63
  won't-fix and 0 fixed — so Fixable rendered "—" everywhere, hiding the useful
  fact (nothing outstanding) behind a four-figure total. Fix state is now carried
  through, and won't-fix is counted separately.
- **Counts are distinct CVEs, not CVE-on-package rows.** One source package fans
  out across many binaries (`glibc` → `libc6`, `libc-bin`, …), inflating every
  number. Against the same stock `debian:12` sample: total 154 → 72, critical
  7 → 6, high 17 → 13, medium 50 → 18, with 31 now shown as won't-fix.
- Migrations: `0070_vuln_fix_state.sql`.

---

## v0.70.5 — Reconciler can't fail its own live work; "interrupted" run status

- **A live instance can no longer mark its own in-flight work as orphaned.** The
  ownership reconciler (sessions, scans, playbook/script/command runs, enrollment
  jobs, dead-instance certificate revocation) now always excludes rows owned by
  the instance running the sweep — it is alive by definition. Previously a
  host-level stall (observed in prod: the hypervisor under the Provenance VM was
  itself mid-upgrade, starving the VM for minutes) froze the heartbeat goroutine
  past its 30s lease, and the next reconcile sweep declared the instance's own
  running playbook "orphaned" and failed it — while ansible was still running and
  went on to finish the job.
- **Runs cut off by a Provenance restart are now "interrupted" (amber), not "failed"
  (red).** A playbook that reboots the machine hosting Provenance itself can never
  report completion — the ansible process dies with the host. Such runs now end
  as `interrupted` with the explanation "Provenance restarted mid-run — the run was
  cut off and its result was not collected; the target hosts may still have
  completed their tasks", and Ask explains the status the same way. Retention
  prunes interrupted runs like completed/failed ones.
- Migrations: none.

---

## v0.70.4 — Overlay-tunnel health is surfaced; stale jump peers can't steal overlay IPs

- **A down WireGuard tunnel on an otherwise-reachable host is no longer silent.**
  The monitor already fell back to the host's direct address, so the host stayed
  "online" and nothing flagged the dead overlay. Now an overlay-enrolled host
  whose tunnel probes down (while the host itself stays up) appears as a warning
  card under **Needs attention**, is included in Ask's fleet-health answers
  ("anything wrong?"), and fires the new **Host overlay tunnel down / restored**
  notification events (enable routes for them under Settings → Notifications).
  Tunnel-down is confirmed with the same multi-probe logic as offline
  (`PROV_MONITOR_OFFLINE_CONFIRMATIONS` / `PROV_MONITOR_CONFIRM_DELAY`), so one
  lost keepalive doesn't page. Offline hosts don't double-alert.
- **Stale jump-host peers can no longer steal a reused overlay IP.** Deleting or
  re-enrolling a host never removed its WireGuard peer fragment from the jump
  host; when the overlay IP was later reassigned, the stale fragment silently
  took the IP back on the next jump-host restart (WireGuard gives an allowed-ip
  to the last peer that claims it), dead-ending the live host's tunnel. Now:
  enrollment retires every stale claimant of the assigned IP (kernel peer +
  fragment), host deletion removes the host's peer from the jump host
  (best-effort), and the jump-host restore loop skips duplicate AllowedIPs
  claims with a loud warning instead of letting the last file win.
- Bundle note: the jump-host restore guard lands with the next deliberate
  jumphost image rebuild (bundles intentionally exclude the jumphost container);
  the enrollment/deletion cleanup makes it a belt-and-braces backstop.
- Migrations: none.

---

## v0.70.3 — Confirm host-offline before alerting

- **A host must now fail multiple consecutive probes before it is marked offline
  and alerted** (default 3 attempts, 10s apart, within the same sweep). Previously a
  single failed check — often a transient jump-host hiccup such as an sshd
  connection reset or a DNS blip — flipped the host offline for one 30s interval,
  fired an offline alert, and immediately recovered. Only previously-online hosts
  get the confirming re-probes, so steady-state sweep cost is unchanged and hosts
  that are genuinely down aren't re-probed extra times every sweep.
- Tunable via `PROV_MONITOR_OFFLINE_CONFIRMATIONS` (set `1` to restore the old
  single-check behavior) and `PROV_MONITOR_CONFIRM_DELAY`.
- **Release policy from here on: every bundle is full-stack and installable from
  any older version** — no stepping-stone installs; the latest bundle always
  carries all previous fixes. `make bundle` now defaults `BUNDLE_FROM` to `0.0.0`
  and `BUNDLE_COMPONENTS` to all five app components.

---

## v0.70.2 — Full-stack upgrade bundle; bundles pin linux/amd64

- **The release bundle now carries every app component** — backend, frontend,
  grype-scanner, **ansible-runner**, and the **prov-updater** itself (self-updated
  last via its detached helper) — so one in-UI install brings the whole stack to the
  same version instead of leaving sidecars behind.
- **`make bundle` pins images to `linux/amd64` by default** (`BUNDLE_PLATFORM`
  overrides). Building on an Apple Silicon host otherwise produces arm64 images that
  crash-loop with `exec format error` on an amd64 server and get health-gated back —
  correct behavior, but a confusing failure. No code changes beyond v0.70.1.

---

## v0.70.1 — Fix in-UI upgrades crashing the backend; truthful upgrade status & cluster roster

- **Fixed: applying an in-UI upgrade crashed the backend** (`sync: unlock of unlocked
  mutex` in the upgrade service) before the updater was ever dispatched. Introduced by
  the v0.67.x stale-dispatch self-heal; every UI-driven upgrade attempt since then hit
  it — the backend restarted, the update never applied, and the UI then showed the
  **previous** upgrade's persisted result (e.g. "Upgraded to 0.68.5") as if it were
  this run's outcome.
- **Upgrade status no longer reports a prior run's outcome as current** — a terminal
  updater status (success/failed) older than the running backend process is treated as
  history, not live progress.
- **A single-instance deployment no longer presents as a multi-node cluster** after
  crashes or container swaps: the upgrade UI's instance roster now counts only
  lease-live instances, ignoring dead rows awaiting the leader's prune sweep.

---

## v0.70.0 — Super-admin promote/demote; role/flag unification; Users-page fixes

- **Promote or demote an existing account to super administrator** — new **Super
  admin** switch in the user edit dialog (and `PUT /api/v1/users/{id}/super-admin`).
  Previously the flag could only be set when creating a user, so the only path to
  a second super admin was a new account or direct SQL. Super admins only.
- **The built-in "Super Administrator" role now IS super-admin status.** Assigning
  the role promotes the account (sets the real `is_super_admin` flag); removing it
  demotes. Before, the role granted the `Admin.All` permission wildcard but not
  true super-admin status, so a role-holder still could not modify, disable, or
  delete super-admin accounts — the role and the flag could silently drift apart.
- **Last-super-admin lockout guard** — deleting, disabling, or demoting the last
  active super administrator is refused with a clear error, so an instance can
  never be left without one.
- **Fixed: opening "Access policy…" on the Users page blanked the whole app** when
  no fleet-wide session policy had ever been saved (the unset global policy
  serialized its IP allowlist as `null` and the dialog crashed rendering it). The
  API now always returns an array and the dialog is defensive regardless.
- Users-page edit/delete failures now surface the server's reason (e.g. the
  last-super-admin refusal) instead of failing silently.

---

## v0.69.0 — Ask Provenance: calendar ranges, feedback, follow-up chips, and a regression harness

- **True calendar ranges for "yesterday", "this week", and "last week"** — "who connected
  yesterday?" now means midnight-to-midnight of the prior day (display timezone), "this
  week" starts Monday, and "last week" is the prior Mon–Sun, across sessions, audit log,
  auth events, metric history, and availability. Rolling phrases ("past week", "last 7
  days") are unchanged.
- **Deterministic failed-login answers** — counts and timestamps come from code, rendered
  in the display timezone in 12-hour format; large sets summarize by targeted user and
  top source IP with a brute-force note.
- **"Which hosts have been accessed today?"** is now a deterministic fast path that
  groups sessions by host.
- **Follow-ups no longer bounce back "what do you mean?"** — if the model answers a
  follow-up with a clarifying question while the conversation already named the subject,
  it is retried once with the recent subject assumed.
- **Thumbs up/down on every answer** (new `assistant_feedback` table +
  `POST /api/v1/assistant/feedback`) so unhelpful or misrouted answers can be found and
  fixed from data instead of live debugging.
- **One-click follow-up chips** under the latest answer — deterministic suggestions
  chosen by which tool answered, never model-generated.
- **`tools/ask-harness/`** — the Ask acceptance battery (the 7 canonical questions plus
  every variant that has regressed before, and a multi-turn thread) now lives in the
  repo and runs against a live instance with one command.


---

## v0.68.23 — Ask Provenance: "today" is the calendar day; bare connection questions scope to a week

- **"today" now means since local midnight for every time-windowed question**, not a
  rolling 24 hours — "which hosts were accessed today?", "who connected today?", "what
  changed in the audit log today?", and "any failed logins today?" no longer include
  yesterday-evening rows. Applied on both the fast path and the model tool-loop for
  session, audit, security-event, metric-history, and availability questions.
- **A bare "who connected to <host>?" with no time cue now scopes to the past week**
  (was 30 days), matching "recently"/"lately". Explicit windows ("this month", "last 30
  days") and "who last connected" are unchanged.


---

## v0.68.22 — Ask Provenance: "recently" is a week, not a month

- **"recently"/"lately" now scopes host-connection questions to the past week** (was 30
  days). "Has anyone connected to <host> recently?" no longer sweeps in a month of
  sessions. An explicit window ("this month", "last 30 days") still honors what you ask,
  "who last connected" is still unbounded-to-most-recent, and this matches how "recently"
  already behaved for audit/security/failed-run questions.


---

## v0.68.20–0.68.21 — Ask Provenance: calendar-day "today" + follow-up context

- **"today" now means the calendar day**, not a rolling 24 hours — "who connected today"
  no longer includes yesterday-evening sessions (window starts at local midnight).
- **Follow-up questions use conversation context.** The assistant carries the prior
  subject forward ("tell me about them", "which host had the most?", "what about <host>")
  and re-runs the relevant tool instead of asking the user to repeat themselves. (A
  genuinely vague reference over a mixed prior context — e.g. "when did the failures
  happen?" after discussing both failed scans and failed runs — can still draw a
  clarifying question from the local model; naming the subject resolves it.)


---

## v0.68.19 — Ask Provenance: broaden session-history routing

Two "who connected" phrasings mis-routed: "has anyone connected to <host> recently?"
fell to the model and used a too-narrow 24h window ("no one" when there were sessions
2 days back), and "has anyone logged into <host>?" was answered from Provenance SIGN-IN auth
events instead of SSH sessions to that host. The session-history fast path now recognizes
"has anyone / did anyone / anyone connected/logged into/accessed <host>" (including
"logged into"/"onto"), with "recently" mapping to a 30-day window. Guarded so "who has
access to <host>" (a permissions question) still defers to the model.


---

## v0.68.18 — Ask Provenance: systematic reliability overhaul

A ground-up pass over the assistant, validated by an end-to-end harness that runs the
full question battery through the live API against real fleet data (no more one-off
checks). Every fix below was confirmed by that harness, and the deterministic builders
are covered by unit tests.

**Correctness (false negatives / hallucinations)**
- **Deterministic answers for list/aggregate questions.** "Which hosts have <N% disk
  free", "who (last) connected to <host>", "what changed in the audit log", and
  "disk/memory/load trend on <host>" are now built in code from the tool data — the model
  is unreliable at enumerating, counting, and computing trends, so it no longer narrates
  those. Result: complete host lists with correct counts, the actual most-recent session,
  a real trend sentence ("disk-free fell from 31.8% to 29.1%"), and an accurate change
  breakdown.
- **No more example-name hallucinations.** The system prompt's illustrative hostnames
  were replaced with unmistakable placeholders, so an empty/mis-routed tool result can no
  longer make the model invent a fake host.
- **Deterministic routing for more shapes**: disk-free filters, metric trends, session
  history, "failed scans OR playbook runs" (combined + failure-filtered), and audit
  "what changed" now take the fast path with parsed arguments instead of depending on the
  model to emit correct JSON (which it sometimes inverted).
- **Time windows honored everywhere.** "past day/48 hours/this week/last week" now map to
  the right lookback for security events, session history, audit, and metric trends
  (previously several silently used a fixed default — a false negative).
- **Audit counts are window-wide**, not derived from the display row cap, so real changes
  aren't crowded out by high-volume routine rows.

**Scope / no fluff**
- Answers stay tight: de-noised audit summaries (automated events shown only as a count,
  capped to the top change types), session answers reduced to who + counts, no unrequested
  recommendations, no preamble.

**Robustness**
- A fast-path tool that is routed but has no dispatch handler now falls through to the
  model instead of returning an empty "nothing found" — plus a coverage test that fails
  the build if routing and dispatch ever drift apart (the bug class behind two earlier
  regressions).

Backend-only; the configured model (e.g. qwen2.5:14b-instruct) is unchanged.


## v0.68.11 — Ask Provenance: deterministic disk + session-history routing

Two false negatives found in real-usage testing, both from time/threshold arguments the
local model got wrong or a too-narrow default window:

- **Disk-free filter** — "which hosts have less than 80%% / 90%% disk free" returned "no
  hosts" even though ~10 qualify. The threshold now routes through the fast path and is
  parsed deterministically (diskFreePctMax/Min) instead of relying on generated JSON args,
  which small models sometimes invert or mis-set.
- **"Last person to connect to <host>"** — session_history defaulted to a 48-hour window,
  so a host whose last login was >48h ago wrongly returned "no one has connected". These
  questions now route through the fast path with a ~1-year window (find the most recent
  session regardless of age); an explicit window ("yesterday", "this week") is still honored.

---

## v0.68.10 — Ask Provenance: de-prioritize automated audit noise

"What changed in the audit log today?" led with automated background events (the
assistant's own queries, per-session certificate issuance) that dominate the log by
volume but are not operator changes. The audit_log tool now splits its result into
changesByAction (operator-initiated changes) and routineByAction (automated noise:
assistant queries, certificate issue/renew/revoke, KRL housekeeping), and the prompt
tells the assistant to lead with the changes and treat the routine as a background count
or omit it. On real data the summary now leads with upgrades applied, group/credential
changes, and logins, and drops the 30 assistant-query / 14 cert-issuance noise entirely.

---

## v0.68.9 — Ask Provenance: unified answer discipline across both paths

The scope/summarize reminder from v0.68.8 (LLM-tool-loop path) is now also applied to
the fast-path narration, so questions that route deterministically (schedules, pending
updates, downtime, security events, etc.) get the same discipline: summarize with counts
instead of enumerating, honor the qualifier, no unrequested recommendations, terse empty
answers. Extracted the reminder into a single shared instruction used by both paths.

Validated on real fleet data: "hosts under 20%% disk free" (none) -> one-line "no hosts...";
"what changed in the audit log today" -> a grouped count summary, not a dump; "what runs on
a schedule" -> the 8 schedules ordered by next fire.

---

## v0.68.8 — Ask Provenance: focused final-answer pass

The scope/qualifier rules in the (long) system prompt were being ignored by the local
model when a tool returned a large result — it would enumerate every row and append a
summary and recommendations despite the instructions. Now, once tools have gathered the
data, the final answer is regenerated with a short scope reminder placed as the LAST
message, right before generation — a position small models follow far more reliably.
The refined answer summarizes and groups (e.g. "RouterOS Upgrade failed ~19 times,
almost all on coreswitch") instead of listing every row, drops unrequested
recommendations, and honors the question's qualifier. The full rows still appear in the
table beneath the answer.

---

## v0.68.7 — Ask Provenance: time-window fix + qualifier discipline

Follow-ups from real usage:

- **Time-window false negative fixed.** "Any failed logins in the last 48 hours / 72
  hours / past week" was silently windowed to a fixed 24h, so it reported none while the
  answer parroted back the user's window — missing older failures. The fast path now
  parses the actual window from the question ("48 hours", "3 days", "2 weeks") and passes
  it through; a bare failed-login/downtime question now defaults to a week, not a day.
- **Qualifier discipline.** The assistant is now told to honor filter words: "FAILED
  playbook runs" lists only the failures (not a full run history, a success summary, and a
  multi-point action plan), "OFFLINE hosts" only offline, "CRITICAL vulns" only critical.

Builds on v0.68.6's deterministic sampling + answer-scope discipline.

---

## v0.68.6 — Ask Provenance: consistent, scoped answers

Two changes make the AI assistant behave like a precise sysadmin tool instead of a
chatbot, addressing answers that varied by phrasing and volunteered unrequested detail.

- **Deterministic sampling.** Every assistant model call now runs at low temperature
  (0.1), low-ish top_p, and a fixed seed, instead of the model's chat default (~0.8).
  This stabilizes both tool selection (fewer mis-routes / false positives) and the final
  answer, so the same — or a reworded — question yields the same result run to run.
- **Answer-scope discipline.** The system prompt now instructs the assistant to answer
  ONLY what was asked: no volunteering adjacent metrics, background, or "you may also
  want to…" recommendations unless requested; no preamble; and to answer a question the
  same way regardless of how it is phrased. When the tools return nothing, it says so in
  one sentence rather than filling the gap with related data.

Backend-only; no config or schema change. The configured model (e.g.
qwen2.5:14b-instruct) is unchanged.

---

## v0.68.5 — Self-healing upgrade state

Fixes a loop where, after an in-UI upgrade failed on the `prov-updater` sidecar, the
backend stayed wedged reporting "an upgrade is already in progress" while the UI showed
"ready" — so every Install click silently reverted. The backend's busy-check now consults
the updater's actual state and clears a stale dispatch, so upgrades recover on their own
instead of needing a backend restart.

---

## v0.68.4 — Fix updater compose path resolution

Fixes an in-UI upgrade failing with `/prov.env is a directory`. When the updater runs
`docker compose -f /compose/docker-compose.yml`, Compose resolved the compose file's
relative `../../.env` bind against `/compose` → a stray `/.env` directory that then got
bound as the updater's env file. The updater now passes `--project-directory <real host
compose dir>` (discovered by inspecting its own mounts) so relative paths resolve to real
host files. Deploy this updater fix host-side (`make redeploy-single`), not via an in-UI
self-update — the old updater's self-update carries the very bug being fixed.

---

## v0.68.3 — Security hardening (audit batch 3: persistent host-key pins)

- **SSH host-key pins now persist across restarts.** The gateway's trust-on-first-use
  verifier previously kept pins only in process memory, so after a backend restart the
  first connection to any host was re-pinned blindly — a MITM during that window (or a
  silent host rebuild) would be accepted as the new pin. Pins are now stored in the
  database (`ssh_host_keys`, migration 0068) and cached in memory, so a key mismatch is
  detected for the life of the host, not just the process. A pin-store lookup error now
  fails **closed** (refuses the connection) rather than re-pinning. The schema also
  supports an operator-set `pinned` source, so a future enrollment flow can pre-seed the
  expected key and verify even the first connect.

  Fixed in review: a nil-logger code path that would have accepted a connection on a
  lookup error instead of failing closed (caught by a new test).

Migration 0068 is additive (a new table; no action required).

---

## v0.68.2 — Security hardening (audit batch 2: key lifecycle)

The higher-effort fixes from the security audit — closing the key-rotation and
tenant-isolation gaps.

- **`provctl vault rekey --old … --new …`.** Rotates the vault master passphrase by
  decrypting every locally-sealed vault secret under the old key and re-encrypting under
  the new one (verify-before-write). Remediates a suspected `PROV_VAULT_PASSPHRASE`
  compromise — previously, changing the passphrase silently made every secret
  undecryptable. Resumable/idempotent per row; run offline, then update the env var.
- **Authenticated backups (encrypt-then-MAC).** Each backup now ships a detached
  `<file>.sql.enc.hmac` (HMAC-SHA256 over the ciphertext, streamed alongside the write),
  so a tampered or corrupted backup is detectable before restore. openssl CBC alone is
  unauthenticated; the tag closes that. Stock-openssl decryption is unchanged, and the
  tag is reproducible with stock tools (disaster-recovery runbook updated with a verify
  step). Old backups without a sidecar still restore.
- **Dedicated, rotatable MFA-at-rest key.** `PROV_MFA_ENCRYPTION_KEY` (optional) now
  encrypts TOTP secrets independently of `PROV_JWT_SECRET`, so the JWT secret can rotate
  without bricking stored MFA secrets. Decryption falls back to the legacy JWT-derived
  key, so adopting it never locks out enrolled users (covered by a migration test).
- **Multi-tenancy fail-closed on a superuser DB role.** With `PROV_MULTI_TENANCY=true`,
  the app now refuses to start if the database role is a SUPERUSER or has BYPASSRLS —
  either silently bypasses row-level security and would break tenant isolation. The error
  tells you to connect as a `NOSUPERUSER NOBYPASSRLS` role.

---

## v0.68.1 — Security hardening (audit batch 1)

Quick, low-risk hardening from a five-domain security audit of the secrets/vault/auth
surface. No behavior change for normal operation.

- **Ansible inventory + ssh_config written 0600.** The runner's `inventory.ini` (which
  embeds vaulted `ansible_password` values) and `ssh_config` were created with the
  default umask (world-readable) while sibling key files were already 0600. Now all
  credential-bearing run artifacts are 0600.
- **FIPS-mode login timing oracle closed.** The anti-enumeration dummy password-verify
  always used Argon2id, but real accounts verify with PBKDF2 under FIPS — so failed
  logins for nonexistent vs. real users took measurably different time, reopening user
  enumeration in exactly the strict mode. The dummy verify now uses the active KDF.
- **Unencrypted-Postgres boot warning + docs.** The backend now logs a warning when
  `PROV_DATABASE_URL` uses `sslmode=disable` (fine on a co-located DB, a cleartext-on-
  the-wire risk for any networked/managed Postgres). The production env example documents
  `sslmode=verify-full` and now also reminds operators to `chmod 600 .env`.
- **`.env` created 0600.** `make env` now creates (and re-tightens) `.env` as mode 0600
  so the file holding every master secret isn't readable by other local users.

(Deferred to later batches with the operator: backup AEAD re-key, `provctl vault rekey`,
dedicated rotatable MFA key, multi-tenant superuser-role guard, persisted host-key pins,
and CSRF double-submit enforcement — the last requires coordinated frontend changes.)

---

## v0.68.0 — Self-updating upgrades: the updater upgrades itself + config migration

Closes the last gaps that made some releases need a host-side `make redeploy-single`, so
**every** update can now install from a signed `.provup` bundle in the UI.

- **The updater upgrades itself.** A bundle may now include the `prov-updater`
  component. Since the updater cannot recreate its own container inline (that would kill
  the in-flight upgrade), it applies everything else first, persists `success` to disk,
  then hands its own replacement to a short-lived **detached helper** (watchtower-style)
  launched from the new image. The helper mounts the same compose files + `.env` (host
  paths discovered by self-inspection) and recreates the updater against the upgrade
  override. The new updater loads the persisted status on boot, so the UI still sees the
  final result across the blip.
- **Additive config migration.** A signed manifest can declare `configAdditions` — new
  env keys with defaults, or generated secrets (`generate: secret`, e.g.
  `PROV_UPDATER_TOKEN`). The updater merges any that are absent into `.env` before
  recreating containers. Strictly additive: an operator-set key is never overwritten. The
  updater's `.env` mount is now read-write for this (it already holds the Docker socket,
  so this is no new trust boundary).
- `provctl release build` gains `--config-add KEY=VALUE` and `--config-secret KEY`;
  `make bundle` builds whatever `BUNDLE_COMPONENTS` lists (so `prov-updater` can ride
  along). Docs: new "Upgrading Provenance (in-UI)" section in operations.md.

The only step still done by hand is the one-time bootstrap of a brand-new deployment.

---

## v0.67.5 — Hardening: updater token required in prod + no-cache index.html

Two hardening items surfaced by the end-to-end upgrade smoke test:

- **prov-updater fails closed without a token in production.** The updater drives the
  Docker socket, so an empty `PROV_UPDATER_TOKEN` is an unauthenticated RCE surface for
  anything on the internal network. It previously only warned; now, with `PROV_ENV` set
  to anything other than `development`, it refuses to start until the token is set. The
  backend already sends `X-Updater-Token`, and compose already wires the shared value to
  both services — set `PROV_UPDATER_TOKEN` (openssl rand -hex 32) in your `.env`.
- **index.html is served no-cache; hashed assets cache for a year.** After an in-UI
  upgrade the build emits new content-hashed asset names; a browser-cached `index.html`
  kept pointing at the old chunks, so users ran stale UI until a manual hard-refresh.
  nginx now revalidates `index.html` every load (via `expires -1`, preserving the
  inherited security headers) and caches `/assets/*` immutably.

(A third candidate — pinning the session secret — was already handled: production
requires persistent `PROV_JWT_SECRET` + `PROV_CSRF_SECRET` and fails closed without
them, so auth sessions already survive the backend restart during an upgrade.)

---

## v0.67.4 — Fix: updates volume not writable by the backend user

The backend Dockerfile creates and chowns its data dirs (recordings, scans, backups,
rdp-drive, scap-content) to the unprivileged `fleet` user in both the build step and
the privilege-dropping entrypoint — but `/var/lib/prov/updates` (added in v0.61.0 for
the in-UI upgrade staging area) was in neither list. A named volume mounted there comes
up root-owned, so the `fleet` process cannot write the staged bundle:
`could not stage the bundle: open /var/lib/prov/updates/pending.provup: permission denied`.
Added `updates` to both mkdir/chown lists. Existing deployments: the entrypoint now
chowns it on next start; or `chown` the volume once.

Fourth and final bug in the in-UI upgrade path found by the end-to-end smoke test.

---

## v0.67.3 — Fix: 8 MiB global body cap truncated bundle uploads

The global `bodyLimitMW` request-body cap (8 MiB) exempted the SFTP upload route but
not the in-UI upgrade bundle upload (added later in v0.61.0). Its own 2 GiB limit was
overridden by the outer 8 MiB wrap, so any real bundle was truncated mid-stream and the
backend rejected the incomplete multipart with `400 "expected a multipart 'bundle' file"`.
Added `/system/upgrade/preview` to the exemption. Backend-only.

This was the third and final bug in the upload path found by the end-to-end smoke test
(after the v0.67.1 `/api/v1` prefix and v0.67.2 multipart-boundary fixes).

---

## v0.67.2 — Fix: bundle upload multipart boundary

Following v0.67.1 (which let the upload request reach the backend at all), the bundle
upload still failed with `400 "expected a multipart 'bundle' file"`. `previewUpgrade`
hard-coded `Content-Type: multipart/form-data`, which omits the `boundary=…` parameter
the browser generates automatically — without it the server can't parse the multipart
body. Removed the manual header so the browser sets Content-Type (with boundary) itself.
Frontend-only. Second bug in the upload path surfaced by the same end-to-end smoke test.

---

## v0.67.1 — Fix: in-UI upgrade API calls missing `/api/v1` prefix

The Settings → Updates screen called the upgrade endpoints at `/system/upgrade/*`
instead of `/api/v1/system/upgrade/*` (every other API module includes the prefix; this
one didn't). Behind a reverse proxy this meant the calls never matched the `/api/`
proxy location: bundle **upload returned HTTP 413** (the request fell through to the SPA
route, which enforces the default 1 MB body limit instead of the API location's
unlimited `client_max_body_size`), and check/status/apply/pull/drain silently hit the
SPA fallback rather than the backend. Corrected all six paths. No backend change.

This was the first real end-to-end exercise of the in-UI upgrade UI through a proxied
deployment — the unit/build tests never caught it because they don't traverse nginx.

---

## v0.67.0 — Upgrade system phase 5: federation upgrade ordering

The in-UI upgrade system is now federation-aware, completing the upgrade epic:

- **Federation protocol negotiation.** The site↔hub join handshake now carries a real
  wire-protocol version. A hub rejects a site whose protocol is older than it supports
  (and a site rejects a too-old hub), each with a message naming which side to upgrade
  first. This build speaks protocol v1; legacy pre-versioning sites are treated as v1, so
  existing federations keep working with no change.
- **Site build-version visibility.** Each site reports its running `provd` version on
  its read-model heartbeat. The hub stores it and surfaces it on the **Sites** page (new
  Version column) and the hub's **Updates** panel.
- **Sites-first ordering guard.** The hub's Updates panel compares each site's version
  against the version the hub is about to install and warns when a site is behind —
  upgrade the sites before the hub, so the hub never runs a newer federation protocol than
  a site it must talk to. Upgrades stay per-stack (each site is upgraded from its own UI /
  channel); there is no remote force-upgrade, by design.
- Docs: new "Upgrading a federation" section in `docs/federation.md`.

Schema: migration `0067` adds `build_version` / `protocol_version` to `federation_sites`
(both default-backfilled; additive, no action required).

---

## v0.66.0 — Upgrade system phase 4: HA rolling upgrades

In-UI upgrades are now cluster-aware:

- **Rolling upgrade for additive releases.** On a multi-instance (HA) deployment, the
  `prov-updater` rolls the backend **one replica at a time**, health-gating each replica
  (`/ready` + `/version`) before moving to the next — the others keep serving, migrations
  apply once (Postgres advisory lock serializes them), and leadership handoff is automatic.
  Configure the replica service names with `PROV_UPDATER_BACKENDS` (e.g. `backend1,backend2`);
  single-host is unchanged (one "backend").
- **Breaking releases replace all replicas together** — a brief full-cluster outage — because a
  mixed-version cluster would break against the just-migrated schema. The manifest's
  `migrationCompatibility` drives the choice.
- **Cluster visibility.** The Updates panel shows the live instance roster and their versions
  (from the existing `cluster_instances` heartbeat), so you can see version skew during an
  upgrade, and the breaking-migration warning is escalated for clustered deployments.
- Kubernetes/Helm continue to use their native `RollingUpdate` (`maxUnavailable: 0`); the same
  additive-only rolling rule applies.

## v0.65.0 — Host "Device type" selector; RouterOS hosts skip Linux fact collection

- **Device type on the host form.** RouterOS management is now behind a **Device type**
  selector (`Generic` / `MikroTik RouterOS (API)`) instead of a checkbox shown on every
  host — the API-port field only appears when you pick RouterOS. Stored as `deviceType` in
  `host_options`; the previous `routerOsApi` flag is still honored for hosts already
  configured, so nothing breaks.
- **RouterOS hosts no longer show garbage facts.** The monitor was running Linux
  fact/metric commands (`uname`, `/etc/os-release`, `df`, …) against RouterOS, which
  returns a "syntax error" that landed in the host's OS field. A host marked
  `MikroTik RouterOS` is now probed for reachability only and labeled "MikroTik RouterOS"
  — no Linux commands, no garbage.

Requires rebuilding backend + frontend (`make redeploy-single`).

## v0.64.2 — Fix: playbook editor showed stale content after save

Editing a saved playbook, saving, then re-opening the editor showed the *old* content
— even though the save persisted (playbook runs used the new content correctly). The
editor loads the playbook via a per-id query cache that the save flow never
invalidated, so a re-open served the stale cache and the editor's load guard locked it
in. The save now drops that per-playbook cache so re-opening refetches the just-saved
content. Frontend-only.

## v0.64.1 — ansible-runner: add librouteros (RouterOS API client)

Follow-up to v0.64.0. The `community.routeros.api` module requires the `librouteros`
Python library, which wasn't in the runner image — so a RouterOS API play failed with
`No module named 'librouteros'` even though the jump-host API tunnel came up fine.
Added `librouteros`. (The tunnel itself was confirmed working — the play just couldn't
import its API client.)

## v0.64.0 — Manage & schedule MikroTik/RouterOS updates via the RouterOS API

RouterOS 7's SSH doesn't cleanly close command sessions, so `raw`/`network_cli` playbooks hang
(a long-standing Ansible↔RouterOS issue). Provenance now drives RouterOS over its **binary API**
(port 8728) instead, **tunneled through the jump host** — and you can **schedule** it with the
existing playbook scheduler.

- **Mark a host "Manage via RouterOS API"** (Hosts → edit → RouterOS section, default port 8728),
  stored in a new generic `host_options` JSONB column. The host stays a normal SSH host (terminal
  still works); the flag just says "also reachable via its API".
- **When a playbook runs against it**, the ansible-runner opens `ssh -L …:<device>:8728` through the
  jump host and exposes it to the play as `prov_api_host` / `prov_api_port`, so a
  `community.routeros.api` task (`connection: local`) reaches the device. Tunnels are set up before
  the play and torn down after.
- **Credential:** the RouterOS API needs a username+password, so an API host uses a `vault_password`
  open-policy credential (an SSH key can't authenticate the API). It flows to the runner exactly like
  the SSH vaulted password — no new secret plumbing.
- **Scheduling reuses the existing playbook scheduler** — save a RouterOS-update playbook (see the
  operations guide) and create a Playbook-kind schedule targeting the host. No new scheduling code.

Requires rebuilding the ansible-runner sidecar (`make redeploy-single`). The `host_options` column
is added automatically on startup.

## v0.63.4 — ansible-runner: add paramiko (network_cli SSH backend)

The `network_cli` connection (community.routeros etc.) needs an SSH library, and the
runner image shipped with neither — so a network_cli play failed immediately with
`paramiko is not installed`. Added **paramiko 3.5.0** to the runner. network_cli plays
now initialize.

Honest status on reaching a **jump-hosted** device via network_cli: paramiko doesn't
read the ssh_config's ProxyJump, so a device only reachable through the Provenance jump host
may still not connect. The correct mechanism (a ProxyCommand in
`ansible_ssh_common_args`) is shared with the proven `raw` connection path, so it isn't
changed by default to avoid regressing working `raw` upgrades. **For upgrading RouterOS
through Provenance, the `raw` + `until`-reconnect playbook remains the supported path**;
community.routeros/network_cli is best for directly-reachable network devices today.

## v0.63.3 — Network-device playbooks (MikroTik / community.routeros)

The ansible-runner now ships the **community.routeros** collection (and its
ansible.netcommon dependency), so playbooks can drive MikroTik/RouterOS with the
proper modules (`community.routeros.command`, `connection: network_cli`) instead of
`raw` SSH commands.

Because `network_cli` uses paramiko/libssh (which don't read the ssh_config the way
the default ssh connection does), the runner now also wires network_cli connections to
**tunnel through the Provenance jump host** (a paramiko `ProxyCommand`) and to authenticate
vaulted hosts (a per-host key/password), so a jump-hosted network device is reachable.
This path should be verified on real hardware; the `raw` + `until`-reconnect approach
remains the proven way to reach RouterOS through Provenance. Requires rebuilding the
ansible-runner sidecar (`make redeploy-single`).

## v0.63.2 — Playbooks: don't force sudo on vaulted (appliance) hosts

Follow-up to vaulted-credential playbook auth (v0.62.0). The runner forced
`become: true` (sudo) on every host, so a playbook against a MikroTik/RouterOS switch
failed every task with `Timeout waiting for privilege escalation prompt` even after
login succeeded — network gear has no sudo. Privilege escalation now defaults **per
host**: enrolled Linux hosts still run under sudo, but **vaulted hosts default to
`become: false`**. A playbook can still opt a host in with an explicit `become: true`.
(Requires rebuilding the `ansible-runner` sidecar — `make redeploy-single` now does.)

## v0.63.0 — Check for updates (pull upgrades from a release channel)

The Updates panel can now **pull** an upgrade instead of only accepting an upload. Set
`PROV_UPDATE_CHANNEL_URL` to a signed release-channel index and Settings → Maintenance
→ Updates gains a **Check for updates** button (and surfaces an available update on
load). "Download & install" streams the bundle server-side straight into the same
verified apply pipeline — no manual download.

- The channel index is Ed25519-signed by the **same release key** as the bundles, so
  there's no new trust root; the index signature is verified before it's read, and the
  downloaded bundle is still verified independently before it's applied.
- Publish a channel with `provctl release channel --key <priv> --base-url
  <https://…/> <bundle.provup>…` — it reads each bundle's manifest and writes a signed
  `channel.json` + `channel.json.sig` to host alongside the bundles.
- Manual upload still works and needs no channel; leave `PROV_UPDATE_CHANNEL_URL`
  empty to hide the check button.

## v0.62.0 — Playbooks work against vaulted-credential hosts

Ansible playbooks can now target hosts that authenticate with a **vaulted SSH key or
password** (routers, switches, appliances) — not just hosts that trust the Provenance CA.

Previously the playbook runner always authenticated with the run's ephemeral Provenance
certificate. A host reached with a vaulted credential (e.g. a MikroTik switch you can
open a terminal to) would fail every play with `Permission denied (publickey)`, even
though the terminal logged in fine — because the terminal injects the vaulted
credential and the runner didn't. Now the runner injects the **same per-host vaulted
credential the terminal uses** for the final hop, while the jump-host hop still uses
the Provenance certificate. Mixed target sets work: cert-trusting hosts and vaulted hosts
in one run each authenticate their own way.

- Only **open-policy** vaulted credentials are used (a check-out-gated secret is never
  sent to the runner). As with the existing run credential, the injected key/password
  is written to the runner filesystem for the run — a caveat to weigh for untrusted
  playbook content. `sshpass` is added to the runner image for password auth.
- Note: authentication is only half the story for network gear. RouterOS/EOS/etc. are
  not POSIX shells, so `become: sudo` and shell modules won't work — use the
  appropriate `ansible_network_os` collection or `raw:` commands in the playbook.

## v0.61.0 — Upgrade Provenance from the UI (single-host)

You can now upgrade Provenance by uploading one signed file in the UI instead of
running `make redeploy-single` on the host. **Settings → Maintenance → Updates**:
choose a `.provup` bundle, review its manifest (version, release notes,
additive/breaking migrations), and install it in place.

- **Minimal interruption.** The frontend is swapped invisibly; the backend restarts
  for a few seconds and the page reconnects on its own. The jump host and WireGuard
  overlay are never touched, so managed hosts stay online. Active terminal/RDP
  sessions are dropped by the restart, so upgrade during a quiet window.
- **Signed, verified, reversible.** Bundles are Ed25519-signed; the backend verifies
  the signature against a trusted release key before staging, and the privileged
  `prov-updater` sidecar re-verifies it independently before touching Docker. A
  pre-upgrade database backup is taken automatically, the previous images are kept
  tagged `:rollback`, and a failed health check rolls the app back to the prior
  version. Gated by a new **System.Upgrade** permission (super-admins only) and fully
  audited.
- **Publishing:** `provctl release keygen` makes your offline signing key; `make
  bundle` builds + signs a `.provup`. See the operations guide.

**Deploy notes:** a new `prov-updater` sidecar (which mounts the Docker socket)
and an `updates` volume are added to the single-host compose. Set
`PROV_RELEASE_TRUST_KEYS` (your release public key) and `PROV_UPDATER_TOKEN` in
`.env`; leave `PROV_RELEASE_TRUST_KEYS` empty to disable in-UI upgrades entirely
(they fail closed). The `System.Upgrade` permission is added automatically on startup.

## v0.60.0 — Vulnerabilities: "fixable" now says how to fix it

Vulnerability findings are now classified by **how to remediate them on the specific
host**, so "fixable" stops being misleading when a package can't actually be updated:

- **Remove (orphaned).** The vulnerable package is installed but offered by no
  configured repository — a leftover from an in-place distribution upgrade (e.g. an
  old `libdns-export1104` still in the dpkg database on a host that's since moved to a
  newer Debian). An `apt`/`dnf` update will *never* clear it; the fix is to remove the
  package. Previously these showed a fixed-in version from the scanner and looked
  updatable, but `apt` offered nothing.
- **Update.** The host's package manager has the fix — a normal upgrade resolves it.
- **No apt fix.** A fix exists upstream but this host isn't being offered it (package
  held, Debian marked it no-DSA, or it needs an OS release upgrade).

To power this, the monitor's hourly fact collection now also records each host's
**obsolete packages** (apt `[installed,local]` / dnf "extras"), cache-only and
best-effort. The classification appears as a **Fix** column in the per-host findings
view and in the Ask assistant's vulnerability answers (which now call out orphaned
packages and tell you to remove rather than update them). The API's scan-findings
response carries a `remediation` field per finding. No configuration needed; the
`obsolete_packages` column is added automatically on startup.

## v0.59.0 — Monitor directly-managed (vaulted) hosts

- **Hosts that authenticate with a vaulted credential are now health-monitored.**
  A host added with a stored username/password or SSH key (`vault_password` /
  `vault_ssh_key`) — a router, switch, or other appliance reached directly rather
  than through WireGuard enrollment — is fully usable for terminal/SFTP but was
  never probed by the monitor, so it sat permanently at **"unknown"** status even
  though you could open a terminal to it. The monitor now probes these hosts too,
  authenticating with the same vaulted credential injected in a system context, and
  reports online/offline, latency, uptime, inventory, and metrics like any other
  host. Offline/recovered alerts and availability history apply to them as well.
- Only credentials with an **"open"** access policy are used for the unattended
  probe; a check-out-gated credential is never resolved by the background monitor,
  so such a host keeps its last-known status rather than being probed (unchanged).
- No configuration or migration needed — existing vaulted hosts start reporting
  status on the next monitor sweep after upgrade.

## v0.58.3 — Ask: "any problems?" attaches the right data; insights fix

- Open-ended health questions ("any problems?", "anything wrong?", "morning
  report", "does anything need my attention?") now route to the prov-insights
  summary as a single grounded call. Previously the model would answer correctly
  but sometimes tack on an unrelated tool call (e.g. the schedule list) whose table
  clobbered the insights table shown beneath the answer — so a health question
  could render an irrelevant grid.
- **Provenance insights: report pending security updates even when a host has no
  metrics yet.** Pending updates come from inventory, not metrics, but the insight
  loop skipped any host whose metrics hadn't been collected — so a freshly enrolled
  host (or one whose metric probe was lagging/failing) could hide pending security
  updates from "what's wrong with the fleet". Updates are now evaluated
  independently of metrics. Offline hosts are still summarized by their offline card.

## v0.58.2 — Ask: reliable schedule answers + better fallback

- "What runs on a schedule / when does it fire next?" now routes deterministically
  to the schedule list and answers from it directly, instead of occasionally
  looping and returning "I couldn't fully resolve that" with a bare table.
  (History/failure phrasings like "did the scheduled scan fail" still go to the
  scan/playbook run history.)
- When the model does run out of tool steps on any question, Ask now makes one
  final pass over the data it already gathered to write a real answer, rather than
  giving up — and the last-resort message no longer implies failure when the
  answer is sitting right there in the results.

## v0.58.1 — Ask assistant works under multi-tenancy

Fixed the Ask assistant returning nothing when `PROV_MULTI_TENANCY` is enabled.
The assistant answers in a background context (local-LLM inference outlives the
HTTP request), which was unmarked by tenant — so the row-level-security hook
denied every row (fail-closed) and answers came back empty. Ask now captures the
caller's tenant from the request and re-applies it to the background work, so every
query is scoped to that tenant exactly as a synchronous request would be — never
cross-tenant. With multi-tenancy off, behavior is unchanged. Verified with a real
non-superuser role and RLS enforced: an unmarked context sees nothing, each
tenant's context sees only its own rows, and no data crosses tenants.

## v0.58.0 — Fuller host support bundle

Expanded the per-host support bundle to cover what a support agent typically
requests up front when troubleshooting, so the first download usually has what's
needed. Added, alongside the existing diagnostics: PSI pressure, swap, ulimits/
open-file handles and kernel modules; filesystem details (`blkid`/`fstab`), SMART
health, RAID (`mdstat`/`zpool`), and I/O stats; interface error counters and time
sync (`timedatectl`/chrony/ntp); systemd timers, cron, and boot analysis; package-
manager health (held packages, repositories); SELinux/AppArmor, effective sshd
config, sudo/privileged groups + `NOPASSWD` rules, and login-capable accounts;
hardware (`dmidecode`/`sensors`/`lspci`) and Docker/Podman; plus an error-priority
journal extract and the boot list. Every command is best-effort — a tool that
isn't installed just leaves its file empty rather than failing the bundle — and
each file records the exact command that produced it. Verified end-to-end that the
collector runs cleanly and produces a valid archive.

## v0.57.0 — Ask assistant: capacity + login security, and reliable routing

Follows v0.56.0 with two more answerable areas and a substantial reliability pass
on how questions are routed — validated end-to-end against a local model.

**New**
- **Capacity outlook** — "are any hosts going to run out of disk or memory this
  week?" now gives a direct answer: it filters the insights engine to the disk-
  runway and memory signals and states plainly when nothing is at risk, instead of
  returning unrelated items (e.g. pending updates) as if they answered the question.
- **Login security** — a new `security_events` view over the authentication event
  stream answers "any failed logins?", "is someone brute-forcing the login?",
  "any account lockouts / MFA failures?", including a per-IP failure tally as a
  brute-force signal. These events are separate from the change/audit trail, so
  this is distinct from the audit log. Requires `Audit.View`.

**Reliability**
- Expanded the deterministic fast-path so common sysadmin question shapes route to
  the right data and are answered from that data directly — vulnerabilities/CVEs,
  users/roles/MFA, login-security, OS/kernel inventory, disk-provenance follow-ups
  ("which filesystem is that %?"), and aggregate/superlative host questions ("which
  host has the highest load / longest uptime", "how many hosts are online"). This
  removes a class of misroutes and stops a small local model from answering with a
  canned example instead of the real data.
- When a question maps to no available data, Ask now says so plainly (and notes what
  it *can* answer) instead of returning a blank response.

## v0.56.0 — Ask assistant: six new answerable areas + accuracy fixes

A coverage pass over the **Ask** assistant so it can answer the questions an IT
admin / sysadmin actually asks day to day. Six data areas that previously had no
tool are now answerable, and two accuracy problems are fixed.

**New things Ask can answer**

- **Availability / downtime history** — *"did any host go offline overnight?"*,
  *"was web-01 down this week?"*, *"how much downtime has db-02 had?"*. Host
  online↔offline transitions are now **recorded** (previously they were alerted and
  then discarded), so Ask can report outages that already recovered — which the
  live-status tools cannot see. Adds the `host_status_events` table (migration
  0063, tenant-scoped) written by the monitor, pruned on the activity-retention
  window.
- **Vulnerabilities (CVEs)** — per-host findings (CVE, package, installed/fixed
  version, severity, CVSS) and a fleet roll-up, from the vulnerability scanner
  (distinct from OpenSCAP compliance). Requires `Host.Scan`.
- **Users, roles, and MFA** — accounts with their roles, auth source, MFA-enrolled
  state, disabled/super-admin flags, and last login. Requires `User.Edit`.
- **Approvals and just-in-time access** — pending access requests plus the
  currently active temporary grants. Requires an approvals permission.
- **Windows software inventory** — installed apps on an RDP host (host-access
  scoped).
- **Platform health** — the HA cluster roster + current leader, and recent host
  enrollment jobs. Cluster needs `System.Configure`; enrollment needs `Host.Enroll`.

  Every new tool re-checks the caller's permissions and host access, exactly like
  the existing ones.

**Accuracy fixes**

- **Disk-free %, explained.** A host's headline "disk free %" is the free space on
  its *tightest* filesystem, measured as `df` Available / size — which does not sum
  to 100 with a mount's Used % because `df` Available excludes filesystem-reserved
  blocks. `host_detail` now returns a breakdown that names the driving mount and
  gives each mount's free % and used %, and Ask explains the difference instead of
  it looking like an inconsistency.
- **No more echoed examples.** Hardened the assistant's grounding so it can no
  longer answer a question by repeating a placeholder from its own instructions
  (e.g. replying about "systemctl on web-01" to an unrelated question); downtime
  questions are also pinned to the availability tool via the deterministic
  fast-path so they can't be misrouted to command-history search.

## v0.55.5 — Revert module-path placeholder

Reverts v0.55.4. The generic placeholder made the `git clone`, `go get`, and
`go install` commands non-functional, so the SDK and Terraform provider module paths
and the docs' install examples are restored to the repository's real GitHub path.

## v0.55.3 — Live host status on the terminal view

Extends v0.55.2 to the in-terminal view. The terminal header now shows the host's
**online/offline** status as its own chip (next to the connection-status chip), and it
updates live — driven by the same app-wide `host.status` subscription, with a 30-second
scheduled refetch as a fallback. Invalidation now also refreshes the single-host detail
query, so the file browser and host-details dialog stay current too.

## v0.55.2 — Live host status across the UI

Host online/offline changes now show up on their own — no manual page refresh.

- The app already broadcasts `host.status` on every monitor probe over a WebSocket, but
  only the Dashboard consumed it. That subscription is now **app-wide** (in the shell
  that's mounted on every page), so the **Terminals** launcher, the **Hosts** grid, and
  the **Dashboard** all reflect a host coming online/offline within seconds — from a
  single shared connection. Previously the Terminals and Hosts lists never updated until
  you reloaded.
- Added a **30-second scheduled refetch** to the Terminals and Hosts lists as a fallback,
  so status stays current even if the events socket is briefly disconnected.

## v0.55.1 — Accurate pending updates on RHEL-family hosts

Follows up v0.54.1 (which fixed the Debian/Ubuntu path) with the RHEL/dnf/yum side.

- **Per-package security flags are now correct on dnf hosts.** The dnf path previously
  hard-coded every pending package to *non-security* in the package list (only the
  aggregate count tried, via `updateinfo`, to reflect security updates) — so on RHEL,
  Rocky, Alma, and Fedora hosts no individual package was ever shown as a security
  update. Collection now uses `dnf repoquery --upgrades --latest-limit 1` for a clean,
  de-duplicated one-row-per-package list and `--security` to flag each security update,
  so the per-package flags and the security count agree.
- **More robust parsing.** repoquery's machine-readable output avoids the header/line-wrap
  and "Obsoleting Packages" pitfalls of scraping `dnf check-update` columns; a
  check-update fallback covers minimal installs without repoquery. The yum path (RHEL 7)
  gains the same per-package security flagging via `yum --security` when available.
- Validated against a real Rocky Linux 9 host (108 pending, 56 security — counts and
  per-package flags consistent, matching `dnf check-update`). Counts refresh on the next
  hourly inventory sweep. Like the apt path, collection reads cached metadata (kept fresh
  by `dnf-makecache.timer`), so it stays cheap and adds no network load.

## v0.55.0 — Cross-instance live session shadowing (HA)

Closes the last HA gap: **live session shadowing now works across instances.** Watching
an in-progress session (`Session.Watch`) previously only worked if the watcher happened
to land on the same instance as the session's PTY; otherwise the watcher saw nothing.

- When a watcher attaches to a session another instance owns, it announces interest over
  the existing Postgres LISTEN/NOTIFY backplane, and the owning instance mirrors that
  session's live output/resize frames to peers — **only while a remote watcher is
  attached**, so an unwatched session adds zero backplane traffic.
- Frames are chunked to fit the NOTIFY payload limit and relayed on a dedicated,
  non-blocking path, so shadowing never slows the operator's terminal; under a burst a
  remote watcher drops frames rather than stalling the session (same policy as a local
  slow watcher).
- No new infrastructure or configuration — it rides the backplane Provenance already uses, and
  is inert in a single-instance deployment.
- The HA test stack (`deploy/compose/docker-compose.ha.yml`) is now self-contained: it
  pins its two backends to its own Postgres single-tenant, so it runs as-shipped
  regardless of the production `PROV_DATABASE_URL` / multi-tenancy in your `.env`.

Verified live: leader-kill failover, ownership reconciliation (dead-owner rows fail while
live peers are spared), and — via two real backends over one Postgres — cross-instance
events, terminate, and the shadow subscribe + chunked-frame relay all round-trip.

## v0.54.1 — Pending-updates accuracy + Ask-AI timezone fixes

Three fixes to how host updates are collected and how the assistant reports times.

- **Pending updates now match `apt update`.** The monitor collected pending updates
  with `apt-get -s upgrade`, which silently holds back packages that need new
  dependencies and Ubuntu **phased updates** — so hosts whose only pending updates
  were phased/kept-back showed *nothing* pending even though `apt update` listed them
  (and since security updates are rarely phased, a host often surfaced its security
  updates while all its regular updates stayed invisible). Collection now uses
  `apt list --upgradable`, which enumerates every upgradable package exactly as
  `apt update` reports it. Host Details, the dashboard, and Ask AI now reflect the
  real update posture; counts refresh on the next inventory sweep (hourly).
- **Ask AI reports schedule times in your timezone.** The assistant rendered schedule
  and other times in UTC and left recurrences like "daily at 03:00" unlabeled, so it
  would say a 03:00-Eastern schedule runs at "03:00 UTC". It now knows the configured
  display timezone, labels recurrences with the zone ("daily at 03:00 EDT"), and
  reports times in that zone.

## v0.54.0 — Federation site key rotation

Completes federation key lifecycle: a **site can rotate its own identity key** in
place, mirroring the existing hub-key rotation, with no re-enrollment and no link
downtime.

- **Site-initiated rotation** (`POST /api/v1/federation/site/rotate-key`,
  `System.Configure`). The site generates a new keypair and, over its
  already-authenticated link, sends the new public key **signed by its current key**.
  The hub verifies that against the site's active key and stages the new key as
  *pending* — leaving the current key in force — then **promotes** it to active on the
  site's next reconnect with the new key. The hub accepts both keys during the overlap,
  so a crash or drop mid-rotation never locks a site out.
- **Prompt reconnect.** A site reacts to its link closing immediately (rather than at
  the next push tick), so a rotation promotes within seconds.
- **Transport honesty.** `PROV_FEDERATION_TRANSPORT=wireguard` no longer implies a
  distinct wire protocol. The federation protocol is always WSS (outbound TLS 443 +
  Ed25519 auth); `wireguard` documents that the WSS link rides a WireGuard/VPN underlay
  (point `PROV_HUB_URL` at the overlay address). Both values run identical code.
- Uses the pre-existing `pending_public_key` column (no new migration). See
  docs/federation.md ("Key rotation", "Transport").

## v0.53.0 — Federation site-as-tenant

A multi-tenant **hub** now isolates federated sites per tenant, completing the MSP shape where one
hub serves many provider customers. Off by default and a no-op unless multi-tenancy is enabled.

- **A site belongs to the tenant that minted its join token.** The site, its aggregated read-cache
  (inventory, sessions, scans, schedules, playbook runs, SFTP transfers), and its sync state are all
  owned by that tenant and enforced by Postgres row-level security.
- **Everything hub-side is tenant-scoped.** The Sites list, the top-bar site selector, the aggregated
  cross-site inventory and dashboards, and the proxy all show and reach only the acting tenant's own
  sites. A cross-tenant site id resolves to *not found* — the proxy (browser terminals, SFTP, every
  management page) can never reach another customer's infrastructure.
- **No change for single-tenant / non-multi-tenant hubs.** Every site simply belongs to the default
  tenant, exactly as in v0.52.0. Standalone instances are unaffected.
- Migration `0062` adds tenant scoping + RLS to the federation and cache tables. See
  docs/federation.md ("Federation and multi-tenancy").

## v0.52.0 — Multi-site federation

Turn one Provenance instance into a **hub** — a single pane of glass over many independent **site**
instances, each a full autonomous Provenance stack on its own network. Opt-in and **off by default**
(`PROV_MODE=standalone`): a standalone instance builds and mounts none of it and is unchanged.

- **Site-initiated tunnels.** Sites need no inbound reachability — each dials the hub over a single
  outbound WSS connection (yamux-multiplexed); the hub never routes back into a site.
- **Ed25519 trust, no shared secrets.** The hub generates a federation identity on first boot
  (encrypted at rest with `PROV_CA_PASSPHRASE`); a site generates its own keypair at join and pins
  the hub's key fingerprint (MITM defense). Every hub→site action carries a short-lived, hub-signed
  **acting-user assertion** bound to one exact request (`sha256(method+path+body)` + single-use nonce).
- **Single pane of glass.** On a hub, a top-bar **site selector** points the *entire* UI at a chosen
  site — host list, terminals, SFTP, databases, Kubernetes, scans, playbooks, schedules, audit — all
  transparently proxied to the site's own unmodified API (a request interceptor rewrites `/api/v1/*`).
- **Autonomy + trust boundaries.** Each site runs proxied requests through its **own** handlers under a
  site-local shadow user, so it enforces its own RBAC/[access policies](access-policies.md) and keeps
  its own **authoritative** audit hash-chain (the hub keeps a linked copy) — the hub is an
  authorization initiator, never a bypass. A site keeps working if the hub or WAN is down.
- New `internal/federation` package, `Federation.Manage` permission, **Sites** page, and migrations
  `0060`/`0061`. Verified end-to-end with a live hub+site (join, link, cross-site proxy, revoke). See
  docs/federation.md — including how federation composes with multi-tenancy.

## v0.51.0 — ITSM two-way sync

The ITSM integration (v0.48.0) now writes the **decision back** to the linked ticket: when an access
request is approved or denied, Provenance posts a ServiceNow *work note* or a Jira *comment* recording the
outcome, who decided, and the granted duration (audited as `approval.ticket_update`). Best-effort, so
a decision is never blocked on the ITSM. Closing/transitioning the ticket remains the ITSM workflow's
job. Verified end-to-end (request → ticket opened → approval → comment written back). See docs/itsm.md.

## v0.50.0 — External secrets: AWS Secrets Manager

The external secrets manager (vault-of-record, v0.47.0) now supports **AWS Secrets Manager**
alongside HashiCorp Vault KV. Back a vault credential with an AWS secret (name or ARN, optionally
`#field` to extract one key from a JSON secret); Provenance fetches it on demand via a SigV4-signed
`GetSecretValue` — no AWS SDK, and no local copy is stored. Configure with `PROV_EXTSECRET_AWS_*`
(an endpoint override supports emulators). The SigV4 signer is now shared (`internal/awssig`)
between AWS KMS and Secrets Manager. Verified end-to-end against LocalStack. See
docs/external-secrets.md.

## v0.49.0 — Database broker: MongoDB

The database broker now speaks **MongoDB** alongside PostgreSQL/MySQL/MariaDB/SQL Server. Because
MongoDB is document-oriented, its console takes a **MongoDB command document as JSON** (e.g.
`{ "find": "users", "limit": 10 }`) and returns the result as formatted JSON, with the same
vaulted-credential injection and `db.query` auditing as the SQL engines.

- The MongoDB driver opens several connections, so each driver dial gets its **own fresh jump
  tunnel** (rather than the single shared tunnel the SQL engines use); the tunnels are wrapped to
  tolerate the driver's deadline calls (SSH channels don't support them). This hardening also covers
  the MySQL/SQL Server drivers over the real jump tunnel.
- Migration `0059` widens the engine constraint; the Databases page adds MongoDB (default port
  27017) and a JSON-command console. Verified end-to-end against a live MongoDB (`listDatabases` and
  `find` through the broker with a vaulted credential). See docs/database-broker.md.

## v0.48.0 — ITSM integration (ServiceNow / Jira)

Tie privileged access to change management. When enabled, Provenance opens a **change/incident ticket**
in ServiceNow or Jira for each just-in-time access request and attaches the ticket reference to the
approval, so every grant carries a change record.

- Best-effort and non-blocking: if the ITSM is unreachable the access request still proceeds
  (failures logged, successes audited as `approval.ticket`). The ticket reference and link are
  included in the approval notification.
- Configure under Settings → Integrations (`System.Configure`): provider, base URL, user, token,
  and table/project. The token is sealed at rest and never returned by the API; a **Test
  connection** button validates credentials without creating a ticket.
- New `internal/itsm` (ServiceNow + Jira clients, stdlib HTTP, no SDK) and `itsm/config` +
  `GET/PUT /itsm/config`, `POST /itsm/test`. Verified end-to-end (a request opened a ServiceNow
  ticket and attached its reference). See docs/itsm.md.

## v0.47.0 — External secrets manager (vault-of-record)

A vault credential can now be **external-backed**: instead of Provenance storing the secret material, the
credential references it in an external secrets manager (**HashiCorp Vault KV v2**), and Provenance
fetches the value **on demand** at point of use. Integrate with the secrets manager your
organization already runs instead of keeping a second copy.

- **No local copy.** An external-backed credential stores only `provider` + `reference` (e.g.
  `secret/db/prod#password`); the local sealed blob is empty. Every reader — reveal, SSH/RDP
  credential injection, the database broker, the Kubernetes broker — resolves the value live through
  one new central resolver (`internal/credresolve`), so it always reflects the manager's current
  contents and is never cached.
- **Manager is source of record.** Provenance does not rotate or re-seal external-backed credentials
  (rotate them in the manager); local rotation is refused.
- Locally-sealed credentials are byte-for-byte unchanged. Configure with `PROV_EXTSECRET_VAULT_*`;
  tick "Store in an external secrets manager" when creating a credential. Migration `0058`. Verified
  end-to-end against a live Vault KV. See docs/external-secrets.md.

Also exposes the `PROV_KMS_*` and `PROV_EXTSECRET_*` settings in the reference compose file so the
external-KMS and external-secrets features are configurable in the standard deployment.

## v0.46.0 — Behavior analytics (UEBA)

Surface access patterns that deviate from a user's established baseline, computed from Provenance's own
session records — no ML, no external dependency, just explainable statistics over data you already
have. Four detectors:

- **Off-hours access** — a session started at an hour outside the user's usual pattern.
- **First access to a host** — a user connecting to a host they've never used.
- **New source IP** — a connection from an address not seen before for that user.
- **Activity spike** — session volume well above the user's daily baseline.

A new **Behavior** page (permission `Audit.View`) lists the anomalies with severity; signals are
advisory ("verify before acting"). New `internal/ueba` (pure, unit-tested engine) and `GET
/ueba/anomalies` computed on demand over a 30-day baseline / 24-hour recent window. No migration —
it reads existing session records. Verified end-to-end (off-hours + new-IP anomalies surfaced from
seeded sessions; normal activity produced none).

## v0.45.0 — Kubernetes access brokering

Broker access to Kubernetes clusters the way Provenance brokers SSH/RDP/databases. Register a
cluster (API server + a vaulted bearer-token credential), and Provenance becomes an **authenticating
proxy**: a user — or their `kubectl` — authenticates to Provenance, and Provenance forwards to the cluster's
API server with the vaulted token injected, **auditing every call**. The operator never sees the token.

- **Resource browser** built in: list pods, deployments, services, namespaces, and nodes per
  cluster/namespace with no kubectl required.
- **Raw authenticating proxy** at `/k8s/clusters/{id}/proxy/*` — point `kubectl` at Provenance with a
  Provenance token and reach the cluster through the broker.
- Per-cluster TLS: verify the API server against a stored CA bundle, or skip verification for test
  clusters. New permissions `Kubernetes.Manage` / `Kubernetes.Access`; migration `0057`; new
  **Kubernetes** page. Every call audited (`k8s.proxy`, `k8s.list`).
- Verified end-to-end against a live k3s cluster (listed real pods; proxied the version endpoint).

## v0.44.0 — Policy-as-code: attribute-based access control (ABAC)

Layer contextual **deny** rules on top of RBAC. An access policy can block a host connection
that a user's roles would otherwise permit, based on **host attributes** (environment, tags,
protocol), **time of day** (business-hours windows, including windows that wrap past midnight,
and specific days of week), with **role exemptions**. Policies only ever *restrict* access —
they never grant it beyond RBAC — and **super administrators are always exempt** (no self-lockout).

- Enforced at every interactive connect choke point — **browser SSH terminal, RDP, SFTP**, and the
  **ad-hoc command runner** — immediately after the RBAC/host-access check. Denials return the
  policy's message and are recorded as `access.denied` audit events (rule, host, surface, reason).
- Rules evaluate first-match-by-priority in the configured display timezone. Example: "deny
  production SSH outside 09:00–18:00, except for the SRE role."
- New **Access Policies** page (permission `AccessPolicy.Manage`) and `access-policies` API;
  migration `0056`. The evaluation engine is pure and exhaustively unit-tested; enforcement was
  verified end-to-end (a non-admin blocked from a production host with the rule's message; the
  admin exempt; disabling the rule restores access).
- Note: scheduled/automation runs (Ansible playbooks, PowerShell scripts, scheduled scans) are
  service-account governed and not subject to time-of-day ABAC.

## v0.43.0 — KMS backends: Azure Key Vault & GCP Cloud KMS

Two more external KMS backends for master-key protection (v0.40.0), so the CA and vault
passphrases can be wrapped by the KMS your organization already runs:

- **Azure Key Vault** (`PROV_KMS_PROVIDER=azure-keyvault`) — wrapKey/unwrapKey (RSA-OAEP-256);
  the key never leaves the vault. Azure AD client-credentials auth with token caching.
- **GCP Cloud KMS** (`PROV_KMS_PROVIDER=gcp-kms`) — encrypt/decrypt on a cryptoKey. Service-account
  auth via an RS256-signed JWT exchanged for an access token.

Both are implemented against the vendor REST APIs directly — **no cloud SDK** — joining the existing
HashiCorp Vault Transit and AWS KMS backends behind the same `internal/kms` interface, `provctl kms`
tooling, and the Settings "Encryption at rest" status card. See docs/kms.md.

## v0.42.0 — Customizable dashboard Quick Connect

The dashboard **Quick Connect** list is now personalizable. Click the tune icon to pick
exactly which hosts appear — and in what order — instead of the automatic top-6. Leave the
selection empty to restore the automatic list (online hosts first). The choice is stored
**per user** and follows your account across browsers and devices.

- New reusable per-user preference store: `user_preferences` table (migration `0055`), store
  helpers, and a self-scoped `GET/PUT /preferences/{key}` API (any signed-in user manages only
  their own preferences; keys are whitelisted). A foundation for further personalization.
- The dashboard falls back gracefully: pinned hosts you can no longer reach are skipped, with a
  hint to update the list.

## v0.41.1 — Offline .guac player: drop a recording anywhere

The offline RDP recording player only accepted a file dropped precisely on a small box.
Now the **entire page** is a drop target: dragging a `.guac` file over the window shows a
large, unmistakable overlay ("Drop your .guac recording to play it — release anywhere on the
page"), and releasing anywhere loads it. The click-to-browse area is also enlarged with
clearer copy. Prevents the browser from navigating away when a file is dropped off-target.

## v0.41.0 — Database broker: MySQL, MariaDB & SQL Server

The database broker (v0.39.0) now speaks three more engines. Register a **MySQL**,
**MariaDB**, or **SQL Server** target alongside PostgreSQL and run brokered SQL through the
jump host with the same vaulted-credential injection, row/statement caps, and `db.query`
auditing — the operator never sees the password.

- Each engine connects over the existing single SSH-tunneled connection: the per-engine driver
  (pgx for Postgres, the MySQL wire protocol for MySQL/MariaDB, TDS for SQL Server) runs over the
  tunnel via a one-shot dialer. No cloud SDK is pulled into the binary.
- The SQL console adapts per engine: engine-aware default port (5432 / 3306 / 1433) and starter
  query (`LIMIT` vs `TOP`). Row-returning statements render a grid; other statements report rows
  affected.
- Migration `0054_database_broker_engines` widens the engine constraint; existing PostgreSQL
  targets are untouched.

## v0.40.0 — External KMS / HSM for master-key protection

Provenance's at-rest secrets (the CA signing key and every credential-vault entry) were already
AES-256-GCM sealed with a passphrase. That passphrase can now be **protected by an external
Key Management Service or HSM** instead of living in the environment as plaintext — the
near-universal enterprise security-review requirement, *"is the master key in a KMS/HSM?"*

- **Unseal-via-KMS.** Wrap your `PROV_CA_PASSPHRASE` / `PROV_VAULT_PASSPHRASE` once with the
  external KMS (`provctl kms wrap`) and store only the opaque wrapped blob
  (`PROV_CA_PASSPHRASE_WRAPPED` / `PROV_VAULT_PASSPHRASE_WRAPPED`). At boot Provenance makes a single
  Unwrap call to recover the passphrase into memory. A stolen disk or database backup is useless
  without live access to the KMS.
- **No re-seal, no format change.** The on-disk sealed-data format is unchanged, so enabling (or
  disabling) a KMS backend needs no migration and no re-encryption — only the passphrase *source*
  moves. The default provider is `local`, which preserves prior behavior exactly.
- **Backends:** **HashiCorp Vault Transit** (encryption-as-a-service; the key never leaves Vault)
  and **AWS KMS** (Encrypt/Decrypt), both implemented against the provider HTTP APIs with **no
  cloud SDK dependency** (SigV4 signing is validated against AWS's published test vector). An AWS
  endpoint override supports KMS-compatible emulators. Azure Key Vault / GCP KMS slot into the
  same `internal/kms` interface next.
- **Tooling & visibility:** `provctl kms status | wrap | unwrap`, and a read-only **Encryption at
  rest** card (Settings → Infrastructure) showing the provider, key ID, live backend health, and
  whether each passphrase is KMS-wrapped. New `GET /kms/status` (System.Configure).
- Fail-closed: production refuses `PROV_KMS_VAULT_SKIP_VERIFY`, and the CA/vault passphrase
  distinctness and length invariants are re-checked after unwrapping. See docs/kms.md.

## v0.39.0 — Database access brokering (PostgreSQL)

Provenance now brokers privileged access to **databases**, not just SSH/RDP hosts. Register a
PostgreSQL target (address, port, database, and a vaulted credential), then run SQL from the
new **Databases** page: Provenance reaches the database **through the jump host**, injects the
vaulted credential (you never see the password), executes your statement, and **audits it**.

- Zero-knowledge: the database password is decrypted in RAM at point of use and never returned
  to the client; the connection authenticates as the credential's user.
- Reuses the existing spine — the jump-host tunnel (`DialRawViaJump` with your session
  certificate), the credential vault, RBAC, and the hash-chained audit log. Every query is
  recorded (`db.query`) with who ran what against which database.
- New permissions `Database.Manage` (register/edit/delete targets) and `Database.Connect`
  (open a session and run queries); a results grid with row/statement caps. Migration
  `0053_database_broker`.
- First engine is PostgreSQL (reuses the bundled pgx driver); the model is built to extend to
  MySQL/others. This version executes one statement per request (no persistent transaction/
  session yet).

## v0.38.0 — Scheduled automatic credential rotation

The credential vault could already rotate a password on its host **on demand**; it can now do
so **automatically on a schedule**. Set a rotation interval (1/7/30/60/90 days) on a password
credential from the Credentials page, and a background job rotates it on its host every
interval — generating a new value, changing it over SSH, verifying it by re-login, and storing
the new sealed version. No one ever sees the password.

- Reaches the host with a short-lived **system certificate** through the jump hop (no user
  session required); the change-and-verify contract is shared with the on-demand path.
- **Backs off on failure** (retries at the next scheduled time rather than every check) and
  emits `credential.rotated` / `credential.rotate_failed` notifications; every rotation is
  audited.
- Leader-gated and RLS-bypassed so one instance rotates due credentials across all tenants,
  with each stored version tagged to the credential's own tenant.
- New knob `PROV_VAULT_ROTATION_CHECK` (default 30m) sets how often the leader scans for due
  credentials. Migration `0052_vault_rotation`.

## v0.37.1 — Multi-tenancy: keep the audit hash-chain global (append fix)

Completes the audit-chain hardening started in v0.37.0. `AppendAudit` read the previous hash
inside the request's tenant-scoped transaction, so under multi-tenancy an event written while
acting inside a customer tenant chained to that tenant's last *visible* hash instead of the true
global head — corrupting the single global hash chain and defeating tamper-evidence.

The chain-head read, advisory lock, and insert now run under RLS bypass so `prev_hash` is always
the true global head regardless of the caller's tenant, while the row's `tenant_id` is set
explicitly (so tenant-scoped audit reads still work; `tenant_id` is deliberately not part of the
hashed record). Verified: an audit event created while acting inside a customer tenant now chains
to the global head and is tagged with that tenant, and the chain tail is internally consistent.
Single-tenant deployments are unaffected. (v0.37.0 already fixed the verification side to read the
chain globally.)

## v0.37.0 — Compliance evidence pack (PDF)

Adds a single, auditor-ready PDF to the Reports page that complements the existing per-domain
CSV exports. For a chosen date range it bundles:

- an **audit-log integrity attestation** — a genesis-to-latest verification of the hash-chained
  audit log, stated as PASS (chain cryptographically intact) or FAIL with the broken sequence.
  This is Provenance's tamper-evidence guarantee rendered as evidence auditors can file;
- summary statistics for privileged access (sessions, distinct users/hosts), certificate
  issuance (and revocations), scan posture (pass/fail), vulnerabilities (with critical/high
  counts), and privileged-command activity (flagged/blocked).

Generated server-side as a real PDF (pure-Go, CGO-free), white-label aware, with the full
line-item detail still available as the individual CSV exports. Gated by `Audit.View`.

Also fixed: the audit-chain verification (`/audit/verify` and the new attestation) now runs
globally regardless of the caller's tenant — the hash chain is a single cross-tenant sequence,
so a tenant-scoped read would hide rows and falsely report the chain broken.

## v0.36.5 — Multi-tenancy: scope token-authenticated endpoints

Fixes a multi-tenancy correctness bug (single-tenant deployments unaffected). Endpoints that
authenticate with a token instead of the `RequireAuth` middleware — the WebSocket terminal,
session-watch, RDP session, plus the RDP-recording / scan-report streams and the enrollment
agent — resolve the caller under RLS-bypass but then ran their queries without re-applying the
caller's tenant. Under multi-tenancy that made row-level security deny the row: opening a
terminal to one of your own hosts returned "host not found", and the terminal's detached
finalize writes (session-end audit, recording metadata) were silently dropped.

Each such endpoint now scopes its work to the caller's tenant (`Auth.TenantScope`), including
the **detached `context.Background()` contexts** that outlive the request (terminal finalize +
command-policy audit/waiver/approval; RDP disconnect finalize). Verified end-to-end with
multi-tenancy on: the terminal connects and its `session.start`/`session.end` audit events are
recorded under the correct tenant; cross-tenant isolation is unchanged. The live-events socket
needs no change (it pushes in-memory events and issues no tenant-scoped query).

A verification pass over an earlier code review confirmed most flagged issues were already
fixed; this closes the few real remainders.

- **Retention now covers issued certificates and resolved access requests.** The activity-
  retention loop additionally prunes expired `ssh_certificates` (keyed on expiry, so an
  unexpired cert is never removed; the KRL is built from `cert_revocations`, unaffected) and
  resolved `approval_requests` — skipping any pending request or any request still holding a
  live grant, so pruning can never strip a user's access. Both were previously unbounded.
- **WebSocket access tokens no longer travel in the URL.** The browser terminal, live-events,
  and session-watch sockets now carry the short-lived token in the `Sec-WebSocket-Protocol`
  subprotocol instead of a `?token=` query parameter, so it no longer appears in reverse-proxy
  access logs. The server still accepts the query parameter as a fallback for older/non-browser
  clients.
- **Removed dead CSRF-validation middleware.** State-changing API calls authenticate with a
  Bearer token (which a cross-site page cannot forge) and the only cookie-authenticated
  endpoints use SameSite=Strict cookies, so the unused double-submit validator was removed and
  the design documented in place.

## v0.36.3 — Wider third-party CVE coverage on Windows

- Expanded the curated Windows app→CPE dictionary from 19 to 35 entries, so more installed
  third-party software is matched against NVD CVEs during a vulnerability scan: WinRAR,
  TeamViewer, Slack, Oracle VirtualBox, VMware Workstation, GIMP, Audacity, KeePass,
  KeePassXC, Dropbox, Opera, Apache Tomcat, Apache HTTP Server, MySQL Server, nginx, Grafana,
  and Jenkins. Same precision-first rule — only confident NVD vendor/product identifiers;
  apps still not in the dictionary are reported as not scanned rather than guessed. (Zoom,
  Redis, and MongoDB were deliberately left out: Zoom's CPE is inconsistent, and the Redis/
  MongoDB names collide with their separate GUI tools. "MySQL Server" is matched specifically
  so MySQL Workbench doesn't inherit the server's CVEs.)

## v0.36.2 — System Health page reachable on direct load

- **Fixed** the System Health page showing raw `{"status":"ok"}` JSON on a hard refresh or
  direct link. nginx proxies the exact path `/health` to the backend liveness endpoint (for
  infra/monitoring probes), which shadowed the SPA's `/health` route. Moved the UI page to
  **`/system-health`**; the `/health` liveness endpoint is unchanged. In-app navigation was
  never affected — only a direct load of that URL.

## v0.36.1 — Session-replay full-screen fix + tenant-switch UX + multi-tenancy compose wiring

- **Tenant switching is now obvious from anywhere.** While a provider admin is acting
  inside a customer tenant, the top bar shows the tenant's **name** ("Tenant: Acme") on
  every page, next to a one-click **Exit** button that returns to the provider's own view
  (clears the tenant header, refetches under the restored context, lands on the dashboard).
  Previously the only always-visible affordance was a generic "In customer tenant" chip
  that merely linked to the Tenants console — the actual switch-back was buried there.
- **Fixed** the "Exit full screen" control being invisible when replaying an SSH session
  full-screen. The replay renders inside a right-anchored drawer (a modal whose stacking
  context tops out just below the app bar), so a top-right exit button was painted over by
  the app bar — the button existed but couldn't be seen or clicked. Moved it to the
  bottom-right (always clear of the app bar) and padded the top of the overlay so the
  caption and first line of output are no longer hidden behind the bar. (The RDP replay's
  full-screen control was already correct — it renders at the page root, not in a drawer.)
- **Compose:** `PROV_MULTI_TENANCY` is now passed through to the backend and
  `PROV_DATABASE_URL` is overridable, so MSP mode can be enabled without editing the
  compose file. Note (documented inline): with multi-tenancy on, the app's DB role must be
  **non-superuser** and lack `BYPASSRLS`, or row-level isolation is silently ineffective.

## v0.36.0 — FIPS 140-3 mode (opt-in, default off)

The FIPS 140-3 mode is available. Opt in with
`PROV_FIPS_MODE=true` (default off — non-FIPS deployments are unchanged: Ed25519,
WireGuard, Argon2id as before).

- **FIPS 140-3 crypto profile** via Go 1.24's native module (`GODEBUG=fips140=on`,
  runtime toggle, one image): ECDSA P-256 CA + identities, pinned SSH suites
  (AES-GCM/ECDH-P256/HMAC-SHA256), PBKDF2 at-rest KDF + password hashing, SHA-256 TOTP,
  ES256/RS256 WebAuthn, TLS 1.2 floor on outbound clients. Fails closed if the module
  isn't active in FIPS mode.
- **Certificate-authenticated overlay (OpenVPN)** as a FIPS alternative to WireGuard,
  **selectable per host** at enrollment (WireGuard remains the default). Its own X.509
  overlay PKI. (A strongSwan/IPsec variant was prototyped but removed until it can be
  validated on real IPsec-capable hosts.)
- **Migration toolset** (`provctl fips check` / `reseal-secrets` / `flag-stale-passwords`,
  verify-then-upgrade-on-login) + a FIPS readiness card in System Health.

Validated in Docker: a FIPS deploy boots with the module active, ECDSA CA, and a green
readiness verdict; a default deploy is byte-for-byte unchanged. Migrations
`0049_overlay_pki`, `0050_host_overlay`.

## v0.35.0 — Multi-tenancy (MSP) — experimental, default off

One deployment can now serve multiple **isolated customer tenants**, for MSPs. Opt in
with `PROV_MULTI_TENANCY=true` (default off — with it off, Provenance is unchanged).

- **Provider manages many customers.** Existing data lands in a seeded **Provider**
  tenant; its admins get a **Tenants** console to create customer tenants and **switch
  into** one to operate within it. Each customer's hosts, users, sessions, credentials,
  audit and everything else are fully isolated.
- **Enforced by Postgres row-level security**, not hand-scoped queries: a `tenant_id` +
  RLS policy on every tenant-scoped table, driven by the request's tenant — so a missed
  filter physically cannot leak, and an unscoped request sees nothing (fail closed).
  Proven end-to-end (a provider can't see a customer's hosts, and vice versa).
- **Requirement:** enabling it needs the app's database role to be a **non-superuser**
  (Postgres superusers ignore RLS). See docs/multi-tenancy-plan.md.

Treat as **experimental** until you've validated it for your data; single-tenant
deployments are entirely unaffected. Migration `0051_tenancy`.

## v0.34.0 — Offline .guac player + content-search keyword highlighting

- **Offline RDP recording player.** A self-contained, cross-platform HTML player for
  downloaded `.guac` recordings — get it from **RDP recordings → "Offline player"**. It's
  a single file that runs in any browser on any OS with **no server and no install**: open
  it, drop in a `.guac` file, and play/pause/seek/full-screen. Recordings are read locally
  and never uploaded. (Bundles Apache Guacamole's player, Apache-2.0.)
- **Content search highlights the keyword.** In Sessions → Content search, the searched
  term is now highlighted in each result snippet for easier scanning.

## v0.33.7 — Full-screen for RDP replay + a visible SSH exit button

- **RDP session replay can now go full screen** — a control it never had. The Guacamole
  desktop scales to fill the viewport, with the same Esc-to-exit and a floating "Exit
  full screen" button.
- **SSH replay exit is now unmissable** — replaced the small top-row icon with a floating
  **"Exit full screen (Esc)"** button fixed to the viewport corner, above the player.

## v0.33.6 — Session replay: reliable full-screen exit

Fixes the recorded-session full-screen view: **Esc now always exits** (the key listener
moved to the capture phase, so the terminal — which could swallow keydowns when focused —
no longer eats it), and the exit control is now a clear **"Exit full screen (Esc)"
button** instead of a small corner icon.

## v0.33.5 — Ask AI: deterministic fast-path for obvious questions

Small local models often mis-route clear questions (answering "who ran df" with fleet
health, or dumping the whole host for an updates question). Ask AI now **bypasses the
model's tool choice** for a couple of unambiguous shapes: it detects the intent, runs
the correct tool directly with the right arguments, and has the model only narrate the
result (with tools disabled so it can't mis-route):

- **"who ran / typed / executed `<command>`"** (optionally "on `<host>`") → `search_commands`.
- **"what are the pending updates" / "which packages need updating" / "what security
  updates are pending"** (optionally per host) → `host_updates`.

It's high-precision — anything it doesn't clearly recognize still goes through the normal
model-driven tool loop, so nothing else changes. This makes those answers reliable
regardless of how capable the configured local model is.

## v0.33.4 — Ask AI: focused host_updates tool (no more whole-host dump)

Asking Ask AI "what are the pending updates?" used to answer via `host_detail`, which
returns the entire host — so the UI rendered the full host card (OS, filesystems,
interfaces) beneath the answer. A new **`host_updates`** tool returns just the pending
packages (host · package · target version · security) as a focused table, for one host
or all accessible hosts. Update questions now route there; `host_detail` is reserved for
filesystem/network deep-dives. Scoped to the caller's accessible hosts.

## v0.33.3 — Ask AI: route "who ran <command>" to the command tools

Tightened the assistant's tool-selection guidance so questions like "who ran df" /
"did anyone run rm -rf" go firmly to **search_commands** (interactive terminals) and
**recent_commands** (Provenance Run-Command), instead of being answered by the fleet-health
tool. `prov_insights` is now scoped explicitly to health/capacity questions only.
Helps smaller local models route these correctly. (Prompt-only; requires the assistant
tools from v0.33.0 to be deployed — if your Sessions page has no "Commands" tab, deploy
the newer build first.)

## v0.33.2 — Sessions: "Commands" search view

A new **Commands** tab on the Sessions page searches the commands users **typed** in
recorded terminal sessions ("who ran `X`"), backed by the v0.33.0 command index — fast
and across all history (unlike the on-the-fly Content search). Filter by host, see
user/host/time/command, and jump straight to the session replay. Gated by
Session.Replay, scoped to the caller's accessible hosts, and audited. Results are a
best-effort reconstruction (tab-completion / recalled history may be partial) and cover
recorded sessions only. New endpoint `GET /api/v1/session-commands`.

## v0.33.1 — Host detail: pending-update package list

The host-detail dialog now shows the **pending update packages** collected in v0.33.0,
not just the count: a scrollable "Pending updates" list under System, each entry showing
the package name and target version, security fixes flagged and sorted first. Appears
once the monitor has collected the list (frontend-only; no migration).

## v0.33.0 — Ask AI: command history & update details; session-replay full screen

Four enhancements, led by deepening the Ask AI assistant.

- **Ask AI — "who ran command X".** Two new assistant tools:
  - **`recent_commands`** — the authoritative record of commands run through Provenance's
    Run-Command feature (exact command, who ran it, target, status, exit code, when),
    gated by Command.Run.
  - **`search_commands`** — searches the commands users **typed** in recorded interactive
    SSH sessions, reconstructed from the recordings (backspace/Ctrl-U/escape aware). A
    background indexer builds a full-text index (backfilling existing recordings); search
    is scoped to the caller's accessible hosts and gated by Session.Replay. This is a
    best-effort reconstruction (tab-completion / history-recall may be partial), so the
    assistant qualifies results as "typed", and it only covers recorded sessions.
- **Ask AI — which packages need updating.** The monitor now collects the actual pending
  **update package list** per host (name, target version, security flag — apt/dnf/yum),
  not just the counts, so `host_detail` (and the API) can answer "which packages need
  updating on web-01".
- **Session replay — full screen.** The recorded-session player has a full-screen toggle
  (Esc to exit) with a larger font, re-fitting on resize, so recordings are easier to read.

Migrations: `0049_host_update_packages`, `0050_session_commands`. Command indexing runs
in the background after startup; on a large recording archive the first pass may take a
few minutes to backfill.

## v0.32.3 — Fix: vulnerability scan 504 "scan timed out" on large hosts

The grype scanner sidecar capped each scan at **5 minutes** (`GRYPE_SCAN_TIMEOUT`,
its built-in default) while the backend was willing to wait **20 minutes**
(`PROV_VULN_SCAN_TIMEOUT`) — and the bundled compose never overrode the scanner's
cap. A host with a large package database (e.g. an ML/CUDA box with thousands of
installed packages) legitimately takes longer than 5 minutes to scan, so it always
came back as `scanner error (504): scan timed out` even though the backend would have
waited.

- The scanner's per-scan timeout now **defaults to 20 minutes**, matching the backend,
  and is exposed as `GRYPE_SCAN_TIMEOUT` (seconds) in the compose file and
  `.env.example`. Raise both it and `PROV_VULN_SCAN_TIMEOUT` further if a host still
  times out.
- **Deploy:** pull, then recreate the scanner: `docker compose up -d grype-scanner`
  (no rebuild needed unless you also want the updated in-image default). Existing
  `.env` values are respected.

## v0.32.2 — Fix: blank Disaster Recovery page + stuck Authentication settings

Two UI robustness fixes.

- **Disaster Recovery page no longer blanks on a single instance.** The page crashed
  to a white screen when this instance is a primary with no downstream standbys —
  the API returned `replicas: null` and the page called `.length`/`.map` on it. The
  page now normalizes that to an empty list, and the backend returns `[]` instead of
  `null`.
- **Authentication settings (OIDC / LDAP / SAML) no longer hang on "Loading…".** If a
  card's config request fails, it now shows a clear error with a **Retry** button and
  a hint to hard-refresh (a stale cached bundle after an update is the usual cause),
  instead of an indefinite spinner. The backend endpoints were already fine; this is
  purely making the cards fail visibly rather than silently.

**Deploy:** `make redeploy-single`, then **hard-refresh your browser**
(Ctrl/Cmd-Shift-R) — a redeploy invalidates the old bundle/session, and a cached SPA
can otherwise show stale-load symptoms.

---

## v0.32.1 — Fix: fleet-wide vulnerability scans timing out at the scanner

A scheduled "scan all hosts" could fail several hosts with
`scanner unreachable: Post "http://grype-scanner:8000/scan": context deadline
exceeded (Client.Timeout exceeded while awaiting headers)`. Root cause: the
scheduler fans out up to 16 host scans at once, but the grype-scanner sidecar ran a
**blocking** `grype` call inside an **async** handler on a **single worker** — which
froze its event loop and processed scans strictly one at a time. Hosts stuck at the
back of that serialized queue blew past the backend's timeout.

- **Scanner now processes scans concurrently, bounded.** grype runs off the event
  loop with a small concurrency cap (`GRYPE_SCAN_CONCURRENCY`, default 2 — grype is
  CPU/memory-heavy, so it's deliberately modest and tunable per host size). Extra
  requests queue with the worker responsive instead of freezing it.
- **Backend scan timeout is now realistic + configurable.** A per-host request that
  legitimately waits behind others no longer fails at a hard 6 minutes; the bound is
  `PROV_VULN_SCAN_TIMEOUT` (default **20 minutes**), applied to both the HTTP client
  and the per-scan context.

**Deploy:** rebuild the scanner + backend — `make redeploy-single` (it rebuilds
`grype-scanner` and `backend`). Then re-run the scan or clear the recent failures on
the Vulnerabilities page. On a small box, keep `GRYPE_SCAN_CONCURRENCY` at 1–2; raise
it on a beefier host.

---

## v0.32.0 — Read-only DR standby mode (usable warm standby)

Makes the two-site warm standby (v0.31.0) actually **runnable on the replica**.
Previously, a standby Provenance pointed at a read-only replica couldn't serve requests
(login/audit/heartbeat all write), so the DR console could only *finish* a failover
after the database was promoted by other means. Now Provenance detects the replica and
runs in a dedicated **standby mode**:

- **Automatic detection.** On startup Provenance checks `pg_is_in_recovery()`. If its
  database is a replica it boots read-only: **migrations are skipped**, **no
  background writers start** (cluster/monitor/scheduler/CA — none of which a replica
  can service), and the API surface is reduced to a health check plus the DR
  standby console. Migrations auto-skip on a replica, so the old
  `PROV_MIGRATE_ON_START=false` requirement is now just belt-and-suspenders.
- **Break-glass standby console.** The web UI detects standby posture (unauthenticated
  `GET /dr/mode`) and replaces the whole app with a console showing **live replication
  lag** and a **Promote this instance to primary** action — authenticated by a static
  **`PROV_DR_STANDBY_TOKEN`** (a login can't be used: the replica can't write a
  session). Promotion runs `pg_promote()` and the instance **restarts into full normal
  mode** against the now-primary database (give the container a restart policy).
- **Peer health still works:** a standby answers `/ready`, so the primary's DR page
  shows it reachable.

Validated end-to-end against a real streaming replica (base-backup standby):
detection, migration/writer suppression, lag reporting, token-gated promotion, and
the restart-into-primary handoff. See the updated **Two-site warm standby** section of
`docs/disaster-recovery.md`. No migration; standby mode is inert until an instance is
actually pointed at a replica, so existing single-instance deployments are unaffected.

## v0.31.0 — Disaster Recovery console (two-site warm standby)

A new **Disaster Recovery** page (nav; `DR.Manage` — Super Administrator +
Administrator by default) for running Provenance as **two independent instances** — an
active primary and a warm standby at a second site — with administrator-triggered
**failover / failback** from the UI.

- **Live status:** whether this instance's PostgreSQL is a **standby (in recovery)**
  and its **replay lag**, the **connected standbys** when it's a primary (from
  `pg_stat_replication`), and the **reachability of the peer instance** (`/ready`).
- **Force failover / Force failback:** run from the instance taking over. Each
  optionally runs **`pg_promote()`** on this instance's database (enable "Also
  promote this database" when the standby steps up), then **POSTs a configured
  webhook** — which you wire to your DNS repoint + standby jump-host WireGuard
  bring-up — and audits every step (`dr.failover` / `dr.failback` / `dr.promote`,
  hash-chained). Guarded by a confirmation dialog.
- **Configuration:** role label (standalone / primary / standby), peer URL, and the
  failover/failback webhook URLs.

**Scope boundary (by design):** the console is a **trigger + status surface**, not
the orchestrator — Provenance does not replicate the database or move DNS itself.
`pg_promote()` works only when this DB is actually a standby and the role may run it
(superuser-only unless you `GRANT EXECUTE ON FUNCTION pg_promote`); the console
surfaces the DB's error verbatim otherwise. Full runbook — replication setup, the
mandatory secret-parity checklist (`PROV_CA_PASSPHRASE` is the linchpin), host
reachability options, and the failover/failback procedures — is in the new **Two-site
warm standby** section of `docs/disaster-recovery.md`. Migration `0048` (the
`DR.Manage` permission) applies automatically; no schema tables are added.

## v0.30.0 — Ad-hoc command runner (Linux)

Run a one-off shell command on one or many Linux hosts without authoring a
playbook — the lightweight counterpart to Ansible playbooks and PowerShell scripts.
A new **Ad-hoc Command** tab on the **Automation** page (`Command.Run`) takes a
command and a host/group target, runs it over the jump host, and streams the
aggregated per-host output; recent runs are listed with status.

- **Governed by command control.** Every command is evaluated against the
  command-control policy (v0.29.0) per host *before* it runs: a **blocked** command
  is refused on that host, an **approval-gated** one is refused and files an
  approval request (and runs once a waiver is granted), and a **flagged** one runs
  with an audit + alert. So the ad-hoc runner can't be used to bypass the rules
  that apply to interactive sessions.
- **Safe + scalable by construction.** Runs as each host's configured SSH user
  through the jump host, with a **bounded worker pool** (6 hosts at once), a
  per-host **timeout**, and a **4 MiB output cap**. Windows hosts are rejected (use
  PowerShell scripts). HA-aware: a run abandoned by a dead instance is reconciled to
  `failed` on startup. Every run is audited (`command.run`).
- API: `POST /commands/run`, `GET /command-runs`, `GET /command-runs/{id}`.
  Migration `0047` (the `command_runs` table + the `Command.Run` permission,
  Administrator-only by default) applies automatically.

This is the raw ad-hoc runner deferred from v0.25.0 — it ships now that command
control exists to govern it, rather than ungoverned.

## v0.29.0 — Command control (privileged-command policy)

Define rules that match commands typed in interactive terminal sessions and act on
them — a core PAM control. A new **Command Control** page (`CommandPolicy.Manage`)
manages the ruleset; enforcement happens at the terminal relay.

- **Three per-rule actions:** **flag** (allow, but audit + alert), **block**
  (refuse to run — the relay withholds the command and clears the line), and
  **approval** (refuse until an approver grants a time-boxed waiver, then the user
  re-runs it). Patterns are RE2 regular expressions matched against each command
  line.
- **Scope:** each rule is **global** or scoped to a **host group** (e.g. stricter
  blocks on production). A host's applicable rules are loaded once per session.
- **Approvals:** an approval-gated command creates a request; an admin approves it
  from the Command Control page (you can't approve your own — separation of duties),
  granting a 10-minute waiver. Every decision is audited and notified.
- **Fully audited:** `command.flagged` / `command.blocked` /
  `command.approval_requested` / `command.approved_run`, plus notification event
  types you can route (flagged / blocked / awaiting-approval).

**Important — what this is and isn't:** enforcement inspects the interactive input
stream, so it is a strong **deterrent and a complete audit trail**, not a
cryptographic guarantee. A determined insider can obfuscate (paste-splitting,
base64, launching a sub-shell or editor). It raises the bar and records intent; it
does not make a hostile operator harmless. Hosts with **no** rules are completely
unaffected — the input path is an unchanged, zero-overhead passthrough. Migration
`0046` (rules + approvals + the `CommandPolicy.Manage` permission) applies
automatically.

## v0.28.0 — Provenance-wide session content search

Search across recorded terminal sessions for a string — "who ran `X`, where, and
when" — instead of opening recordings one by one. A new **Content search** tab on
**Session Replay** (`Session.Replay`) takes a query and returns the matching
sessions with **context snippets**, each linking straight to its replay.

- Searches the recorded session content (the terminal output stream, which echoes
  what was typed), across the most recent recordings. ANSI escape codes and control
  characters are stripped so matches are on the visible text, not terminal codes.
- **Bounded by design:** a single query scans the most recent 500 recordings, caps
  the bytes read per recording, and returns snippets/results within fixed limits —
  the response says how many recordings were scanned and whether the set was capped
  (so you can narrow with a more specific term). Keeps search cost predictable
  regardless of history size.
- Session content is sensitive, so **every search is audited** (`session.search`,
  with the query and match count). Endpoint: `GET /sessions/search?q=`.

*Note:* this searches recorded **content**; there is no separate parsed
command-history store (Provenance records full PTY sessions, not individual commands).

## v0.27.0 — In-browser config-file editor

Edit a remote text file — `/etc/nginx/nginx.conf`, a `.env`, a unit file — right in
the **Files** browser, without downloading, editing locally, and re-uploading. Each
file row now has an **Edit** (pencil) action that opens the contents in a monospace
editor; **Save** writes it back over the same audited jump-host/SFTP path.

- **Automatic on-host backup.** Before overwriting, Provenance copies the current file
  to `<name>.provbak-<timestamp>` on the host (toggle off if you don't want it), so
  a bad edit is always recoverable. The save reports where the backup went.
- **Safe by construction.** The editor refuses files over 2 MiB or that look
  binary (contain NUL), and **preserves the file's existing permissions** on save.
  It's gated by the same **`File.Transfer`** permission and per-host access as
  upload — this is a nicer, audited UX over a capability SFTP already had (you can
  overwrite files today), not a new one. Reads and writes are audited
  (`sftp.read` / `sftp.edit`).
- New endpoints: `GET /hosts/{id}/sftp/read`, `POST /hosts/{id}/sftp/write`.

## v0.26.0 — Expiry & Rotation dashboard

A new **Expiry & Rotation** page (nav; `System.Configure`) gives one at-a-glance
view of the credentials and keys that need lifecycle attention, so nothing silently
ages out:

- **API tokens** that are **expired**, **expiring** within 30 days, or **unused**
  (never used and older than 30 days, or not used in 90 days).
- **Vault credentials** not **rotated** in over 90 days (based on the last version
  written — pairs with the `Credential.Rotate` action).
- **User passwords** older than 90 days (active accounts).
- **CA keys** older than a year (rotation hygiene, informational).

The page shows per-status counts and a table ranked most-urgent first. Everything
is **metadata only** — no secret material is ever read or shown. Backed by a single
read-only endpoint, `GET /lifecycle/expiry`; a healthy fleet shows "nothing needs
attention." Thresholds are fixed for now (they may become configurable later).

## v0.25.0 — Bulk host actions

Act on many hosts at once. Select hosts in the grid (the checkboxes were already
there) and a **Bulk actions** menu appears in the toolbar:

- **Run vulnerability scan** on the whole selection (Linux via grype, Windows via
  MSRC + third-party — each host scanned by the right method).
- **Refresh facts** — queue a re-collect of pending updates / inventory on the
  next monitor sweep for every selected host.
- **Maintenance…** — silence alerts on the selection for 1 / 4 / 8 / 24 hours, or
  clear an active window, in one step (pairs with v0.24.3 maintenance windows).
- **Edit tags…** — add and/or remove tags across the selection (comma- or
  newline-separated); useful for driving dynamic-group membership at scale.

Each action reuses the existing per-host operation and its permission
(`Host.Scan` / `Host.View` / `Host.Edit`), and the server filters the selection to
hosts you can actually access — so a bulk action can never reach a host you
couldn't touch one at a time. Bulk operations are bounded (max 1000 hosts/request)
and audited (`host.bulk_*`). New endpoints: `POST /hosts/bulk/refresh`,
`/hosts/bulk/maintenance`, `/hosts/bulk/tags`, and `hostIds` on `POST /vuln-scans`.

*Note:* a **raw ad-hoc command runner** (type a shell command, run it on a
selection) is intentionally **not** here yet — it's the execution surface the
upcoming **privileged-command policy** work will govern, so it ships alongside
those guardrails rather than ungoverned. Today, run vetted automation in bulk via
the Automation page (playbooks/scripts) or a group schedule.

## v0.24.5 — Fix: couldn't schedule a Vulnerability DB update

The **Create** button stayed greyed out when adding a **Vulnerability DB update**
(`vulndb`) schedule. That kind is fleet-wide and has no host/group target, but the
form still required a target to be selected before enabling **Create** — so it
could never be saved. The button now only requires a target for the kinds that
have one (scan / vulnscan / playbook / script); `vulndb` can be scheduled again.
Frontend-only; the backend already accepted target-less `vulndb` schedules.

## v0.24.4 — Conditional access (IP allowlist + concurrent-session limits)

Gate sign-in on **where** a user connects from and **how many** sessions they may
hold at once — a core PAM control, enforced at session creation across **every**
login method (password, LDAP, OIDC, SAML) so there's no per-IdP bypass.

- **Global policy** under **Settings → Authentication → Conditional access**: an
  **IP allowlist** (CIDRs or bare IPs, one per line — empty = any network) and a
  **max concurrent sessions per user** (0 = unlimited). Saving an allowlist that
  wouldn't include your *own* current IP is **rejected**, so you can't lock the
  fleet out in one click.
- **Per-user overrides** from a user's **Access policy…** action: each dimension
  independently overrides the global default or inherits it (e.g. exempt a service
  admin from the office-network restriction, or give one user a tighter limit).
- **On denial:** the login is refused with a clear message (SSO users land back on
  the login page with the reason), and a `login_blocked` auth event is recorded.
  Idle/absolute session timeouts (already configurable via `PROV_SESSION_IDLE_TTL`
  / `PROV_SESSION_ABSOLUTE_TTL`) are unchanged.
- API: global policy via the existing `PUT /settings/session_policy`; per-user via
  `GET/PUT/DELETE /users/{id}/session-policy` (`User.Edit`, audited).

**Client-IP note:** behind a reverse proxy, set `PROV_TRUSTED_PROXIES` (off by
default) so the allowlist matches the *user's* IP and not the proxy's. Migration
`0045` (per-user override table) applies automatically.

## v0.24.3 — Maintenance windows (silence a host's alerts while you patch)

Mark a host **in maintenance** so its offline / updates-pending / scan-failure
signals stop firing while you patch, reboot, or otherwise take it down on purpose —
no more chasing an "offline" alert you caused yourself.

- **Silence from host details.** The host-details dialog gains a **Silence alerts**
  action (1 / 4 / 8 / 24 hours) and, while active, an **End maintenance** button. A
  host in maintenance shows an **In maintenance** chip in the details header and a
  **maint** chip on the Hosts grid, so a deliberately-silenced host reads differently
  from a genuinely-broken one.
- **What's suppressed.** While the window is open, the monitor doesn't emit
  offline/recovered **alerts** for the host and the **dashboard insights** skip it —
  so it drops out of "needs attention" — but health-checking, fact collection, and
  metrics keep running, so status is still current when you look. The window ends
  automatically when the timer passes.
- API: `POST /hosts/{id}/maintenance` (`{minutes}`, default 60, capped 30 days) and
  `DELETE /hosts/{id}/maintenance`, both gated by `Host.Edit` and audited
  (`host.maintenance_set` / `host.maintenance_clear`).

**Deploy:** migration `0044` (adds `hosts.maintenance_until`) applies automatically.

## v0.24.2 — `make redeploy-single`: update app code without dropping the overlay

Root-caused the recurring "hosts offline for minutes after a deploy" on a single
instance: `make up-single` runs `compose up -d --build`, which **recreates the
jump-host container** — tearing down the WireGuard overlay so every managed host
has to re-handshake before the monitor can reach it (leader election was already
proven instant; this was the actual cause).

New **`make redeploy-single`** updates only the app services
(`backend frontend grype-scanner`) in place, leaving the jump host and overlay
**running** — so a code deploy no longer disrupts host connectivity (just the
few-second backend restart). Use `up-single` for the initial bring-up or jump-host
changes; use `redeploy-single` for routine code updates.

## v0.24.1 — Monitor sweeps promptly on becoming leader (offline-after-restart)

Compounding the leader-handoff delay: while an instance wasn't leader yet, the
monitor's timer still reset to the full sweep **interval** each tick, so even once
it became leader the first host sweep could be up to a whole interval away — hosts
stayed "offline" long after leadership settled. Now the monitor **polls every 5s
until it's leader**, then sweeps and returns to the normal interval — so the first
sweep lands within ~5s of taking over. Combined with v0.23.3's stranded-lock
reclaim, a restart's offline window is now bounded to a few tens of seconds
(instant on a clean handoff).

## v0.24.0 — Scheduled vulnerability scans + CVE database updates

The **Schedules** page gains two new kinds:

- **Vulnerability scan** (`vulnscan`) — run a vuln scan on a recurring schedule
  against a host or group. Works for **Linux** (grype packages) and **Windows**
  (missing Microsoft updates via MSRC + curated third-party apps) in one schedule
  — each host is scanned by the right method. (The engine already supported this;
  it just wasn't creatable — now it is.)
- **Vulnerability DB update** (`vulndb`) — refresh the CVE databases on a schedule:
  the grype vulnerability DB and the MSRC (Windows) mapping, online. Not
  host-targeted (it's fleet-wide); runs in the background so a long DB download
  doesn't block the scheduler.

Set them up under Schedules → "What to run", with the usual interval/daily/weekly
recurrence. Disabled by default like all schedules.

## v0.23.3 — Faster leader takeover after a restart (reclaim stranded lock)

A restart could leave hosts **offline for minutes**: the new backend couldn't
acquire the Postgres leader advisory lock until Postgres reaped the *old* instance's
dropped connection, and the monitor only sweeps as leader. The v0.20.3 graceful
release fixed the clean case, but an unclean stop (SIGKILL, crash, or a pre-fix
outgoing version) still stranded the lock — which is exactly what a single-instance
`make up-single` hit.

Now the **incoming** instance self-heals: if the leader lock is held but no other
instance has a live leader heartbeat, it terminates the stale holder's connection and
takes over — bounding the offline window to the lease (~30s) instead of however long
Postgres takes to notice the dead socket. Also set `stop_grace_period: 30s` on the
backend so the clean, instant handoff has time to complete before SIGKILL.

## v0.23.2 — Host details: "Refresh facts" (don't wait for the hourly check)

Pending-updates counts (and the Windows software inventory) are collected on an
hourly cadence to keep the WinRM/WUA searches cheap, so after patching a host the
dashboard's "security updates pending" can lag until the next check. Host details
now has a **Refresh facts** button that clears the update-check timestamp so the
monitor re-collects that host on its **next sweep** (typically within a minute)
instead of waiting the hour. `POST /hosts/{id}/refresh` (Host.View + access).

## v0.23.1 — Windows third-party app CVE coverage (CPE → grype)

Windows vuln scans now also cover **third-party applications** — Chrome, Firefox,
VLC, 7-Zip, OpenSSL, Node.js, Wireshark, etc. — alongside the Microsoft/MSRC
findings, closing the gap versus the Linux package scan.

- The scan inventories installed software over WinRM (v0.23.0), maps the **curated**
  apps to **CPEs** (`internal/cpe` dictionary, precision-first), builds a CycloneDX
  SBOM, and scans it with the existing **grype** sidecar (new `/scan-sbom` endpoint)
  — matching the CPEs against NVD. Third-party findings merge with the MSRC ones.
- Apps not in the curated dictionary are **not** guessed at (a wrong CPE would
  mislead); coverage ("installed / mapped") is logged. The dictionary starts with
  ~20 high-value apps and is meant to grow.

**Deploy note:** the grype-scanner sidecar gained an endpoint, so rebuild it
(`docker compose build grype-scanner && docker compose up -d grype-scanner`). No
new CVE data source — it reuses grype's existing (online/offline) NVD database.

## v0.23.0 — Windows software inventory (over WinRM)

Provenance now inventories the **installed applications** on Windows hosts, read over
WinRM from the registry Uninstall keys (64- and 32-bit views; Windows/KB updates
filtered out — those are the MSRC path). It's the foundation for third-party CVE
coverage (next), and useful on its own:

- The monitor refreshes each Windows host's software list hourly (same cadence as
  the updates check), stored in a new `windows_software` table (migration `0043`).
- Host details now show an **Installed software (N)** section for Windows hosts.
- API: `GET /hosts/{id}/software`.

Registry reads are fast and side-effect-free (no `Win32_Product`).

## v0.22.1 — Vulnerabilities: fixable subset + severity filtering

Both scanners already report only what's actually on each host (grype reads the
real installed-package DB; the Windows scan uses WUA applicability), but grype's
model surfaces a long tail of low-severity and unfixable ("no fix available")
CVEs. This adds a way to focus on what's **actionable**:

- **Fixable count in the roll-up.** Each host row now shows a **Fixable** column —
  the subset of findings that have an available fix version — next to the total
  (e.g. "380 fixable / 2690 total"). Computed at scan time and stored (migration
  `0042` adds `vuln_scans.fixable`); existing scans show 0 until re-scanned.
- **Filters in the findings view.** A **Fixable only** toggle (findings with a fix
  version) and per-severity toggles, with Negligible/Unknown hidden by default and
  a "showing X of Y" count. This makes the Linux view directly comparable to the
  Windows "missing patches" view — present *and* fixable.

No scanning changes; both filters work on existing scan data.

## v0.22.0 — Windows CVE data from MSRC (real CVE/severity/CVSS)

Windows vulnerability scans now report **real CVE IDs, MSRC severity, and CVSS
scores** — not just "N missing security updates." The Windows Update Agent reports
which KBs a host is missing, but not (reliably) the CVEs/severity they remediate;
that authoritative data lives in Microsoft's **Security Update Guide** (CVRF), keyed
by KB. Provenance now caches that KB→CVE mapping and enriches each finding with it.

- **New `msrc` package** parses CVRF documents; migration `0041` adds
  `msrc_updates` (KB→CVE, severity, CVSS, vector, title, release).
- **Two ways to load the data**, mirroring the grype DB, under **Vulnerabilities →
  Windows CVE data (MSRC)**:
  - **Update online** — fetches the last `PROV_MSRC_MONTHS` releases (default 12)
    from `api.msrc.microsoft.com` (only when you click it; no automatic egress).
  - **Import offline** — for air-gapped deployments: upload a **zip of CVRF JSON**,
    a JSON array of documents, or a single CVRF JSON document.
- The Windows scan looks up each missing KB in the mapping and emits **one finding
  per remediated CVE** with real severity/CVSS (linked to its MSRC page). When a KB
  isn't in the mapping yet, it falls back to the prior KB-level finding, so scans
  still work before the data is loaded.

## v0.21.3 — Clear recent scan failures from the Vulnerabilities page

The "Recent failures" banner now has a **Clear** button that removes failed scan
records (error-only rows with no findings) — `DELETE /vuln-scans/failed`, gated by
`Host.Scan`. Useful for dismissing stale failures, e.g. a Windows host that failed
via the old SSH path before Windows scanning existed (v0.21.0).

## v0.21.2 — Prove a session rode the WireGuard overlay (audit + indicator)

Two ways to confirm/prove a connection went over WireGuard, rather than inferring
it from latency:

- **Audit provenance (proof).** Session-start audit events now record the exact
  address the session was brokered to and whether it is the host's overlay
  address: `session.start` (SSH) and `session.rdp_start` (RDP) carry
  `targetAddress` and `overlay: true|false`. Because the audit log is hash-chained
  and tamper-evident, this is defensible evidence — combined with the (also
  audited) strict-overlay policy being enabled — that a given session used the
  WireGuard overlay. Filter the Audit page by the session action to produce it.
- **At-a-glance indicator.** A green **WireGuard** chip now appears on the Hosts
  and Terminals pages for any host reachable over a healthy overlay (the
  affirmative counterpart to the existing "WG down" chip), so a healthy overlay is
  visible instead of showing nothing. Note: the per-host **latency** figures are
  not comparable across protocols — SSH latency is a full handshake, RDP latency
  is a bare TCP connect — so a lower RDP number is expected and says nothing about
  whether WireGuard is in use.

## v0.21.1 — Clarify: strict overlay mode covers Windows RDP

The **Strict overlay — require WireGuard** setting already forces enrolled hosts
with a WireGuard address to be reachable *only* over the overlay for **RDP**
(Windows desktop) sessions, not just SSH terminal and file transfer — the RDP
connection path has honored it since v0.19.2. The setting's help text only
mentioned terminal and file transfer, so this updates the copy to state that RDP
is covered too. No behavior change: turning it on means a Windows host whose
tunnel is down has its RDP session refused rather than quietly falling back to the
host's direct address.

## v0.21.0 — Vulnerability scanning for Windows hosts

Vulnerability scans now work on Windows (RDP) hosts, alongside the existing
Linux/Grype scans — same **Vulnerabilities** page, same findings/severity model,
same scheduling.

On Windows a host's vulnerabilities are the CVEs remediated by its **missing
security updates**, sourced directly from Microsoft's update metadata via the
Windows Update Agent over WinRM (offline search — no external CVE database, no
grype, no network round-trip). Each missing security update becomes one finding
per CVE it fixes, with severity mapped from **MSRC severity**
(Critical→Critical, Important→High, Moderate→Medium, Low→Low); the CVE links to
its MSRC page and the "fix" is the KB to install. CVSS shows "—" (Microsoft's
metadata is severity-based, not CVSS).

- `internal/vulnscan.Run` branches on `host.Protocol == "rdp"` to the WinRM path;
  Linux hosts are unchanged. Authenticated with the host's open-policy vault
  credential (scans are unattended), tunneled through the jump host.
- Previously, scanning a Windows host silently failed (no SSH / no package DB);
  now it produces real findings. Works for manual scans and group schedules.

## v0.20.4 — Configurable PowerShell script timeout (Settings)

The per-host PowerShell script timeout is now operator-configurable under
**Settings → Hosts → PowerShell scripts** (was fixed at 15 minutes). Set how long
a script may run on a single Windows host before it's stopped (1–240 minutes,
default 15); the whole-run timeout scales from it and the concurrency-bounded
batch count. Stored on the `scripts` setting object as `{"timeoutMinutes": N}`.

For very long jobs (e.g. installing large Windows updates, which the WinRM session
can't hold open — and which the Windows Update Agent won't install from a remote
session anyway), the right pattern is a fire-and-forget script that starts a local
scheduled task on the host and returns, rather than raising this timeout.

## v0.20.3 — Fix: release cluster leadership before the DB pool closes on shutdown

A backend restart/deploy could leave the fleet showing all hosts **offline** for
minutes (and interrupt in-flight singleton work) until leadership was re-acquired.
The cluster coordinator releases its Postgres leader advisory lock on shutdown, but
that step-down ran asynchronously in its goroutine while `main` independently
drained HTTP and then closed the DB pool. When the pool closed first, the
`pg_advisory_unlock` never reached Postgres, so the lock lingered until Postgres
reaped the dead connection — and a standby (or the restarted instance itself)
couldn't become leader until then, so the monitor didn't sweep.

The step-down is now invoked **synchronously in `main` before the pool closes**
(the coordinator's `Stop()` is exported and idempotent), so leadership frees
immediately on a clean stop and the restarted/standby instance takes over on its
next tick — no multi-minute unmonitored window after a deploy. Latent since the
HA work (v0.17.0).

## v0.20.2 — Scheduled PowerShell script runs

PowerShell scripts can now be run on a recurring schedule, just like Ansible
playbooks and scans. The **Schedules** page gains a "PowerShell script (Windows)"
kind: pick a script and a target host or group, set the recurrence, and the
scheduler fires it via the same runner (bounded fan-out, output cap, run history).

Because a scheduled run is unattended (no interactive credential check-out), it
uses only **open-policy** credentials — the same rule the monitor follows. A
scheduled run against a host whose credential is check-out-gated is reported as a
credential failure for that host rather than silently using a gated secret.
Non-Windows hosts in a targeted group are skipped.

## v0.20.1 — Unified Automation page (Ansible playbooks + PowerShell scripts)

The **Playbooks** nav item is now **Automation**, a single page with two tabs:
**Ansible Playbooks** (Linux) and **PowerShell Scripts** (Windows). The Scripts
tab is the UI for the v0.20.0 runner — author/version PowerShell scripts, run them
on one or many Windows hosts or a group (the host picker lists only Windows hosts),
and watch per-host output stream into a live console, with run history and a
drill-down into any past run's captured output.

Each tab appears only if you can author that kind (`Playbook.Edit` /
`Script.Edit`); the old `/playbooks` URL redirects to `/automation`. The Linux
playbook experience is unchanged.

## v0.20.0 — PowerShell script runner for Windows hosts (backend/API)

Run operator-authored **PowerShell scripts on Windows hosts**, the Windows
counterpart to the Ansible playbook runner. Author/version scripts, then run them
on one or many Windows hosts or a group, with streamed per-host output and run
history — all over the existing WinRM path (no new transport, no sidecar; Python
isn't involved). This release lands the backend + API; the unified Automation UI
(Ansible + PowerShell in one place) follows next. Usable now via the API/SDK/CLI.

- **New tables/permissions** (migration `0040`): `winscripts`, `winscript_versions`,
  `winscript_runs`; `Script.Edit` (author/edit) and `Script.Run` (execute), both
  Administrator-only by default, mirroring `Playbook.Edit`/`Playbook.Run`.
- **Execution** runs over WinRM through the jump host, authenticated with each
  host's **vaulted credential honoring its check-out policy** — a check-out/approval
  -gated credential is only used while the requester holds an active check-out.
- **Scalable + safe by construction:** multi-host runs use a **bounded worker
  pool** (one jump connection per host, same cap as the monitor), output is
  **size-capped** (4 MiB, truncation-marked), the script runs on **exactly one**
  WinRM port (TCP pre-probe — never double-executed on port fallback), and each run
  has a bounded timeout. HA-aware: interrupted runs owned by a dead instance are
  reconciled to `failed` on startup.
- API: `GET/POST /scripts`, `GET/PUT/DELETE /scripts/{id}`, `.../versions`,
  `POST /scripts/{id}/run`, `.../runs`, `GET /script-runs/{runId}` (live output).

## v0.19.9 — Windows pending-updates (surfaced in Ask, dashboard, host details)

The WinRM fact collection now also counts **pending Windows updates** and the
security subset, via the Windows Update Agent COM API with an OFFLINE search
(local cache only — no round-trip to Microsoft, the scalable equivalent of
reading cached apt/dnf metadata). The counts land in the same
`updates_available` / `security_updates` inventory fields the Linux path fills,
so the **assistant** (`query_hosts` with `securityUpdatesMin`, `prov_issues`),
the dashboard issues, and host details report Windows update posture with no
further changes — ask "which Windows hosts have security updates" and it works.

The search is throttled to the hourly inventory cadence (heavier than the live
per-sweep metrics), and the counts are preserved between checks — so it adds no
per-sweep cost and doesn't affect monitoring scalability.

## v0.19.8 — Windows enrollment: persist the WireGuard config (survive reboots)

Fixed a Windows tunnel that worked until the first reboot and then crash-looped.
The enrollment script wrote the WireGuard config to `%TEMP%\prov.conf`, installed
the tunnel service from it, and then **deleted** the temp file. WireGuard for
Windows' tunnel service reads its config from that path on every start (it does
not copy it into a store), so after a reboot the service could not load its
config — logging `Unable to load configuration from path: …\Temp\…\prov.conf`
and shutting down repeatedly — and nothing listened on the WireGuard port until
someone reactivated it by hand. No amount of service auto-start/recovery can help
a service whose config file is gone.

The config is now written to a persistent, ACL-locked path
(`%ProgramData%\Provenance\prov.conf`, restricted to SYSTEM + Administrators since it
holds the private key) and is no longer deleted, so the tunnel reconnects on its
own after a reboot with nobody logged in. Existing Windows hosts must **re-enroll**
to pick up the persistent config (the old temp config is gone).

## v0.19.7 — RDP monitoring: one jump connection per probe (scale parity)

A Windows/RDP probe opened the jump-host SSH connection twice per sweep — once
for the RDP reachability check and once for WinRM fact collection — while an SSH
host opens it once. Since the monitor's worker-pool size is tuned against the
jump host's `sshd MaxStartups`, that doubled the per-host connection cost and
halved effective headroom for RDP hosts at scale.

The RDP branch now opens a single jump connection per probe and reuses it for
both the TCP check and WinRM, so RDP hosts cost the same as SSH hosts and scale
identically under the shared bounded worker pool (the sweep already pages all
hosts via `AllHosts` with no fixed cap). Removed the now-unused
`ProbeTCPViaJump` gateway helper.

## v0.19.6 — Windows onboarding: turnkey enrollment, richer facts, docs

Windows/RDP hosts now onboard with no hand-run configuration and report the same
resource details as Linux hosts.

- **Enrollment script now configures the host end-to-end.** In addition to the
  WireGuard tunnel it enables **Remote Desktop** (opens TCP 3389) and stands up a
  **WinRM HTTPS listener** on 5986 with a self-signed cert and firewall rule, so
  fact collection works over TLS with no manual `Enable-PSRemoting` and no
  `AllowUnencrypted`. Each step is best-effort and prints a summary of what it
  configured. The one manual action remains pasting the printed public key back
  into Provenance.
- **Richer Windows facts.** Fact collection over WinRM now also gathers **disk
  usage per drive, free/used memory, network interfaces, and the default
  gateway**, populated into the same `HostMetrics` the UI already renders — so the
  host details show disk, memory, and primary IP for Windows just like Linux
  (load average stays blank; it's a Unix concept). Metrics refresh every monitor
  sweep.
- **Documented.** The host-enrollment guide has a new **Windows (RDP) hosts**
  section covering the PowerShell the operator runs, the ports involved
  (51820/UDP, 3389, 5986) and who opens them, LAN-vs-remote endpoints, and the
  manual WinRM steps if a stripped host skips the automatic setup.

## v0.19.5 — RDP status: report overlay health (wg_ok)

The RDP/Windows status probe reported online/offline and latency but never set
`wg_ok`, so an enrolled Windows host reachable over the overlay still showed a
"wg down" badge. It now sets `wg_ok` when the RDP port is reached over the
WireGuard address, matching the SSH probe.

(Windows SYSTEM facts — OS, CPU, memory, uptime — are collected separately over
WinRM; if they show "—", WinRM/PSRemoting likely isn't enabled or reachable on
the host. See the enrollment guide.)

## v0.19.4 — Windows enrollment: fixed ListenPort so the jump can reach the host

Supersedes the v0.19.3 approach. A Windows host now enrolls with a fixed
WireGuard `ListenPort` (the configured `PROV_WG_PORT`, default 51820), exactly
like a Linux host, and the jump keeps a static endpoint to dial it. This is what
lets a host that shares the jump's LAN come up: the jump reaches the host
directly on the LAN, so the tunnel establishes even though the host's own
configured `Endpoint` is the *public* address (a LAN host can't hairpin to its
own public IP). Remote hosts are unaffected — their outbound keepalive to the
public endpoint establishes the tunnel and WireGuard relearns the real endpoint.

Previously the Windows tunnel used a random source port and didn't listen on the
WireGuard port, so the jump couldn't reach it and the tunnel only came up if the
host could dial the public endpoint itself — which fails for a LAN host. The
v0.19.3 roaming change is reverted in favour of this (it had removed the jump's
ability to initiate, which is precisely what makes LAN hosts work).

## v0.19.3 — Windows enrollment: add the jump peer roaming (no static endpoint)

A Windows host enrolls a dial-out WireGuard client that uses a random source
port and never listens on the WireGuard port, so the jump host cannot reach it
at `mgmtAddr:WGPort`. Enrollment previously pinned the jump-side peer to that
(unreachable) static endpoint — correct for a Linux host that listens on the
port, wrong for a dial-out Windows client, and meaningless when the Windows host
is remote behind NAT. The jump peer is now added **roaming** for RDP hosts: the
hub learns the endpoint from the client's keepalive handshake, exactly as it
already does on a jump-host rebuild.

Note: the Windows tunnel dials the jump host at the endpoint baked into its
config (your stored WireGuard endpoint). For a host on the jump's LAN, set the
enrollment endpoint to the jump's LAN address; for a remote host, use the public
endpoint with UDP/WireGuard forwarded to the jump — same as remote Linux hosts.

## v0.19.2 — RDP: don't route over the overlay until the host is enrolled

Clicking **Enroll** on an RDP host allocates and saves the host's WireGuard
overlay address immediately (the enrollment script needs it baked in). But the
RDP connection path preferred that overlay address the moment it was set — and
committed to it with no fallback — so a host mid-enrollment (tunnel not yet up)
became unreachable over RDP even though its direct address still worked.

RDP addressing is now enrolled-aware: the overlay address is used only once the
host is actually enrolled (tunnel established), and connections fall back to the
direct management address otherwise (unless strict WireGuard mode is enabled).

## v0.19.1 — Fix Windows enroll hang + finish-dialog crash

Finishing a Windows overlay enrollment could hang for minutes and then white-screen.
Two fixes: the RDP-over-overlay reachability check now has an 8-second timeout (it was
unbounded, so a still-settling tunnel or a host firewall blocking 3389 stalled the
finish), and the enrollment-result dialog no longer crashes if the response has no
step list (defensive rendering).

## v0.19.0 — Windows WireGuard enrollment (remote reach)

Windows/RDP hosts can now join the WireGuard overlay, so they're reachable from
**anywhere** with internet — the same dial-out model as Linux, previously Linux-only.
On an RDP host, **Enroll** offers a **PowerShell** script: run it elevated on the host
and it installs WireGuard, brings up a persistent dial-out tunnel to the jump host (no
inbound firewall rules), and prints its public key; paste that back and Provenance adds it as
an overlay peer. The RDP session and WinRM fact collection then ride the tunnel.
Enrollment is protocol-aware (bash for SSH hosts, PowerShell for Windows) and, for
Windows, verifies RDP reachability over the new tunnel instead of SSH-cert login.
(WireGuard on Windows is for non-FIPS deployments.)

## v0.18.0 — Windows host facts over WinRM

RDP (Windows) hosts previously showed no inventory (OS/CPU/memory/uptime were blank)
because fact collection runs over SSH, which Windows lacks. The monitor now collects
those facts over **WinRM (PowerShell remoting)**: it authenticates with the host's
attached **open-policy** vault credential and tunnels to WinRM through the jump host
(trying HTTPS `5986` then HTTP `5985`, NTLM), best-effort and refreshed like other
inventory. Requires WinRM enabled on the host. Toggle with `PROV_RDP_COLLECT_FACTS`
(default on); ports via `PROV_RDP_WINRM_PORTS`. The host-details dialog now hides
fields that don't apply to Windows (kernel, SSH version, WireGuard, apt/dnf updates).

## v0.17.8 — Revert RDP download to raw recording (.guac)

The self-contained offline RDP HTML player is dropped: guacamole-common-js 1.5.0's
recording playback leaves the desktop black offline (an async image-load race in the
library's render loop that can't be fixed cleanly from outside). The RDP download is
again the **raw `.guac` recording**; in-app replay (Session Replay → Desktop) remains
the supported way to watch. Removes the vendored player and its endpoint.

## v0.17.7 — Downloaded RDP player: patch the Guacamole Blob bug

The downloaded player threw `cannot read property "size" of undefined` — a bug in
guacamole-common-js 1.5.0's `SessionRecording` Blob support (it calls its Blob parser
with an unassigned `recordingBlob`). The vendored library is patched to assign
`recordingBlob = source`, so the player replays the recording from the embedded Blob
directly (original bytes, no fetch/tunnel). Backend-only.

## v0.17.6 — Downloaded RDP player: play from a Blob

Second attempt at the downloaded-player black screen: the recording is now fed to
`Guacamole.SessionRecording` directly as a `Blob` (parsed and rendered in place) rather
than through a streaming tunnel, whose reconstruct-then-render path dropped large
desktop-image draws offline while the small cursor draws survived. Backend-only.

## v0.17.5 — Fix black screen in the downloaded RDP player

The downloaded self-contained RDP player showed only a moving cursor on a black screen
(the desktop image draws were lost) even though in-app playback rendered correctly. The
embedded recording was served to the player via a large `data:` URL, which browsers
deliver/stream differently (notably under `file://`); it is now served via a `blob:`
URL — a real, chunk-streamed resource identical to the in-app playback path.
Backend-only.

## v0.17.4 — Self-contained RDP recording player

The RDP recording download is now a **self-contained HTML player** (double-click to
watch offline, no server) — full parity with SSH replay export. The Guacamole client
and the recording are both embedded; the player loads the library via a blob-URL
dynamic import and replays through the same streaming path as in-app playback. The
Guacamole client (v1.5.0) is vendored into the backend for embedding.

## v0.17.3 — Download button for RDP recordings

Session Replay → Desktop (RDP) recordings gained a **download** action (initially the
raw `.guac` recording; superseded by the self-contained HTML player in v0.17.4).

## v0.17.2 — Fix white screen when opening an RDP recording

Opening an RDP recording in Session Replay crashed the page to a white screen
(`Node.removeChild: The node to be removed is not a child of this node`). The player's
canvas container also held a React-managed loading spinner, so React reconciled
against the manually-inserted Guacamole canvas and threw. The canvas now lives in its
own React-inert node with the spinner as an absolutely-positioned sibling (matching the
live desktop viewer). Frontend-only.

## v0.17.1 — Fix RDP recording playback

RDP session recordings failed to play back ("Could not download the recording",
Play greyed out) even though the recording file was valid. The player downloaded the
recording as a Blob and used `Guacamole.SessionRecording`'s block-sliced Blob parser,
which mis-parses the stream. Playback now streams the recording through a Guacamole
tunnel (the reference-player approach) via a new token-authenticated endpoint
(`GET /rdp/recordings/{id}/stream`). No migration; rebuild the backend + frontend.

## v0.17.0 — High Availability (multi-instance)

Provenance can now run as **multiple backend instances** behind a load balancer,
for redundancy and rolling upgrades. HA is **safe by default** — a single-instance
deployment is unchanged (it is simply always the leader). See the new
[High Availability guide](high-availability.md).

- **Leader election & instance identity.** Each backend registers a heartbeat and
  contends for leadership via a Postgres session-scoped advisory lock (auto-releases
  on failure → no split brain). Cluster-wide singleton jobs (host monitor, KRL
  distribution, retention, digests, reports, backups, dynamic groups) run only on the
  leader; per-instance work still runs everywhere.
- **Ownership-scoped reconciliation.** Long-running rows (sessions, scans,
  playbook/vuln/remediation/enrollment runs) are tagged with their owning instance.
  On boot and periodically, only work abandoned by a **dead** instance is failed —
  never a live peer's. Fixes the pre-HA "kill everything on restart" behaviour.
- **Cross-instance real-time.** A Postgres LISTEN/NOTIFY backplane bridges the
  WebSocket hub so dashboard events reach clients on every instance, and an admin can
  terminate a session whose live terminal runs on another instance.
- **Issue-own-cert model.** A request landing on an instance that doesn't hold the
  session's key mints its own short-lived cert and **never revokes a peer's** — so any
  request can be served by any instance (no sticky sessions required). A dead
  instance's now-keyless certs are revoked by a leader sweep.
- **Postgres-failover-ready pool** (idle-conn recycling + exponential-backoff
  reconnect) and a **standby jump-host path**: each host's WireGuard public key is now
  persisted, and `provctl wg-peers` emits the overlay peer list so a standby jump
  host can rebuild the hub from the database on failover.
- **Cluster roster** on the Background Jobs page (instances, leader, liveness).

*Deploy:* no configuration is required for single-instance. Migrations `0036`–`0039`
apply automatically. For a multi-instance deployment (shared Postgres + shared storage
for recordings, a VIP for the jump host), follow `docs/high-availability.md`.

**Also in this release — RDP refinements.**

- **Windows hosts show real status.** RDP hosts are now health-checked with a TCP probe
  to the RDP port through the jump host (they have no SSH for the standard probe), so
  they report online/offline instead of always "unknown".
- **Protocol-aware actions.** RDP hosts only show actions that work on them — a
  **Desktop** button in place of Terminal/SFTP across the Hosts, Terminals, and
  Dashboard views, and the SSH-only actions (OpenSCAP scan, support bundle, WireGuard
  enrollment) are hidden for RDP hosts.
- **RDP connection failures are logged.** The broker now logs the reason a desktop
  session fails to start (credential, reachability, guacd, handshake) instead of only
  closing the browser tab.
- **guacd runs with a writable `HOME`** (also shipped as v0.16.2) so FreeRDP's TLS/NLA
  setup works.

## v0.16.0 — RDP recording, clipboard/display controls & file transfer

Rounds out Windows/RDP (v0.15.0 shipped live desktops) with recording/replay,
per-host display & security controls, gated clipboard, and drive-redirection file
transfer.

**Session recording & replay.** Every RDP session is recorded (guacd streams a
Guacamole recording to a shared volume; the backend stores metadata and serves it
back). A new **Desktop (RDP)** tab under **Session Replay** replays them with a
built-in player (play/pause + seek), gated by `Session.Replay`; delete/prune needs
`System.Configure` and shares the SSH recording retention window. Sessions now audit
`session.rdp_end` (with duration) alongside `session.rdp_start`.

**Clipboard & display/security controls.** Per-host RDP options passed to guacd:
security mode (Any / NLA / TLS / RDP / Hyper-V), color depth, resolution/DPI, AD
domain, and audio + wallpaper/theming toggles — for compatibility with locked-down /
NLA-only Windows hosts. **Clipboard** copy (desktop → browser) and paste (browser →
desktop) are independent and **off by default** (a data-transfer surface); guacd
enforces each gate and enabled directions are audited. (Clipboard needs an HTTPS
origin.) The live desktop also resizes to follow the browser window.

**Drive redirection (file transfer).** Enabling **Enable drive** mounts a **Provenance**
drive in the session and adds a **Files** button to the viewer — browse, download, and
upload. **Allow upload / Allow download** are independent and off by default. Each
session gets an isolated exchange directory on the shared `rdp-drive` volume that the
backend removes when the session ends (scratch space, not durable storage).

*Multi-monitor is not supported* — Guacamole's web client cannot drive multiple RDP
displays.

*Deploy:* pull the updated `deploy/compose/docker-compose.yml` — the **guacd** sidecar
now runs as the backend's `fleet` user (uid 100 / gid 101) and mounts the shared
`recordings` and `rdp-drive` volumes. Optional `PROV_RDP_DRIVE_DIR` defaults to
`/var/lib/prov/rdp-drive`. Migrations `0034` (the `rdp_recordings` table) and `0035`
(a JSONB `rdp_options` column on hosts) apply automatically.

## v0.15.0 — Windows desktops (RDP)

Provenance brokers full **Windows desktop (RDP)** sessions to the browser, alongside SSH
terminals and SFTP — no local RDP client, no direct route to the host.

- **Live RDP in the browser.** Set a host's **Protocol** to **RDP** and pick its port
  (default `3389`); the host then shows a **desktop** action that opens the live
  Windows desktop in a new tab, gated by `Host.Connect` and the usual per-host access
  checks. Mouse and keyboard are wired through; each connect is audited
  (`session.rdp_start`).
- **Brokered through the jump host.** The backend tunnels the target's RDP port over
  the **same jump-host / WireGuard path as SSH** and hands the bundled **guacd**
  sidecar an ephemeral local proxy — so guacd only ever connects back to the backend
  and needs no route to managed hosts.
- **Credential injected, never seen.** RDP authenticates with a **vaulted password
  credential** injected into guacd **in memory** — the operator never sees it and it
  never reaches the browser. Attaching it enforces the same `Host.Edit` +
  credential-access (and check-out policy) rules as SSH injection.

*Deploy:* add the `guacd` service (bundled in `deploy/compose/docker-compose.yml`) to
your stack. Optional `PROV_GUACD_ADDR` / `PROV_RDP_PROXY_HOST` default to the
compose service names. Migration `0033` (host `protocol` + `rdp_port`) applies
automatically. Clipboard, drive redirection, multi-monitor, and RDP session recording
are not in this release.

## v0.14.0 — Credential vault: injection, check-out, rotation

The credential vault becomes a full PAM workflow: connect through credentials
without seeing them, gate high-value ones behind approved check-out, and rotate
them.

- **Credential injection (connect without seeing the secret).** On a host's edit
  form, set **Authentication** to a vault credential (password or SSH key). When
  anyone opens a terminal or SFTP to that host, Provenance decrypts the credential **in
  memory** and authenticates the connection with it — the operator never sees the
  secret, and it never reaches the browser. Use it for appliances, network gear, and
  legacy systems that can't accept Provenance's ephemeral certificates. Attaching a
  credential requires `Host.Edit` plus access to it; injected sessions are audited.
- **Check-out & approval.** Each credential has an **access policy**: *open* (reveal/
  inject per grants), *check-out required* (time-boxed, self-service), or *approval
  required* (a `Credential.Approve` holder — not the requester — approves each
  check-out; the classic four-eyes control). Reveal **and** injection are blocked
  until an active check-out is held; approvers get an inbox on the Credentials page.
- **Rotation.** For a password credential attached to a host, **Rotate**
  (`Credential.Rotate`) changes it automatically over SSH, verifies the new login,
  and stores it — reverting if the host change fails so the vault stays consistent.
  Requires passwordless `sudo chpasswd` on the host; validate against a test host
  before production use.

*Deploy:* migrations `0031` (host auth method) and `0032` (check-out + the
`Credential.Approve` permission) apply automatically.

## v0.13.0 — Credential vault

Provenance is now a secrets manager, not just an SSH-certificate broker.

- **Credential vault.** A new **Credentials** page stores static credentials —
  **passwords, SSH keys, API keys** — for systems that can't use Provenance's ephemeral
  certificates (network gear, appliances, databases, legacy hosts). Secret material
  is **encrypted at rest** with secretbox under a dedicated **`PROV_VAULT_PASSPHRASE`**
  (required in production and enforced to differ from the CA passphrase; falls back
  to it in development).
- **Audited reveal.** Revealing a credential's plaintext requires the `Credential.View`
  permission (or `Credential.Manage`) plus access to that specific secret, and is
  **always written to the audit log**. Secret material never appears in logs.
- **Per-secret grants.** Delegate access to a credential to a user or group at
  **view / use / manage** level without granting vault-wide management. Administrators
  hold `Credential.Manage`; Operators get view/use/rotate; **Auditors are excluded
  from reveal**.
- **Versioning.** Editing a credential's value stores a new version, keeping rotation
  history.

*Deploy:* migration `0030` (vault tables + `Credential.*` permissions) applies
automatically. To use the vault in production, set `PROV_VAULT_PASSPHRASE` to a
strong value distinct from `PROV_CA_PASSPHRASE`.

## v0.12.1 — Fix: ZFS ARC memory accounting

- **Memory usage on ZFS-on-Linux hosts is no longer overstated.** The ZFS ARC cache
  is charged as "used" memory and excluded from the kernel's `MemAvailable`, even
  though it is reclaimable under pressure. The metrics collector now reads
  `/proc/spl/kstat/zfs/arcstats` and adds the reclaimable ARC (`size − c_min`) back
  to available memory, so a host with a large cache no longer reads as near-
  exhaustion (and the "high memory" insight clears accordingly). Non-ZFS hosts are
  unaffected.

*Deploy:* rebuild the backend; corrected values appear on the next monitor sweep.

## v0.12.0 — Terraform provider

Manage Provenance as infrastructure-as-code.

- **`terraform-provider-provenance`** — a Terraform provider (built on the modern plugin
  framework and the Go SDK) that manages **hosts**, **groups** (including dynamic
  membership rules), **service accounts**, and their **API tokens** declaratively,
  plus a `prov_role` data source to resolve role names to IDs. It authenticates with
  the same service-account token as the SDK and CLI; hosts and groups support full
  CRUD and `terraform import`. See the provider's README and `examples/` for usage,
  installation via dev overrides, and current limitations.
- The Go SDK gains `GetGroup` and `GetServiceAccount` (read-by-id) helpers.

*Note:* the provider builds from the repository (it references the in-repo SDK);
publishing it to the Terraform Registry is a separate release step.

## v0.11.0 — Assistant actions: guarded actions with approval + action policy

Completes the actionable assistant: it can now propose consequential actions that
require a second person to approve, and administrators can govern what it may do.

- **Guarded actions require approval.** More consequential actions the assistant can
  propose — **disable a user** and **delete a host** — never run on the requester's
  confirm. They show **Request approval** and wait for a different administrator (with
  the new `Assistant.Approve` permission) to approve or deny. Separation of duties is
  enforced: the requester can never approve their own action. On approval, Provenance
  **re-checks that the original requester still holds the required permission and an
  active account** before running it — an approval is not a bypass. Approvers see an
  "Awaiting your approval" inbox on the Ask page and a badge in the sidebar; every
  decision is audited and notified.
- **Action policy.** Under **Settings → Assistant actions**, administrators can
  **require approval for every assistant action** (even the safe ones) or **disable
  specific actions** entirely. Policy is applied when an action is proposed.
- **Action history.** The Ask page now shows a collapsible history of your recent
  assistant actions and their outcomes.

*Deploy:* migration `0029` (approval columns + the `Assistant.Approve` permission,
granted to Super Administrator and Administrator) applies automatically.

## v0.10.0 — Actionable AI assistant: docs answers + confirmed actions

The "Ask Provenance" assistant gains two capabilities, built so it can never act without
explicit human confirmation.

- **Answers grounded in the documentation.** Ask how-to and conceptual questions —
  *"how do I configure SAML?"*, *"how do access reviews work?"* — and the assistant
  searches the product documentation and answers with clickable **Sources** that link
  into the in-app help. Retrieval is a lightweight, dependency-free keyword (BM25)
  index over the docs embedded in the backend; no external service or model is added.
- **Proposed actions you confirm.** With the new `Assistant.Act` permission, the
  assistant can *propose* a small set of safe actions — currently **run a vulnerability
  scan** on a host or group, and **add/remove tags** on a host. The assistant never
  runs anything itself: it stages a proposal, you see exactly what will happen, and it
  executes only when you click **Confirm**. Execution **re-checks your permission and
  host access at that moment**, so the assistant can never do anything you couldn't do
  yourself or didn't approve. Every action is audited, and the proposal history is
  retained.

Security model: the model proposes, a human authorizes, and the backend executes and
re-verifies. Untrusted text (host data, documentation) is treated as information to
report, never as instructions to act on. Actions are gated behind `Assistant.Act`
(granted to Super Administrator, Administrator, and Operator) on top of the per-action
permission.

*Deploy:* migration `0028` (assistant action proposals + the `Assistant.Act`
permission) applies automatically. No configuration change is required beyond enabling
the assistant under Settings → AI assistant as before.

## v0.9.1 — Fixes: scans on symlinked hosts, session-expiry UX

- **Vulnerability scans no longer fail on hosts that symlink `/etc/os-release`.** The
  on-host collector now dereferences symlinks when building the package archive, so
  hosts where `/etc/os-release` (or `/var/lib/rpm`) is a symlink — common on NAS /
  appliance and openSUSE systems — scan correctly instead of failing with
  "links not allowed in archive".
- **Expired sessions now return you to the login screen.** When a background token
  refresh fails (the session expired or was reaped by the idle / absolute timeout),
  the UI clears the session and redirects to login instead of leaving you on a page
  whose actions all fail with "missing access token". The backend already enforced the
  expiry server-side; this closes the client-side display gap.
- **The vulnerability-scan dialog now shows the scanner's actual error** instead of a
  generic message.

*Deploy:* rebuild the backend and frontend images.

## v0.9.0 — Access certification, automation SDK/CLI, and SAML + SCIM

Three enterprise capabilities: certify access on a schedule, manage Provenance as code,
and federate identity with SAML SSO and SCIM provisioning.

- **Access certification (access reviews).** Create recertification campaigns that
  snapshot the current access grants — each user's group memberships and direct host
  grants — then **keep or revoke** each one and export the sign-off as CSV audit
  evidence. Revoking removes the underlying grant. Scope a review to everyone, one
  group, or specific users; a due date and progress are tracked. Gated by a new
  `AccessReview.Manage` permission (granted to Super Administrator, Administrator,
  and Auditor).
- **Automation: Go SDK + `fleet` CLI.** A standalone, dependency-free Go module
  (`github.com/kforbus3/provenance/sdk`) and a token-authenticated `fleet`
  command-line tool for managing hosts, groups (incl. dynamic rules), users, roles,
  service accounts and tokens, vulnerability scans, and CSV reports — for CI/CD,
  scheduled jobs, and custom tooling. Authenticates with a service-account `flt_`
  token; distinct from the on-host `provctl` recovery tool. See the new
  **Automation** guide.
- **SAML 2.0 single sign-on.** Authenticate users against a SAML identity provider
  (Okta, Azure AD / Entra ID, OneLogin, ADFS…), in addition to OIDC and LDAP. Both
  SP-initiated and IdP-initiated flows; IdP-signed assertions are validated
  (signature, audience, time bounds) before trust. Just-in-time user provisioning is
  gated by an auto-create toggle. The SP metadata, ACS, and entity-ID URLs are shown
  in the config UI.
- **SCIM 2.0 provisioning.** Let your identity provider create, update, and
  **deprovision** Provenance accounts automatically — disabling an account (and tearing
  down its live sessions and credentials) the moment a user is removed upstream.
  Users create/read/replace/PATCH/delete plus discovery endpoints, authenticated by a
  dedicated, revocable `scim_` bearer token. Pairs with SAML SSO.

*Deploy:* migration `0027` (access reviews) applies automatically. No configuration
change is required; SAML and SCIM are off until configured under Settings →
single sign-on / provisioning.

## v0.8.2 — Fixes: in-app help and CVE database

Two defect fixes for the in-app documentation and the vulnerability scanner.

- **In-app Help no longer renders blank.** The searchable help bundle is generated
  from the documentation at image-build time; the frontend image now builds with the
  docs present in its context, so Help shows its guides instead of a blank page. The
  build now fails fast if the help content is missing rather than shipping it empty,
  and the Help page degrades to a clear message if a bundle is ever absent.
- **CVE database update/import fixed.** The scanner could not create its database
  directory when running as its unprivileged user, so both the online update and the
  offline import failed with a permission error. The scanner image now creates that
  directory with the correct ownership, and the update error in the UI now shows the
  scanner's actual message instead of assuming a connectivity problem.

*Deploy:* rebuild the frontend and scanner images. If the CVE database volume already
exists from a prior deploy, correct its ownership once —
`docker compose exec -u root grype-scanner chown -R 10001:10001 /home/scanner/.cache/grype`
(or remove and recreate the `grype-db` volume) — then update the database from the
Vulnerabilities page.

## v0.8.0 — Vulnerability scanning

CVE vulnerability scanning of managed hosts, distinct from the OpenSCAP compliance
scans.

- **Vulnerability scanning (Grype).** Scan a host or a whole group for known-
  vulnerable packages and get per-host findings with **CVSS scores** (CVE, package,
  installed vs. fixed version, severity, score). A new `grype-scanner` sidecar does
  the matching centrally; the backend reads each host's package database over SSH, so
  **nothing is installed on managed hosts**. CVSS is populated even on Debian/Ubuntu
  (enriched from the associated NVD records).
- **Vulnerabilities page** with a fleet roll-up (highest CVSS and severity counts per
  host) and a drill-in findings table. Scans run on demand or on a schedule, findings
  are alertable and exportable to CSV, and results are audited.
- **CVE database management** — **Update online** when the backend has internet, or
  **Import offline** a pre-downloaded database archive for air-gapped deployments. The
  database build date is shown.

*Deploy:* adds the `grype-scanner` container (rebuild the stack) and migration `0026`.
Load the CVE database once from the Vulnerabilities page before the first scan.

## v0.7.0 — Enterprise integration

Seven capabilities that close common enterprise/PAM gaps.

- **Service accounts & API tokens.** Non-human identities for automation (CI/CD, IaC,
  monitoring) that carry roles and host access like a user but authenticate via hashed,
  optionally-expiring `flt_` bearer tokens — and survive employee turnover. Managed on a
  new Service Accounts page.
- **Compliance reporting.** Export access, audit, certificate, and scan-posture
  evidence as CSV over any date range from a new Reports page, and schedule recurring
  reports delivered as CSV email attachments.
- **Live session shadowing.** Watch an active terminal session in real time, read-only,
  for four-eyes oversight; watching is itself audited.
- **MFA recovery codes.** One-time backup codes as a fallback for a lost authenticator
  or passkey, generated self-service in Security settings.
- **Broader alerting.** Native PagerDuty and Opsgenie incident channels (severity-gated)
  and a Microsoft Teams webhook format, alongside email and generic webhooks.
- **Dynamic host groups.** Group membership can follow a rule over host attributes
  (environment, tags, OS, hostname); matching hosts join automatically.

*Deploy:* migrations `0022`–`0025`.

## v0.6.2 — Correct version stamping

- The deployed build now reports its real release version (from git tags) instead of
  `dev`, and the release tooling keeps version tags in sync across mirrors.

## v0.6.1 — Host-flapping fix

- Fixed hosts intermittently showing offline after v0.6.0: the health-check sweep was
  parallelized too aggressively for the jump host's SSH limits. Sweep concurrency is now
  bounded (configurable via `PROV_MONITOR_CONCURRENCY`, default 6).

## v0.6.0 — Hardening and a deeper Ask AI

A security/reliability hardening pass plus a much-expanded AI assistant.

- **Ask AI upgraded** from a single-shot question box into a fleet-health assistant:
  multi-turn conversation memory (follow-up questions), a **prov-insights** engine
  (offline hosts, low disk, capacity/disk-runway projection, high load, pending
  updates) surfaced on the dashboard and to the assistant, and opt-in **scheduled
  fleet-health digests**.
- **Reliability & security fixes:** a browser-terminal crash/DoS race, an OIDC
  account-binding weakness, silent 1000-host caps in monitoring and certificate-
  revocation distribution, configurable data/audit **retention**, atomic scheduler
  claims, bounded scan/playbook output, backup and audit-forwarding hardening, and an
  atomic first-run bootstrap.

*Deploy:* migration `0021` (host metric history); new optional retention/monitor
settings.

---

For releases prior to v0.6.0, see the Git history and the GitHub Releases page.
