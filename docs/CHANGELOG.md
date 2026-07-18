# Changelog

Notable changes to Fleet Terminal, newest first. Dates are release dates. Database
schema migrations apply automatically on startup; deploy notes call out anything else.

---

## v0.12.0 — Terraform provider

Manage Fleet as infrastructure-as-code.

- **`terraform-provider-fleet`** — a Terraform provider (built on the modern plugin
  framework and the Go SDK) that manages **hosts**, **groups** (including dynamic
  membership rules), **service accounts**, and their **API tokens** declaratively,
  plus a `fleet_role` data source to resolve role names to IDs. It authenticates with
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
  enforced: the requester can never approve their own action. On approval, Fleet
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

The "Ask Fleet" assistant gains two capabilities, built so it can never act without
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

Three enterprise capabilities: certify access on a schedule, manage Fleet as code,
and federate identity with SAML SSO and SCIM provisioning.

- **Access certification (access reviews).** Create recertification campaigns that
  snapshot the current access grants — each user's group memberships and direct host
  grants — then **keep or revoke** each one and export the sign-off as CSV audit
  evidence. Revoking removes the underlying grant. Scope a review to everyone, one
  group, or specific users; a due date and progress are tracked. Gated by a new
  `AccessReview.Manage` permission (granted to Super Administrator, Administrator,
  and Auditor).
- **Automation: Go SDK + `fleet` CLI.** A standalone, dependency-free Go module
  (`github.com/kforbus3/Fleet-Terminal/sdk`) and a token-authenticated `fleet`
  command-line tool for managing hosts, groups (incl. dynamic rules), users, roles,
  service accounts and tokens, vulnerability scans, and CSV reports — for CI/CD,
  scheduled jobs, and custom tooling. Authenticates with a service-account `flt_`
  token; distinct from the on-host `fleetctl` recovery tool. See the new
  **Automation** guide.
- **SAML 2.0 single sign-on.** Authenticate users against a SAML identity provider
  (Okta, Azure AD / Entra ID, OneLogin, ADFS…), in addition to OIDC and LDAP. Both
  SP-initiated and IdP-initiated flows; IdP-signed assertions are validated
  (signature, audience, time bounds) before trust. Just-in-time user provisioning is
  gated by an auto-create toggle. The SP metadata, ACS, and entity-ID URLs are shown
  in the config UI.
- **SCIM 2.0 provisioning.** Let your identity provider create, update, and
  **deprovision** Fleet accounts automatically — disabling an account (and tearing
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
  bounded (configurable via `FLEET_MONITOR_CONCURRENCY`, default 6).

## v0.6.0 — Hardening and a deeper Ask AI

A security/reliability hardening pass plus a much-expanded AI assistant.

- **Ask AI upgraded** from a single-shot question box into a fleet-health assistant:
  multi-turn conversation memory (follow-up questions), a **fleet-insights** engine
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
