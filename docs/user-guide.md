# Fleet Terminal — User Guide

Fleet Terminal lets you open SSH sessions and transfer files to your servers
**right from your browser** — no SSH client, no VPN, no keys to manage. This
guide walks through everyday use, step by step.

---

## 1. Sign in

1. Open the Fleet Terminal URL your administrator gave you.
2. Enter your **username** and **password**, then **Sign in**.
3. First time, or after a reset, you may be asked to **set a new password**
   (minimum 12 characters with upper, lower, a digit, and a symbol).

You never see or handle an SSH key. Behind the scenes, signing in creates a
short-lived identity that lives only in the server's memory and is destroyed when
you log out or your session times out (typically 30 minutes idle).

### If your organization uses single sign-on (SSO)

- **OIDC:** if SSO is enabled, the login page shows a **Sign in with SSO** button.
  Click it and you'll be sent to your organization's identity provider to sign in;
  you're returned to Fleet Terminal already authenticated — no separate password
  to enter here.
- **LDAP / Active Directory:** just sign in on the normal form with your usual
  **directory username and password** — the same credentials you use elsewhere on
  your network.

### If two-factor authentication (2FA) is required

- **You already set up an authenticator:** after your password, enter the 6-digit
  code from your app.
- **You haven't set one up yet and it's required:** you'll be shown a setup screen.
  **Scan the QR code** with an authenticator app (Google Authenticator, 1Password,
  Authy, …) — or enter the **secret key** manually — then type the current 6-digit
  code to finish signing in. After this, 2FA is asked for at every sign-in.

You can also set up or manage 2FA anytime under **Security** (including passkeys,
if your administrator has them enabled). The QR code there is generated in your
browser, so your secret is never sent anywhere.

#### Passkeys (Touch ID, Windows Hello, security keys)

On the same **Security** page, the **Passkeys (WebAuthn)** card lets you
**Register a passkey** — a hardware security key, Touch ID / Windows Hello, or a
phone passkey — as a phishing-resistant second factor. Once registered, you can
use it to confirm your identity at sign-in instead of typing a code.

#### Recovery codes (in case you lose your authenticator)

Also on the **Security** page, once you've set up a second factor (an
authenticator app or a passkey), you can **Generate recovery codes**. These are
one-time backup codes — 10 of them, each looking like `xxxx-xxxx-xxxx`.

- They're shown **only once**, right after you generate them. **Save them now** —
  print them or store them in your password manager. Fleet Terminal keeps only a
  scrambled copy and can never show them to you again.
- If you ever lose your phone or security key, type **one recovery code** into the
  normal 2FA prompt at sign-in (the same box where you'd enter a 6-digit code) —
  dashes, spaces, and capitalization don't matter.
- Each code works **once**, then it's used up. When you're running low, generate a
  fresh set — doing so replaces any old codes.

Recovery codes are your fastest way back in if your authenticator goes missing, so
keep them somewhere safe but separate from your password.

To **sign out**, use the button at the top-right of the page.

---

## 2. Your dashboard

The home page gives you an at-a-glance overview:

- **Stat cards** (click to jump to the full page): how many hosts you can reach and
  how many are online, your active sessions, and any pending approvals.
- **Quick connect** — your hosts, online first, each one click from a Terminal or
  Files session. **Customize it** with the tune icon: pick exactly which hosts appear
  (and in what order), or leave it empty to keep the automatic list. Your choice follows
  your account across browsers.
- **Live sessions** (if you can review sessions) — a real-time list of who is
  connected to which host, updating as people connect and disconnect.
- **Needs attention** — hosts that are currently offline.

You only ever see the data you're allowed to; cards and panels you don't have
permission for simply don't appear.

---

## 3. Connect to a server (Terminal)

The quickest path is the **Terminals** page:

1. Click **Terminals** in the sidebar.
2. Find your server (search by name, environment, or tag). Online servers appear
   first, with a status dot and latency.
3. Click **Terminal**. A full SSH terminal opens **in a new browser tab**.
4. Use it like any terminal — run commands, `sudo`, `vim`, `htop`, `tmux`.
   Resizing the window resizes the remote terminal too.

With a long list, use **Filter by group** (a multi-select at the top of the page)
to narrow the hosts down to one or more groups. The same control is available on
the **Hosts** page.

You can also start a terminal from the **Hosts** page using the terminal icon on
a host row. To close a session, type `exit` or close the tab.

### Host details and pending updates

On the **Hosts** page, click the info button (ⓘ) on a host row to open its
**details** dialog — OS, kernel, CPU/memory, uptime, and more. When the
information is known, an **Updates available** row shows the number of pending
package updates, with security updates called out separately (for example,
`12 (3 security)`).

> Each connection uses a unique, automatically-issued certificate just for you and
> that server. You'll only see servers you're allowed to reach.

### Databases and Kubernetes

Fleet also brokers access to **databases** and **Kubernetes clusters** the same way — you never
handle the credential. On the **Databases** page, run SQL against a registered PostgreSQL, MySQL,
MariaDB, or SQL Server target (Fleet injects a vaulted credential and audits every query). On the
**Kubernetes** page, browse cluster resources or point `kubectl` at Fleet's proxy. These appear only
if an administrator has registered targets and granted you access.

---

## 4. Transfer files (SFTP)

1. On the **Terminals** or **Hosts** page, click **Files** (folder icon) for a
   server. A file browser opens in a new tab.
2. **Download:** click a file. **Upload:** use the upload button or drag-and-drop
   files (or a whole folder) into the window.
3. A progress bar shows transfer status; you can cancel an in-progress transfer.

Every transfer is brokered by the server and recorded for audit.

---

## 5. Request access you don't have (Just-in-Time)

If you don't see a server you need, you can request temporary access:

1. Go to **Approvals → New Request**.
2. Pick the **host** or **group** you need, enter a **reason** and optional
   **ticket reference**, and choose **how long** you need it.
3. Submit. An approver reviews it.
4. When approved, access is granted automatically for the time window and
   **expires on its own** — nothing to clean up. Connect as usual while it's active.

Track your requests under **Approvals → My Requests** and active grants under
**My Grants**.

### If you approve requests

With approver permission, the **Approvals** queue shows pending requests. Open one
to see who's asking, for what, and why, then **Approve** (optionally for a shorter
time, with a note) or **Deny**.

---

## 6. Review a recorded session

If you have replay permission, **Session Replay** lists recorded SSH sessions
(filter by user or host). Open one to **replay** it as a faithful playback —
exactly what happened, with original timing. You can also **export** a session as
a self-contained file to watch offline.

> **Heads-up: your live sessions may be watched.** For oversight of privileged
> access, an authorized reviewer can open a **read-only, real-time view** of a
> session while it's still active — they see exactly what you see but can't type
> or interfere. Watching is itself recorded in the audit log. This is normal
> four-eyes supervision, not a sign anything is wrong.

---

## 7. Ask Fleet — the AI assistant

If you have the `Assistant.Use` permission, an **Ask** item appears in the
sidebar. It lets you ask questions about your fleet in plain language and get a
written answer back.

**Ask** answers questions from read-only data, and — only when you explicitly ask
and then confirm — can propose a small set of actions (see "Letting Ask take
action" below). You can ask about:

- **Hosts and their specs/status** — OS and kernel, CPU and memory, uptime, disk,
  memory, and load (e.g. *"which hosts have less than 20% disk free"*).
- **Who's currently connected** — active SSH sessions.
- **Full detail for one host** — including filesystems and network.
- **Available package updates** per host (e.g. *"which hosts have updates
  available"*).
- **Recent security scans and playbook runs**, including whether they were
  scheduled (e.g. *"when was the last scan on web-01"*, *"did any scheduled
  playbook runs fail"*).
- **Availability / downtime history** — *"did any host go offline overnight?"*,
  *"was web-01 down this week?"*, *"how much downtime has db-02 had?"*. This is the
  record of hosts going offline and recovering, so it catches outages that already
  cleared — something the current-status view can't show you.
- **Vulnerabilities (CVEs)** — *"what critical vulnerabilities are on web-01?"* or
  *"which hosts have the worst CVE exposure?"*, from the vulnerability scanner
  (distinct from OpenSCAP compliance scans). Requires the `Host.Scan` permission.
- **Users, roles, and MFA** — *"who are the administrators?"*, *"which accounts have
  no MFA?"*, *"what role does bob have?"* (requires `User.Edit`).
- **Approvals and just-in-time access** — *"what's waiting for approval?"*, *"who has
  elevated access right now?"* (requires an approvals permission).
- **Windows software inventory** — *"what's installed on the Windows host?"* for RDP
  hosts.
- **Platform health** — *"is the HA cluster healthy? who's the leader?"* and *"did
  host X enroll successfully?"* (requires `System.Configure` / `Host.Enroll`).
- **What needs attention across the fleet** — ask *"what's wrong with the
  fleet?"* or a capacity question like *"which hosts are about to run out of
  disk?"* and Ask draws on **fleet insights**: offline hosts, low or critically
  low disk, high memory or load, pending security updates, and a **disk-runway
  projection** (roughly how many days until a disk fills up).
- **How the product works** — ask *"how do I configure SAML?"* or *"how do access
  reviews work?"* and Ask searches the product documentation and answers with
  **Sources** you can click straight into the in-app help.

**It remembers the conversation.** Ask a question, then follow up naturally —
*"and db-02?"* or *"what about last week?"* — and Fleet keeps the earlier context,
so you don't have to repeat yourself. The thread stays put even if you refresh the
page. When you want a clean slate on a new topic, click **New conversation** to
start fresh.

Answers are always scoped to what you're allowed to see, and every question is
recorded for audit. Treat an answer as a helpful starting point — verify it
before you act on it.

### Letting Ask take action

If you have the `Assistant.Act` permission, you can ask Ask to *do* a few safe
things — for example *"scan web-01 for vulnerabilities"* or *"tag db-02 as
legacy"*. Ask never acts on its own:

1. It **proposes** the action as a card showing exactly what will happen.
2. **Nothing runs until you click Confirm** (or **Dismiss** to cancel).
3. When you confirm, Fleet re-checks your permission and runs it, then shows the
   result. Every action is recorded in the audit log.

You can only propose actions you already have permission for (e.g. scanning needs
`Host.Scan`, tagging needs `Host.Edit`), and the check is re-applied at the moment
you confirm. This keeps the assistant from ever doing anything you couldn't do
yourself, or anything you didn't explicitly approve.

**Guarded actions need a second person.** More consequential actions — for example
*"disable user jsmith"* or *"delete host old-db-01"* — are **guarded**. Instead of a
Confirm button they show **Request approval**: the action waits until someone with
the `Assistant.Approve` permission (an administrator) approves it, and it can never
be approved by the person who requested it (separation of duties). Approvers see a
short **"Awaiting your approval"** list at the top of the Ask page with Approve /
Deny for each. On approval, Fleet re-checks that the original requester still has the
required permission and account before running it. Guarded actions, like all
actions, are fully audited.

---

## 8. Check hosts for known vulnerabilities

If you have scan permission, the **Vulnerabilities** page shows where your hosts
have publicly known security flaws (CVEs) in their installed packages. Nothing is
installed on your servers to do this — the scan reads the package list over the
existing secure channel.

- **The fleet roll-up** at the top lists your hosts with, for each one, the
  **highest CVSS score** found and a count of **critical / high / medium**
  findings — a quick way to see which servers need attention first. (CVSS is a
  0–10 severity score; higher is worse.)
- **Drill into a host** to see its **findings table**: each row is one CVE, with
  the affected **package**, the **version you have installed**, the **version that
  fixes it** ("fixed-in" — update to at least this to close the hole), the
  **severity**, and the **CVSS score**.
- If a scan is running, you'll see **live progress**; results appear as they
  complete.

Use the fixed-in version to plan updates: patch the highest-severity, highest-CVSS
findings first.

---

## 9. Download reports

If you have audit-viewing permission, the **Reports** page lets you **download
CSV reports** over a date range you choose — handy for compliance evidence or
sharing with an auditor. Available reports include **access** (who connected to
what, when), **audit** events, **certificate** issuance, **security-scan**
posture, and **vulnerability** findings. Pick a from/to range and download; open
the file in any spreadsheet tool.

Your administrator can also have these delivered to you automatically on a weekly
or monthly schedule.

---

## 10. Tips & good habits

- **Show/hide the sidebar** with the menu (☰) button in the top bar — handy on
  wide tables like Hosts.
- **No keys to manage.** You never touch SSH keys or `authorized_keys`; the
  platform issues a fresh short-lived certificate per session, per server.
- **Everything is audited.** Connections, file transfers, and actions are recorded
  in a tamper-evident log.
- **Least privilege.** Prefer Just-in-Time access for occasional needs over
  standing membership in broad groups.
- **Protect your 2FA.** Generate **recovery codes** on the Security page and store
  them safely — if you lose your authenticator, one of those codes gets you back
  in without waiting on an admin. (If you're out of codes too, an administrator can
  still reset your factors.)
- **Times you see are in the app's configured zone.** All dates and times are
  shown in a time zone your administrator sets (**Settings → Time zone**), which
  may differ from your own browser's zone.

---

## 11. Troubleshooting

| Symptom | What to do |
|---|---|
| "Not authorized for host" | You don't have access — request it via **Approvals**. |
| Server isn't in my list | Same — it's not shared with you yet; request access. |
| Signed out unexpectedly | Idle/absolute timeout; just sign in again. |
| "Rate limit exceeded" | Too many rapid attempts from your network; wait a moment. |
| Terminal won't open | Check the server's status on the Terminals page; if offline, contact an admin. |
| Lost my 2FA device | Enter one of your **recovery codes** at the 2FA prompt. Out of codes? Ask an administrator to reset your MFA. |
