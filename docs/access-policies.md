# Access policies (ABAC)

Access policies add **attribute-based access control** on top of role-based access control
(RBAC). An RBAC role grants a user the ability to reach a set of hosts; an access policy can then
**deny** a specific connection based on context — which host, and when — that roles alone can't
express.

Policies **only restrict**. They never grant access beyond what RBAC already allows, and
**super administrators are always exempt** so an over-broad rule can never lock out the operators
who need to fix it.

Manage them under **Access Policies** (requires the `AccessPolicy.Manage` permission).

## When policies are evaluated

At **connect time**, immediately after the normal host-access check succeeds, on these surfaces:

- Browser SSH terminal
- RDP desktop
- SFTP file transfer
- Ad-hoc command runner

Each attempt is checked against the enabled policies in ascending **priority** order; the first
matching rule denies the connection and its message is shown to the user. Every denial is recorded
as an `access.denied` audit event (with the rule, host, surface, and reason).

Scheduled and automation runs (Ansible playbooks, PowerShell scripts, scheduled scans) are governed
by their service-account credentials and are **not** subject to time-of-day policies.

## What a policy matches

A rule matches a connection when **all** of its specified conditions hold (an empty condition is a
wildcard):

| Condition | Meaning |
|-----------|---------|
| Environments | The host's environment is in this set (e.g. `production`). |
| Tags | The host has **any** of these tags (e.g. `pci`, `sensitive`). |
| Protocols | The connection protocol is in this set (`ssh` / `rdp`). |
| Exempt roles | If the user holds **any** of these roles, the rule does **not** apply to them. |
| Active days | Days of week the rule is active (none = every day). |
| Active time | An intra-day window; equal start/end means all day. **Start &gt; end wraps past midnight** (e.g. 18:00–09:00 = after hours). |

Times are evaluated in the **configured display timezone** (Settings → General → Time zone).

## Examples

- **No production access after hours.** Environments `production`, active time `18:00`–`09:00`
  (wraps midnight), deny message "Production access is restricted outside business hours."
- **Weekend change freeze.** Active days Saturday + Sunday, all environments, exempt role `On-Call`.
- **PCI hosts are SRE-only.** Tags `pci`, exempt roles `SRE`, deny message "PCI hosts require SRE."
- **No RDP to sensitive Windows hosts for contractors.** Protocols `rdp`, tags `sensitive`, exempt
  roles `Employee`.

## Notes

- Policies are a restriction layer. If the policy store is briefly unavailable the connection is
  **allowed** (fail-open) and the event logged — ABAC never becomes a single point of failure for
  all access. Use RBAC and host grants as the primary control.
- Disable a policy (rather than deleting it) to pause it while keeping the definition.
