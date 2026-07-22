# ITSM integration (ServiceNow / Jira)

Fleet can open a **change/incident ticket** in your IT service-management system for each
just-in-time access request, and attach the ticket reference to the approval — so privileged-access
grants carry a change record. Supported systems: **ServiceNow** and **Jira**.

Configure it under **Settings → Integrations → ITSM integration** (requires `System.Configure`).

## How it works

- When a user files an access request (Approvals → Request access), if the integration is enabled
  and the requester didn't already supply a ticket reference, Fleet opens a ticket describing the
  request (who, what, how long, and the stated reason) and stores its reference on the approval.
- The ticket reference (and a link) is included in the approval notification.
- It is **best-effort**: if the ITSM is unreachable the access request still proceeds — it is never
  blocked on the ticketing system. Failures are logged; successes are audited (`approval.ticket`).

## Configuration

| Field | ServiceNow | Jira |
|-------|-----------|------|
| Base URL | `https://your-org.service-now.com` | `https://your-org.atlassian.net` |
| User | ServiceNow username | Atlassian account email |
| Token | ServiceNow password | Jira API token |
| Project | Table (default `incident`) | Project key (e.g. `OPS`) |

The token is **sealed at rest** (like Fleet's other integration secrets) and is never returned by
the API. Leave the token field blank when editing to keep the stored value. Use **Test connection**
to verify credentials without creating a ticket.

## Notes

- Use a least-privilege ITSM account — it only needs to create records in the target table/project.
- Tickets are created as ServiceNow *incidents* (or the configured table) and Jira *Task* issues.
- A requester can still enter their own ticket reference on the request; Fleet only auto-opens one
  when none is provided.
