# Behavior analytics (UEBA)

Behavior analytics surfaces access patterns that deviate from a user's established baseline,
computed from Fleet's own session records — explainable statistics, no machine learning and no
external dependency. It's an **advisory** signal layered on the tamper-evident audit log: verify
before acting.

Open it under **Behavior** (requires the `Audit.View` permission).

## What it detects

| Signal | Meaning |
|--------|---------|
| Off-hours access | A session started at an hour outside the user's usual pattern. |
| First access to a host | A user connecting to a host they've never used before. |
| New source IP | A connection from an address not seen before for that user. |
| Activity spike | Session volume well above the user's daily baseline. |

Each user needs a minimum history before deviations are flagged, so brand-new accounts don't
generate noise. Anomalies are computed on demand over a 30-day baseline compared against the last
24 hours of activity.

## Using it

The Behavior page lists anomalies with a severity (informational or warning). Treat them as leads —
correlate with the [audit log](./admin-guide.md) and session recordings before drawing conclusions.
Behavior analytics does not block access; use [access policies](./access-policies.md) for enforcement.
