# Ask Fleet regression harness

The acceptance suite for the **Ask** (AI assistant) feature. It runs the standard
question battery against a live Fleet instance through the real API and prints every
answer, so a change to the assistant can be validated end-to-end in one run.

```sh
FLEET_URL=http://127.0.0.1:8080 FLEET_USER=<admin> FLEET_PASS=<password> \
    python3 askharness.py --multi-turn
```

- `--only sessions` — run one group (disk / trend / sessions / failures / audit /
  security / schedules / updates).
- `--multi-turn` — additionally runs a follow-up conversation ("tell me about the
  failed scans" → "when did the failures happen?") in a single conversation thread.

The harness exits non-zero if any question errors or returns an empty answer.
**Correctness is judged by reading the answers against the instance's real data** —
e.g. confirm "today" answers contain only today's rows, and that host lists match the
hosts page. No Python dependencies beyond the standard library.

The user needs `Assistant.Use` plus broad view permissions; a temporary super-admin
(`fleetctl create-admin`) is simplest. Delete it when done.

What this battery guards (each was a real regression):

- Disk-threshold questions must **name every matching host** with its percentage.
- "today" / "yesterday" / "this week" / "last week" are **calendar ranges** in the
  display timezone, not rolling lookbacks.
- "recently" and bare "who connected to X" mean the **past week**, not a month.
- "who **last** connected" is unbounded and returns the single most recent session.
- Failed-scan/run and failed-login questions must not report unrelated events, and
  times render in the display timezone (12-hour).
- Audit answers separate operator changes from routine automated noise.
- Follow-ups resolve references ("the failures") instead of asking to clarify.
