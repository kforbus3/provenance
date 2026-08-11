#!/usr/bin/env python3
"""Ask Fleet regression harness.

Runs the standard question battery against a LIVE Fleet instance through the real
API (login -> POST /assistant/ask -> poll) and prints every answer for review.
This is the acceptance suite for the Ask feature: every change to the assistant
(fast paths, deterministic answers, calendar windows, prompt text) should be
validated by running this battery and reading the answers against known data.

Usage:
    FLEET_URL=http://127.0.0.1:8080 FLEET_USER=<admin> FLEET_PASS=<password> \
        python3 askharness.py [--only PATTERN] [--multi-turn]

The user needs Assistant.Use plus broad view permissions (a test super-admin is
simplest; delete it afterwards). Answers are judged by a human (or the driving
agent) against the instance's real data — the harness itself only checks that
every question returns a non-error answer, and exits non-zero otherwise.
"""

import argparse
import json
import os
import sys
import time
import urllib.request

BASE = os.environ.get("FLEET_URL", "http://127.0.0.1:8080")
USER = os.environ.get("FLEET_USER", "")
PASS = os.environ.get("FLEET_PASS", "")

# The core battery: the 7 canonical questions plus the time-window, phrasing, and
# calendar variants that have regressed before. Grouped for --only filtering.
BATTERY = [
    ("disk", "Which hosts have less than 20% disk free?"),
    ("disk", "Which hosts have less than 80% disk free?"),
    ("disk", "Which hosts have more than 50% disk free?"),
    ("trend", "What is the disk usage trend on nas over the past week?"),
    ("trend", "What is the disk usage trend on gitlab over the past day?"),
    ("sessions", "Who connected to ai yesterday?"),
    ("sessions", "Who connected to ai today?"),
    ("sessions", "Who last connected to nas?"),
    ("sessions", "Who connected to nas?"),
    ("sessions", "has anyone connected to nas recently?"),
    ("sessions", "has anyone logged into nas recently?"),
    ("sessions", "did anyone connect to repo this week?"),
    ("sessions", "Which hosts have been accessed today?"),
    ("sessions", "Which hosts have been accessed this week?"),
    ("failures", "Any failed scans or playbook runs recently?"),
    ("failures", "Any failed playbook runs this week?"),
    ("failures", "Any failed scans today?"),
    ("audit", "What changed in the audit log today?"),
    ("audit", "What changed in the audit log yesterday?"),
    ("audit", "What changed in the audit log this week?"),
    ("security", "Any failed logins today?"),
    ("security", "Any failed logins this week?"),
    ("schedules", "What runs on a schedule, and when does it fire next?"),
    ("updates", "Which hosts have security updates pending?"),
    # Compliance (OpenSCAP). "Security scan" is the operator's own phrase for these and
    # used to be answered from the CVE tool, then denied outright ("I do not have a tool
    # to retrieve OpenSCAP results") — the answers below must be per-host benchmark
    # results, and must say WHICH kind of scan they are.
    ("compliance", "Give me the latest security scan result for each host"),
    ("compliance", "I want the results for the security scans not for the vulnerability scans"),
    ("compliance", "Which hosts failed their compliance scan?"),
    ("compliance", "Which hosts have never been scanned?"),
    ("compliance", "What rules is nas failing?"),
    ("compliance", "What is the CIS benchmark score for nas?"),
    # The CVE tool must stay distinct from compliance, not absorb it.
    ("vulns", "Which hosts have critical vulnerabilities?"),
    # Governance surfaces that previously had no tool at all.
    ("governance", "What groups are there?"),
    ("governance", "Which hosts are in the prod group?"),
    ("governance", "What can the Operator role do?"),
    ("governance", "What API tokens exist and when were they last used?"),
    ("governance", "Is there an access review open?"),
    ("governance", "What credentials or certificates are expiring soon?"),
    # Platform: these sections were added to platform_status.
    ("platform", "Is the cluster healthy?"),
    ("platform", "Are all federation sites connected?"),
    ("platform", "Any unusual access patterns lately?"),
    # Answer discipline: the assistant must not ask for a hostname when the question
    # explicitly says "each host", and must not open with a chatty preamble.
    ("discipline", "What SSH sessions are active right now?"),
]

# Multi-turn: follow-ups must resolve references from the conversation.
MULTI_TURN = [
    "Any failed scans or playbook runs recently?",
    "tell me about the failed scans",
    "when did the failures happen?",
    "which host had the most?",
]

# The exact exchange that motivated the compliance work: a fleet-wide question, then a
# correction. Turn 1 must not ask which host; turn 2 must switch datasets rather than
# claiming Fleet cannot retrieve compliance results.
MULTI_TURN_COMPLIANCE = [
    "Give me the latest security scan result for each host",
    "I want the results for the security scans not for the vulnerability scans",
    "Which of those is worst?",
    "What rules is it failing?",
]


def api(path, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers={
            "Content-Type": "application/json",
            **({"Authorization": "Bearer " + token} if token else {}),
        },
    )
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)


def login():
    if not USER or not PASS:
        sys.exit("set FLEET_USER and FLEET_PASS (and FLEET_URL if not localhost)")
    return api("/api/v1/auth/login", body={"username": USER, "password": PASS})["accessToken"]


def ask(token, question, convo=""):
    r = api("/api/v1/assistant/ask", token, {"question": question, "conversationId": convo})
    ask_id, convo_id = r["id"], r.get("conversationId", convo)
    for _ in range(120):
        res = api("/api/v1/assistant/ask/" + ask_id, token)
        if res.get("status") in ("done", "error") or res.get("answer"):
            return res, convo_id
        time.sleep(1)
    return {"status": "error", "answer": "(timeout)"}, convo_id


def show(question, res):
    answer = (res.get("answer") or res.get("error") or "(no answer)").strip()
    tbl = res.get("table")
    rows = len(tbl["rows"]) if tbl and tbl.get("rows") else 0
    tool = res.get("answeredBy", "")
    print(f"Q: {question}\nA: {answer}\n   [rows={rows} tool={tool}]\n", flush=True)
    return res.get("status") == "done" and bool(res.get("answer"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="run only groups whose name contains this substring")
    ap.add_argument("--multi-turn", action="store_true", help="also run the multi-turn battery")
    args = ap.parse_args()

    token = login()
    failures = 0

    for group, q in BATTERY:
        if args.only and args.only not in group:
            continue
        res, _ = ask(token, q)
        if not show(q, res):
            failures += 1

    if args.multi_turn:
        for name, thread in (("failed activity", MULTI_TURN), ("compliance correction", MULTI_TURN_COMPLIANCE)):
            print(f"=== multi-turn: {name} (one conversation) ===", flush=True)
            convo = ""
            for q in thread:
                res, convo = ask(token, q, convo)
                if not show(q, res):
                    failures += 1

    if failures:
        sys.exit(f"{failures} question(s) returned an error/empty answer")
    print("all questions returned answers — review them against the instance's data")


if __name__ == "__main__":
    main()
