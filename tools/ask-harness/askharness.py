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
]

# Multi-turn: follow-ups must resolve references from the conversation.
MULTI_TURN = [
    "Any failed scans or playbook runs recently?",
    "tell me about the failed scans",
    "when did the failures happen?",
    "which host had the most?",
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
        print("=== multi-turn (one conversation) ===", flush=True)
        convo = ""
        for q in MULTI_TURN:
            res, convo = ask(token, q, convo)
            if not show(q, res):
                failures += 1

    if failures:
        sys.exit(f"{failures} question(s) returned an error/empty answer")
    print("all questions returned answers — review them against the instance's data")


if __name__ == "__main__":
    main()
