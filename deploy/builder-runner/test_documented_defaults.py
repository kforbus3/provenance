"""A documented default must match the code, and a documented LIFETIME must be checkable.

Sibling of test_documented_settings.py, which asks whether a documented setting
exists. This asks whether a documented *value* is true, and it exists because the
existence check passed while the values had quietly rotted.

What the drift looked like, found by an outside reviewer reading architecture.md:

    user certificate      docs "default 7d"            code 12h
    renewal               docs "~24h before expiry"    code 3h
    playbook run cert     docs "default 2h TTL"        code run timeout + 15m (45m)
    principal             docs `fleet`                 code `prov` (fleet is legacy)

Every one of those describes how long a stolen credential stays useful, which is
exactly what a reader consults this document to learn, and what an auditor would
compare against the implementation.

The interesting part is WHERE the rot was. At the time, 35 documented defaults
stated their value next to the setting's name, and all 35 were correct. All four
wrong statements were in prose that named no setting at all — nothing could check
them, so nothing did. Hence two rules:

 1. Where the docs state a default beside a `PROV_*` name, it must match config.go.
 2. In the documents that describe SECURITY properties, a stated lifetime must name
    the setting that controls it — otherwise it is an unverifiable claim about the
    blast radius of a compromised credential, and rule 1 cannot see it.

Rule 2 is deliberately limited to durations in the security-describing documents.
Ports, row counts and table defaults elsewhere are not credential lifetimes, and
forcing a setting name next to every number in the docs would be noise.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
DOCS = os.path.join(ROOT, "docs")

# Documents whose numbers are security claims.
LIFETIME_DOCS = ("architecture.md", "security-guide.md")

UNIT = r"(?:ns|us|ms|s|m|h|d|w|sec|secs|second|seconds|min|mins|minute|minutes|hour|hours|day|days|week|weeks)"

GO_UNIT = {
    "Nanosecond": 1e-9, "Microsecond": 1e-6, "Millisecond": 1e-3,
    "Second": 1, "Minute": 60, "Hour": 3600,
}
DOC_UNIT = {
    "ns": 1e-9, "us": 1e-6, "ms": 1e-3,
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
    "d": 86400, "day": 86400, "days": 86400,
    "w": 604800, "week": 604800, "weeks": 604800,
}


def go_duration(expr):
    """`12*time.Hour` -> 43200.0 seconds. None when it is not a literal."""
    unit = re.search(r"time\.(\w+)", expr)
    if not unit or unit.group(1) not in GO_UNIT:
        return None
    secs = GO_UNIT[unit.group(1)]
    for n in re.findall(r"(\d+)\s*\*", expr):
        secs *= int(n)
    return secs


def doc_duration(text):
    """`12h`, `12 hours`, `**30 days**` -> seconds. None when not a duration."""
    t = text.strip().lower().replace("**", "").replace("`", "")
    m = re.match(r"^(\d+(?:\.\d+)?)\s*(" + UNIT + r")\b", t)
    if not m:
        return None
    return float(m.group(1)) * DOC_UNIT[m.group(2)]


def config_defaults():
    src = open(os.path.join(ROOT, "backend/internal/config/config.go"), encoding="utf-8").read()
    out = {}
    for m in re.finditer(r'\benv(Duration|Int|Bool|)\("(PROV_[A-Z0-9_]+)",\s*([^\n]+?)\),', src):
        out[m.group(2)] = (m.group(1) or "Str", m.group(3).strip())
    return out


def markdown_docs():
    for name in sorted(os.listdir(DOCS)):
        # CHANGELOG records what was true at the time; a default that has since
        # changed should still be named in the entry that changed it.
        if name.endswith(".md") and name != "CHANGELOG.md":
            yield name, open(os.path.join(DOCS, name), encoding="utf-8").read()


def rule_values_match(real):
    """Rule 1: a default stated beside a setting name must be the real one."""
    problems, checked = [], 0
    for name, body in markdown_docs():
        for m in re.finditer(r"`(PROV_[A-Z0-9_]+)`(.{0,120})", body, re.S):
            setting, tail = m.group(1), m.group(2)
            stated = re.search(r"default[s]?[:\s]*`?([^`,;\n\)]+)`?", tail, re.I)
            if not stated or setting not in real:
                continue
            kind, raw = real[setting]
            said = stated.group(1).strip()
            line = body[: m.start()].count("\n") + 1
            checked += 1
            if kind == "Duration":
                a, b = go_duration(raw), doc_duration(said)
                if a is not None and b is not None and abs(a - b) > 0.5:
                    problems.append(f"{name}:{line}: {setting} — docs say {said!r}, code says {raw}")
            elif kind == "Int":
                n = re.match(r"^\**(\d+)", said)
                if n and raw.isdigit() and int(n.group(1)) != int(raw):
                    problems.append(f"{name}:{line}: {setting} — docs say {said!r}, code says {raw}")
            elif kind == "Bool":
                truthy = ("true", "on", "enabled", "yes")
                falsy = ("false", "off", "disabled", "no")
                said_l = said.lower().replace("**", "")
                if said_l in truthy + falsy and (("true" in raw) != (said_l in truthy)):
                    problems.append(f"{name}:{line}: {setting} — docs say {said!r}, code says {raw}")
    return problems, checked


def rule_lifetimes_are_checkable():
    """Rule 2: a lifetime in a security document must name its setting."""
    problems, checked = [], 0
    for name, body in markdown_docs():
        if name not in LIFETIME_DOCS:
            continue
        for m in re.finditer(r"\bdefault[s]?\b[:\s]*\**`?(\d+(?:\.\d+)?\s*" + UNIT + r")\b", body, re.I):
            checked += 1
            context = body[max(0, m.start() - 200): m.end() + 80]
            if re.search(r"PROV_[A-Z0-9_]+", context):
                continue
            line = body[: m.start()].count("\n") + 1
            problems.append(
                f"{name}:{line}: states a default of {m.group(1).strip()!r} without naming the "
                f"setting that controls it, so nothing can check it"
            )
    return problems, checked


def main():
    real = config_defaults()
    print(f"== documented defaults match the code ==")
    print(f"  read {len(real)} defaults from config.go")
    bad_values, n_values = rule_values_match(real)
    for p in bad_values:
        print(f"  FAIL  {p}")
    if not bad_values:
        print(f"  PASS  {n_values} documented default(s) agree with the code")

    print(f"== documented lifetimes name their setting ==")
    bad_prose, n_prose = rule_lifetimes_are_checkable()
    for p in bad_prose:
        print(f"  FAIL  {p}")
    if not bad_prose:
        print(f"  PASS  {n_prose} lifetime(s) in {', '.join(LIFETIME_DOCS)} are checkable")

    failures = len(bad_values) + len(bad_prose)
    print()
    if failures:
        print(f"{failures} documentation drift(s). A wrong lifetime in these documents is a wrong")
        print("statement about how long a compromised credential is useful.")
        return 1
    print("0 failure(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
