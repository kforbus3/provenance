"""The sidebar agrees with the route table.

Two invariants that drift silently and never surface as an error:

  * every sidebar entry must resolve to a route in App.tsx. A renamed route
    leaves an entry that navigates into the catch-all redirect and quietly dumps
    the user on the dashboard.
  * every entry must claim the same permission its route enforces. Changed on
    one side only, an entry stays visible and then refuses to open.

These read two files, which is why they are here rather than in the vitest
suite: the frontend has no node types, so a `node:fs` import passes vitest and
then fails `tsc -b` inside the production image build. Reading files is what
these checks already do.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
NAV = os.path.join(ROOT, "frontend/src/components/AppLayout.tsx")
APP = os.path.join(ROOT, "frontend/src/App.tsx")

failures = []
checks = 0


def check(name, cond, detail=""):
    global checks
    checks += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        if detail:
            print(f"        {detail}")
        failures.append(name)


print("== the sidebar agrees with the route table ==")

if not (os.path.exists(NAV) and os.path.exists(APP)):
    check("AppLayout.tsx and App.tsx are both present", False)
else:
    nav_src = open(NAV, encoding="utf-8").read()
    app_src = open(APP, encoding="utf-8").read()

    # Each nav entry is `{ to: "/x", label: "...", ..., perm: "Y" }` on one line.
    entries = []
    for m in re.finditer(r'\{\s*to:\s*"([^"]+)"[^}]*\}', nav_src):
        body = m.group(0)
        perm = re.search(r'perm:\s*"([^"]+)"', body)
        entries.append((m.group(1), perm.group(1) if perm else None))

    check("found the nav entries to check", len(entries) >= 10,
          f"parsed {len(entries)}; if the NAV declaration's shape changed, "
          "update this check with it rather than letting it silently pass.")

    missing = []
    mismatched = []
    for to, perm in entries:
        path = to.lstrip("/")
        if not path:
            continue  # "/" is the index route
        m = re.search(r'path="%s"[^\n]*' % re.escape(path), app_src)
        if not m:
            missing.append(to)
            continue
        rp = re.search(r'permission="([^"]+)"', m.group(0))
        route_perm = rp.group(1) if rp else None
        if route_perm != perm:
            mismatched.append(f"{to}: sidebar={perm or 'none'} route={route_perm or 'none'}")

    check("every sidebar entry has a route", not missing,
          "no route in App.tsx for: " + ", ".join(missing) if missing else "")
    check("every entry claims the permission its route enforces", not mismatched,
          "; ".join(mismatched) if mismatched else "")

    tos = [t for t, _ in entries]
    dupes = sorted({t for t in tos if tos.count(t) > 1})
    check("no entry appears twice", not dupes, ", ".join(dupes) if dupes else "")

print()
if failures:
    print(f"FAILED ({len(failures)})")
    sys.exit(1)
print(f"all {checks} navigation checks passed")
