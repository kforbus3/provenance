"""No two modules may register the same method and path.

A duplicate route does not fail loudly. chi takes one of them and the other never
runs, so the symptom appears wherever the losing route's caller is -- as wrong
data, not as an error.

It shipped. `GET /sessions` already belonged to the SSH session RECORDINGS api
(sessionsapi, gated on Session.Replay) and the browser sign-ins screen registered
it again (admin, gated on Session.Terminate). The recordings route won. So the
"Active sign-ins" panel listed SSH recordings as browser sessions:

  - dozens of rows for a single user, which read as a session leak
  - every device "unknown", because a recording carries no user agent
  - every row badged "no MFA", because it carries no mfaPassed either

Three symptoms that all looked like defects in the sign-in data, and none of them
were. The tests that existed asserted the admin route was mounted and gated
correctly -- which it was. A test can only see the module it reads.

Two things in this product are called a "session": a browser sign-in and a
recorded SSH session. That is the collision waiting to happen, and it happened.

Permissions differing between the two registrations makes it worse, not better:
whichever route loses, its permission gate is not the one being enforced.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
API = os.path.join(ROOT, "backend", "internal")

# `.Get("/path"`, `.Post("/path"`, ... on a chi router.
ROUTE = re.compile(
    r'\.(Get|Post|Put|Patch|Delete|Head|Options)\(\s*"([^"]+)"',
)

failures = []
checks = 0


def check(name, cond, detail=""):
    global checks
    checks += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        for line in (detail or "").strip().splitlines():
            print(f"        {line}")
        failures.append(name)


# A chi path parameter's NAME does not affect matching: /x/{id} and /x/{userId}
# are the same route to the router and collide with each other. Normalise so the
# comparison sees what chi sees.
def normalise(path):
    return re.sub(r"\{[^}/]+\}", "{}", path)


routes = {}          # (method, normalised path) -> [(file, line, raw path)]
for dirpath, dirnames, filenames in os.walk(API):
    dirnames[:] = [d for d in dirnames if d not in {"testdata"}]
    for fn in filenames:
        if not fn.endswith(".go") or fn.endswith("_test.go"):
            continue
        if fn == "docs_generated.go":
            continue
        path = os.path.join(dirpath, fn)
        for i, line in enumerate(open(path, encoding="utf-8"), 1):
            if line.lstrip().startswith("//"):
                continue
            for method, route in ROUTE.findall(line):
                if not route.startswith("/"):
                    continue
                key = (method, normalise(route))
                routes.setdefault(key, []).append(
                    (os.path.relpath(path, ROOT), i, route))

print("== no route is registered twice ==")

dupes = {k: v for k, v in routes.items() if len(v) > 1}
# Same file, same line is one registration seen twice; same file twice is a
# mount helper called for several routers, which chi handles. Only flag
# registrations in DIFFERENT files, which is the case nobody reviews together.
dupes = {k: v for k, v in dupes.items()
         if len({f for f, _, _ in v}) > 1}

check(f"{len(routes)} routes, none duplicated across modules", not dupes)
for (method, norm), where in sorted(dupes.items()):
    print(f"        {method} {norm}")
    for f, ln, raw in where:
        print(f"          {f}:{ln}  ({raw})")
    print("        chi takes one and the other never runs. The losing caller")
    print("        gets the winner's data, and the winner's permission gate.")

# The specific pair that shipped, named so a future edit that recreates it fails
# on its own line rather than in a list of many.
recordings = routes.get(("Get", "/sessions"), [])
check("GET /sessions belongs to one module only",
      len({f for f, _, _ in recordings}) <= 1,
      "\n".join(f"{f}:{ln}" for f, ln, _ in recordings))

print()
if failures:
    print(f"FAILED ({len(failures)})")
    sys.exit(1)
print(f"all {checks} route-collision checks passed")
