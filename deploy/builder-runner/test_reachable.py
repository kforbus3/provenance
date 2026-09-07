"""Every capability the orchestrator provides must be reachable from the API.

The bug this pins: `server_clients()` — the function that lists machines
currently on the provisioning network — was ported across from Flipside with the
rest of the provisioning stack and then wired to nothing. No route in app.py, no
backend handler, nothing in the UI. It ran, it worked, and there was no way to
call it.

From the outside that is indistinguishable from the feature not existing, and
that is exactly how it was reported: "Flipside would show me connected machines,
Blackfriars does not". The code was there the whole time.

That failure mode is invisible to every other check in this repo. It is not a
syntax error, not a broken guard, not a wrong family branch — it is working code
with no caller, which no test that exercises behaviour will ever reach, because
nothing reaches it.

So: any top-level function in orchestrator.py that is never referenced anywhere
— not by app.py, not by another orchestrator function, not by a test — is either
dead code or a capability someone forgot to wire up. Both are worth a failure,
and the fix for the first is to delete it.

Names starting with `_` are internal by convention and exempt.
"""

import ast
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Functions that genuinely have no caller in this repo, with the reason. Keep
# this list short and justified: every entry is a claim that something unused is
# meant to be unused, and an unexamined allowlist is how the original bug would
# have been waved through.
ALLOWED_UNREFERENCED = {
    # (none today)
}


def top_level_functions(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    return [n.name for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not n.name.startswith("_")]


def main():
    orch_path = os.path.join(HERE, "orchestrator.py")
    if not os.path.exists(orch_path):
        print("  FAIL  orchestrator.py not found")
        return 1

    names = top_level_functions(orch_path)

    # Everything that could plausibly reference them.
    haystacks = {}
    for fn in os.listdir(HERE):
        if fn.endswith(".py"):
            haystacks[fn] = open(os.path.join(HERE, fn), encoding="utf-8").read()

    orch_src = haystacks["orchestrator.py"]

    unreachable = []
    for name in names:
        # Every mention of the name anywhere in the sidecar, minus the one that
        # is its own `def`. Counting mentions rather than call sites on purpose:
        # a function referenced without being called -- passed as a value, named
        # in a dispatch table -- is still wired to something, and this check is
        # about "can anything reach it", not "is it invoked here".
        total = sum(len(re.findall(rf"\b{re.escape(name)}\b", src))
                    for src in haystacks.values())
        defs = len(re.findall(rf"^\s*(?:async\s+)?def\s+{re.escape(name)}\b",
                              orch_src, flags=re.M))
        if total - defs <= 0 and name not in ALLOWED_UNREFERENCED:
            unreachable.append(name)

    print(f"== orchestrator capabilities are reachable ({len(names)} public functions) ==")
    if not unreachable:
        print(f"  PASS  all {len(names)} are called from somewhere")
        return 0

    for name in sorted(unreachable):
        print(f"  FAIL  {name}() is defined and never called")
        print("        Either it needs a route in app.py (and a backend handler, and UI),")
        print("        or it is dead code and should be deleted. A capability with no")
        print("        caller looks exactly like a missing feature to whoever wanted it.")
    print()
    print(f"FAILED ({len(unreachable)})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
