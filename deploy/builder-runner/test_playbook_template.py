"""The A/B update playbook exists twice; keep the copies identical.

deploy/playbooks/ab-update.yml is the copy ansible can syntax-check and run.
frontend/src/lib/playbook-templates.ts carries the copy the UI actually offers
when someone creates a playbook from a template.

Drift between them is invisible in the worst way: the file keeps passing every
check it has, while the template handed to users is the stale one. Nothing in
either tree would notice — the YAML has no importer, and the TS constant has no
validator. So compare them here, where both are on disk.

This lives with the imaging checks rather than in vitest because `make
frontend-test` mounts only frontend/ into its container: a check that cannot see
the other side is a test that cannot fail.
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))

YAML = os.path.join(ROOT, "deploy/playbooks/ab-update.yml")
TS = os.path.join(ROOT, "frontend/src/lib/playbook-templates.ts")

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


print("== the UI's A/B playbook template matches the file on disk ==")

if not os.path.exists(YAML):
    check("deploy/playbooks/ab-update.yml exists", False)
elif not os.path.exists(TS):
    check("frontend/src/lib/playbook-templates.ts exists", False)
else:
    on_disk = open(YAML, encoding="utf-8").read()
    ts = open(TS, encoding="utf-8").read()

    # The content is a JSON string literal, so json.loads decodes it exactly —
    # including the backticks and backslashes that are the reason it is not
    # written as a template literal.
    m = re.search(r'id:\s*"ab-update".*?content:\s*("(?:[^"\\]|\\.)*")', ts, re.S)
    if not m:
        check("the ab-update template has a decodable content string", False,
              "Expected `content: \"...\"` inside the ab-update entry. If the "
              "encoding changed, update this check with it.")
    else:
        embedded = json.loads(m.group(1))
        same = embedded == on_disk
        check("the embedded template is byte-identical to ab-update.yml", same)
        if not same:
            print("        They have drifted. Regenerate the TS constant from the")
            print("        YAML — the YAML is the copy ansible can check, so it wins.")
            a, b = on_disk.splitlines(), embedded.splitlines()
            for i in range(max(len(a), len(b))):
                x = a[i] if i < len(a) else "<missing>"
                y = b[i] if i < len(b) else "<missing>"
                if x != y:
                    print(f"        first difference at line {i + 1}:")
                    print(f"          yaml: {x!r}")
                    print(f"          ts:   {y!r}")
                    break

    # A playbook that reports a GRUB fallback as success is the one failure mode
    # that matters most here: the update did not take, and the machine says it
    # did. Pinned in both copies, because either could be edited alone.
    check("the playbook treats a fallback to the old slot as a failure",
          "slot_after == slot_before" in on_disk and "ansible.builtin.fail" in on_disk)

    # regex_search returns None (not undefined) when the cmdline has no
    # rauc.slot, and Jinja's default() replaces undefined only — so `| first`
    # was handed None and the play died with "'NoneType' object is not
    # iterable" on exactly the machine whose 'unknown' branch this was for.
    searches = re.findall(r"regex_search\('rauc[^\n]*", on_disk)
    check("every slot lookup survives a cmdline with no rauc.slot",
          bool(searches) and all("default([], true) | first" in s for s in searches),
          "Use `| default([], true) | first | default('unknown')`. Without the "
          "first default, a non-A/B cmdline raises a templating error instead.")

print()
if failures:
    print(f"FAILED ({len(failures)})")
    sys.exit(1)
print(f"all {checks} playbook-template checks passed")
