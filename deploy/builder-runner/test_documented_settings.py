"""Every FLEET_* setting the docs name must exist in the code.

api.md documented an entire imaging API that proxied to a separate "Flipside
deployment" configured by FLEET_FLIPSIDE_URL. None of it existed: imaging is
in-process, and the setting appears nowhere in the source. Six documented routes
were fabricated too.

That doc is not only read by people. It is embedded into the AI assistant's
index, so the assistant was confidently handing users a setting to configure and
endpoints to call that would 404 — the worst kind of documentation error, because
it is indistinguishable from working documentation until you follow it.

A phantom setting is the cheapest version of that mistake to detect: the docs say
`FLEET_X`, and either the code reads it or the docs are wrong.

Scope note: settings are read in cmd/ as well as internal/config, so the whole
backend tree is searched. Restricting this to config.go produces false positives
(FLEET_UPDATER_BACKENDS is real, and lives in cmd/fleet-updater).

CHANGELOG.md is excluded. It is a record of what was true at the time, and a
setting removed in a later release should still be named in the entry that
removed it.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))

code = []
for base in ("backend", "server", "deploy"):
    for dirpath, _, files in os.walk(os.path.join(ROOT, base)):
        for f in files:
            if f.endswith((".go", ".sh", ".py", ".yml", ".yaml", ".tmpl")) and f != "docs_generated.go":
                try:
                    code.append(open(os.path.join(dirpath, f), encoding="utf-8", errors="ignore").read())
                except OSError:
                    pass
known = set(re.findall(r"FLEET_[A-Z0-9_]+", "\n".join(code)))

phantom = {}
docs_dir = os.path.join(ROOT, "docs")
for name in sorted(os.listdir(docs_dir)):
    if not name.endswith(".md") or name == "CHANGELOG.md":
        continue
    body = open(os.path.join(docs_dir, name), encoding="utf-8").read()
    for v in sorted(set(re.findall(r"`(FLEET_[A-Z0-9_]+)`", body))):
        if v not in known:
            phantom.setdefault(v, []).append(name)

print("== every documented FLEET_* setting exists ==")
if not known:
    print("  FAIL  found no settings in the source; this check needs rewriting")
    sys.exit(1)
print(f"  PASS  read {len(known)} settings from the source tree")

if phantom:
    print(f"  FAIL  {len(phantom)} documented setting(s) do not exist in the code:")
    for v, files in sorted(phantom.items()):
        print(f"          {v}  — named in {', '.join(files)}")
    print("        Either the setting was renamed and the docs were not, or it never")
    print("        existed. Both mislead: docs/ is embedded into the AI assistant, so a")
    print("        phantom setting is handed to users as though it were real.")
    sys.exit(1)
print("  PASS  no phantom settings")
print()
print("all 2 documented-settings checks passed")
