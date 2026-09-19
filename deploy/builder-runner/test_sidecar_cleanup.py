"""Deleting an artefact takes its sidecars with it.

keith deleted several images from the UI and found their SBOMs still in the output
directory: delete_image removed a hardcoded `.sha256` and `.json`, while the SBOM
step had since started writing `.cdx.json`, `.spdx.json` and `.packages.tsv`. The
files were orphaned for good -- nothing failed, so nothing said so.

These cover both halves: everything belonging to the artefact goes, and nothing
belonging to a SIBLING build does. The names differ only by a suffix, so a sloppy
prefix match would quietly delete the wrong build's SBOM.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_tmp = tempfile.mkdtemp()
os.environ["PROJECT_DIR"] = _tmp

import orchestrator as orch  # noqa: E402

failures = []


def check(name, cond):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


out = orch.settings.output_dir
os.makedirs(out, exist_ok=True)

IMAGE = "debian-trixie-amd64-ab.img.zst"
SIBLING = "debian-trixie-amd64-ab-2.img.zst"
SIDECARS = [".sha256", ".json", ".cdx.json", ".spdx.json", ".packages.tsv"]

for name in [IMAGE, SIBLING]:
    open(os.path.join(out, name), "w").close()
    for suffix in SIDECARS:
        open(os.path.join(out, name + suffix), "w").close()

print("== every sidecar the SBOM step writes goes with the image ==")
orch.delete_image(IMAGE)
check("the image itself is gone", not os.path.exists(os.path.join(out, IMAGE)))
for suffix in SIDECARS:
    check(f"{suffix} removed", not os.path.exists(os.path.join(out, IMAGE + suffix)))

print("== a sibling build whose name shares the prefix is untouched ==")
check("sibling image kept", os.path.exists(os.path.join(out, SIBLING)))
for suffix in SIDECARS:
    check(f"sibling {suffix} kept", os.path.exists(os.path.join(out, SIBLING + suffix)))

print("\n%d failure(s)" % len(failures))
sys.exit(1 if failures else 0)
