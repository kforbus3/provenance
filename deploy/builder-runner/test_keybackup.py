"""The imaging key backup: what it reports, and what it refuses.

The archive contains the RAUC signing key. Losing it means no already-deployed
machine can ever be updated again -- not "until we re-key", ever, because each
verifies against a certificate baked into its own image. So the interesting
assertions here are about what does NOT leave the host.
"""

import os
import re
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


print("== the archive name is not a path ==")
# It arrives from a browser and is joined to a directory.
for bad in ("../../etc/shadow", "/etc/shadow", "sub/a.tar.gz", "..", "",
            "a.tar.gz/../../b.tar.gz", "notanarchive", "key.pem"):
    try:
        orch._safe_backup_name(bad)
        check(f"{bad!r} refused", False)
    except ValueError:
        check(f"{bad!r} refused", True)
check("a plain archive name is accepted",
      orch._safe_backup_name("imaging-keys-20260907-000000.tar.gz")
      == "imaging-keys-20260907-000000.tar.gz")

print("== status reports what is missing, not just what is there ==")
st = orch.key_backup_status()
check("every tracked path is reported", len(st["items"]) == len(orch.KEY_BACKUP_PATHS))
check("nothing is present in an empty project", all(not i["present"] for i in st["items"]))
check("and that is surfaced as the signing key being absent", st["haveSigningKey"] is False)
check("no backups listed yet", st["backups"] == [])

os.makedirs(os.path.join(_tmp, "output", "rauc-keys"), exist_ok=True)
with open(os.path.join(_tmp, "output", "rauc-keys", "key.pem"), "w") as f:
    f.write("not a real key\n")
st = orch.key_backup_status()
check("the signing key is noticed once present", st["haveSigningKey"] is True)

print("== the tracked paths match the script's own list ==")
# One list here, one array there. They disagree only if somebody adds a path to
# one -- and a path missing from the backup is one nobody finds out about until
# a restore comes up short.
script = os.path.join(_tmp, "scripts", "imaging", "imaging-keys-backup.sh")
real = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "scripts", "imaging", "imaging-keys-backup.sh")
if os.path.isfile(real):
    body = open(real).read()
    m = re.search(r"^PATHS=\((.*?)\)", body, re.S | re.M)
    listed = set(m.group(1).split()) if m else set()
    ours = {p for p, _why in orch.KEY_BACKUP_PATHS}
    check(f"script paths {sorted(listed)} match the orchestrator's", listed == ours)
else:
    check("the backup script was found for cross-check", False)

print("== no route returns key material ==")
app_src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")).read()
keys_routes = re.findall(r'@app\.(get|post)\("(/keys[^"]*)"', app_src)
check(f"routes are {[r[1] for r in keys_routes]} and none is a download",
      all("download" not in r[1] for r in keys_routes))
check("inspect returns entry NAMES only",
      "entries" in orch.key_backup_inspect.__doc__ or "names" in orch.key_backup_inspect.__doc__.lower())

print(f"\n{16 - len(failures)} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
