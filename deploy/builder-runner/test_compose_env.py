"""Every setting the backend reads must reach the backend.

PROV_TRUSTED_PROXY_HOPS was added to config.go, wired into the middleware,
tested, merged and deployed -- and did nothing, because docker-compose.yml never
passed it. Compose does not forward a .env file's contents to a container; it
uses them for substitution, and the service must name the variable. So the
setting was present in .env, absent from the process, and the code fell back to
its default while the operator's file said otherwise.

Nothing catches that shape. The Go code compiles, its tests pass (they construct
a Config directly), the container starts, and the only symptom is a setting that
has no effect -- which looks exactly like the setting not being the problem.

So: every PROV_* variable config.go reads must be declared in the compose file,
or listed below as a deliberate exception.

The exceptions are a snapshot taken when this check was written, NOT an
endorsement. Each is a setting the backend reads and the bundled compose does
not supply; several look like real gaps. The list exists so adding a NEW setting
that nothing passes fails here, rather than requiring all of them to be audited
first. Shrink it when you can.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
CONFIG = os.path.join(ROOT, "backend/internal/config/config.go")
COMPOSE = os.path.join(ROOT, "deploy/compose/docker-compose.yml")

# Known-undeclared as of 2026-09-09. See the docstring: a snapshot, not a target.
KNOWN_UNDECLARED = {
    "PROV_BACKUP_DIR", "PROV_DR_STANDBY_TOKEN", "PROV_FIPS_MODE",
    "PROV_GUACD_ADDR", "PROV_IMAGING_SECRET_PREFIX",
    "PROV_KMS_AWS_SESSION_TOKEN", "PROV_KMS_GCP_CREDENTIALS",
    "PROV_KMS_VAULT_CACERT", "PROV_KMS_VAULT_SKIP_VERIFY",
    "PROV_MFA_ENCRYPTION_KEY", "PROV_MIGRATE_ON_START",
    "PROV_MONITOR_OFFLINE_CONFIRMATIONS", "PROV_MSRC_API_URL",
    "PROV_MSRC_MONTHS", "PROV_OVERLAY", "PROV_OVERLAY_PEER_ISOLATION",
    "PROV_RDP_DRIVE_DIR", "PROV_RDP_PROXY_HOST", "PROV_REDIS_URL",
}

failures = []
checks = 0


def check(name, cond, detail=""):
    global checks
    checks += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        if detail:
            print(detail)
        failures.append(name)


print("== every setting the backend reads reaches the backend ==")

if not (os.path.exists(CONFIG) and os.path.exists(COMPOSE)):
    check("config.go and docker-compose.yml are both present", False)
else:
    cfg = open(CONFIG, encoding="utf-8").read()
    # env("X"), envInt("X"), envBool("X"), envInt64("X"), ...
    used = set(re.findall(r'env(?:Int64|Int|Bool|Dur|Float)?\(\s*"(PROV_[A-Z0-9_]+)"', cfg))
    compose = open(COMPOSE, encoding="utf-8").read()
    declared = set(re.findall(r'^\s{6}(PROV_[A-Z0-9_]+):', compose, re.M))

    check("found the settings to compare", len(used) > 50 and len(declared) > 50,
          f"        parsed {len(used)} read / {len(declared)} declared. If either "
          "shape changed, fix this check rather than letting it pass on nothing.")

    missing = sorted(used - declared - KNOWN_UNDECLARED)
    detail = ""
    if missing:
        detail = ("        read by config.go, never passed by compose:\n" +
                  "".join(f"          {m}\n" for m in missing) +
                  "        Add it to the backend service's environment block as\n"
                  "          NAME: ${NAME:-<default>}\n"
                  "        A .env entry alone does NOT reach the container: compose uses\n"
                  "        .env for substitution, and the service must name the variable.\n"
                  "        If it is genuinely supplied another way, add it to\n"
                  "        KNOWN_UNDECLARED with a reason.")
    check("no new setting is unreachable from the deployment", not missing, detail)

    # The exception list must not rot: an entry that has since been declared, or
    # that no longer exists, is noise that makes the real ones easier to ignore.
    stale = sorted((KNOWN_UNDECLARED & declared) | (KNOWN_UNDECLARED - used))
    check("the exception list has no stale entries", not stale,
          "        no longer needed: " + ", ".join(stale) if stale else "")

print()
if failures:
    print(f"FAILED ({len(failures)})")
    sys.exit(1)
print(f"all {checks} compose-environment checks passed")
