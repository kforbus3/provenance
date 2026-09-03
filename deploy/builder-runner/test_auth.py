"""The builder runner's token guard, checked against every route it exposes.

This service can start privileged containers. A route that reaches it without a
token is root on the host, so "is this endpoint guarded" is not a question to
answer by reading the file -- the interesting failure is a route added later
that nobody remembered to decorate, and reading catches exactly the cases you
already thought about.

So the routes are enumerated from the running app rather than listed here. A new
endpoint without `dependencies=guarded` fails this test on the day it is added,
which is the only day it is cheap to fix.

    python3 deploy/builder-runner/test_auth.py
"""

from __future__ import annotations

import os
import sys
import tempfile

os.environ.setdefault("FLEET_BUILDER_RUNNER_TOKEN", "test-token-not-a-real-secret")
# A real, empty, writable directory. The job manager creates its state directory
# at import time and refuses to start without one -- correctly, since a runner
# that cannot record what it is doing is worse than one that does not start.
os.environ.setdefault("PROJECT_DIR", tempfile.mkdtemp(prefix="builder-runner-test-"))

from fastapi.testclient import TestClient  # noqa: E402

import app  # noqa: E402

TOKEN = os.environ["FLEET_BUILDER_RUNNER_TOKEN"]
GOOD = {"X-Runner-Token": TOKEN}
WRONG = {"X-Runner-Token": TOKEN + "x"}

client = TestClient(app.app)

_ok = _fail = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _ok, _fail
    if cond:
        _ok += 1
        print(f"  PASS  {name}")
    else:
        _fail += 1
        print(f"  FAIL  {name} {detail}")


def _verb(route) -> str:
    return sorted(route.methods - {"HEAD", "OPTIONS"})[0]


def _path(route) -> str:
    # Any value will do: the guard runs before the handler, so these never reach
    # code that would care what the id is.
    return route.path.replace("{name}", "x").replace("{job_id}", "x")


def guarded_routes():
    """Every route that must require a token.

    /healthz is exempt: a liveness probe that needs a secret is a liveness probe
    that reports the secret being wrong as the service being down. FastAPI's own
    doc routes are exempt because they describe the API rather than act on it.
    """
    for r in app.app.routes:
        if not hasattr(r, "methods"):
            continue
        if r.path in ("/healthz",) or r.path.startswith(("/docs", "/redoc", "/openapi")):
            continue
        yield r


def main() -> int:
    print("== the probe is reachable without a credential ==")
    check("GET /healthz -> 200", client.get("/healthz").status_code == 200)

    routes = list(guarded_routes())
    check("there are routes to check at all", len(routes) > 10, f"(found {len(routes)})")

    print(f"\n== all {len(routes)} other routes refuse a missing token ==")
    missing = [f"{_verb(r)} {r.path}" for r in routes
               if client.request(_verb(r), _path(r)).status_code != 401]
    check("none reachable unauthenticated", not missing, f"-> {missing}")

    print(f"\n== and all {len(routes)} refuse a wrong one ==")
    # Separately from the missing-token case: an `if not token` check that forgets
    # to compare passes the test above and fails this one.
    wrong = [f"{_verb(r)} {r.path}" for r in routes
             if client.request(_verb(r), _path(r), headers=WRONG).status_code != 401]
    check("none reachable with a bad token", not wrong, f"-> {wrong}")

    print("\n== a correct token gets past the guard ==")
    # Not asserting 200: PROJECT_DIR is an empty temporary directory, so there is
    # nothing to list and some of this may fail on its own terms. What matters is
    # that it failed for a reason other than auth -- a guard that rejected
    # everything would pass every test above.
    r = client.get("/images", headers=GOOD)
    check("GET /images is not 401", r.status_code != 401, f"(got {r.status_code})")
    r = client.get("/jobs", headers=GOOD)
    check("GET /jobs is not 401", r.status_code != 401, f"(got {r.status_code})")

    print("\n== an artefact name is a name, not a path ==")
    for bad in ("..%2F..%2Fetc%2Fpasswd", "..", "%2Fetc%2Fpasswd"):
        r = client.delete(f"/images/{bad}", headers=GOOD)
        check(f"DELETE /images/{bad} refused", r.status_code in (400, 404, 405),
              f"(got {r.status_code})")

    print(f"\n{_ok} passed, {_fail} failed")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
