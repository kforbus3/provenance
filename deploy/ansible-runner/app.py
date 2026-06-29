"""Fleet Terminal — ansible-runner sidecar.

A small internal HTTP service the Fleet backend calls to validate and lint
Ansible playbooks. It keeps Python + Ansible out of the lean Go backend and
isolates the (eventual) execution blast radius in its own container.

Phase 1 exposes only host-safe operations — neither endpoint connects to any
managed host:
  GET  /healthz       liveness
  POST /syntax-check  ansible-playbook --syntax-check on the posted YAML
  POST /lint          ansible-lint on the posted YAML

Execution (POST /run, streaming) lands in Phase 2.
"""

import os
import shutil
import subprocess
import tempfile

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="fleet-ansible-runner", version="1")

# Cap how long a validation/lint may run so a pathological file can't wedge the
# sidecar.
CHECK_TIMEOUT = int(os.environ.get("RUNNER_CHECK_TIMEOUT", "60"))
MAX_CONTENT = 1 << 20  # 1 MiB of YAML is plenty for a single playbook.


class ContentRequest(BaseModel):
    content: str = ""


class CheckResult(BaseModel):
    ok: bool
    output: str


def _truncate(text: str, limit: int = 64_000) -> str:
    if len(text) > limit:
        return text[:limit] + "\n…(truncated)"
    return text


def _run_against_tempfile(argv_builder, content: str) -> CheckResult:
    """Write content to a temp playbook and run a checker command over it."""
    if len(content) > MAX_CONTENT:
        return CheckResult(ok=False, output="playbook is too large")

    workdir = tempfile.mkdtemp(prefix="fleet-pb-")
    try:
        path = os.path.join(workdir, "playbook.yml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        argv = argv_builder(path)
        try:
            proc = subprocess.run(
                argv,
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=CHECK_TIMEOUT,
                # Never inherit credentials/agents; nothing here should reach a host.
                env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                     "HOME": workdir,
                     "ANSIBLE_NOCOLOR": "1",
                     "ANSIBLE_LOCAL_TEMP": workdir,
                     "ANSIBLE_RETRY_FILES_ENABLED": "0"},
            )
        except subprocess.TimeoutExpired:
            return CheckResult(ok=False, output=f"timed out after {CHECK_TIMEOUT}s")
        except FileNotFoundError as exc:
            return CheckResult(ok=False, output=f"checker not available: {exc}")

        out = (proc.stdout or "") + (proc.stderr or "")
        out = out.strip() or ("OK" if proc.returncode == 0 else "(no output)")
        return CheckResult(ok=proc.returncode == 0, output=_truncate(out))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/syntax-check", response_model=CheckResult)
def syntax_check(req: ContentRequest):
    # `-i localhost,` gives an inline inventory so syntax-check never complains
    # about an empty hosts list; it still does not connect to anything.
    return _run_against_tempfile(
        lambda path: ["ansible-playbook", "--syntax-check", "-i", "localhost,", path],
        req.content,
    )


@app.post("/lint", response_model=CheckResult)
def lint(req: ContentRequest):
    return _run_against_tempfile(
        lambda path: ["ansible-lint", "--nocolor", "--parseable", path],
        req.content,
    )
