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

import json
import os
import shutil
import subprocess
import tempfile
from typing import List

from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

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


# --- execution -------------------------------------------------------------

class RunHost(BaseModel):
    name: str
    address: str
    user: str = "fleet"
    port: int = 22


class RunRequest(BaseModel):
    # Accept the Go backend's camelCase keys (privateKey, jumpHost, …) while
    # keeping Pythonic field names.
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    playbook: str
    private_key: str = ""       # OpenSSH private key (the run credential)
    certificate: str = ""       # matching user certificate (authorized_keys form)
    hosts: List[RunHost] = []
    jump_host: str = ""         # host:port of the Fleet jump host
    jump_user: str = "fleet"
    check_mode: bool = False    # ansible --check (dry run)
    become: bool = True
    timeout_secs: int = 1800


def _ndjson(obj) -> str:
    return json.dumps(obj) + "\n"


def _split_host_port(hostport: str, default_port: int = 22):
    if ":" in hostport:
        h, _, p = hostport.rpartition(":")
        try:
            return h, int(p)
        except ValueError:
            return hostport, default_port
    return hostport, default_port


def _build_ssh_config(req: RunRequest, key_path: str) -> str:
    # A real ssh_config so BOTH hops use the certificate and relaxed host-key
    # handling. Command-line -i / -o options do NOT propagate to a ProxyJump's
    # inner connection, so the jump hop must be configured explicitly here. The
    # certificate (<key>-cert.pub) is loaded automatically alongside the key.
    jhost, jport = _split_host_port(req.jump_host)
    return "\n".join([
        "Host fleet-jump",
        f"    HostName {jhost}",
        f"    Port {jport}",
        f"    User {req.jump_user}",
        f"    IdentityFile {key_path}",
        "    IdentitiesOnly yes",
        "    StrictHostKeyChecking no",
        "    UserKnownHostsFile /dev/null",
        "    ConnectTimeout 15",
        "",
        # Every managed host (anything that is not the jump itself) is reached
        # through the jump host.
        "Host * !fleet-jump",
        "    ProxyJump fleet-jump",
        f"    IdentityFile {key_path}",
        "    IdentitiesOnly yes",
        "    StrictHostKeyChecking no",
        "    UserKnownHostsFile /dev/null",
        "    ConnectTimeout 15",
        "",
    ])


def _build_inventory(req: RunRequest, key_path: str, ssh_config_path: str) -> str:
    common = f"-F {ssh_config_path}"
    lines = ["[all]"]
    for h in req.hosts:
        lines.append(f"{h.name} ansible_host={h.address} ansible_port={h.port} ansible_user={h.user}")
    lines += [
        "",
        "[all:vars]",
        f"ansible_ssh_private_key_file={key_path}",
        f"ansible_ssh_common_args={common}",
    ]
    if req.become:
        lines += ["ansible_become=true", "ansible_become_method=sudo"]
    return "\n".join(lines) + "\n"


def _stream_run(req: RunRequest):
    if not req.hosts:
        yield _ndjson({"done": True, "rc": 1, "error": "no target hosts"})
        return
    if len(req.playbook) > MAX_CONTENT:
        yield _ndjson({"done": True, "rc": 1, "error": "playbook is too large"})
        return

    workdir = tempfile.mkdtemp(prefix="fleet-run-")
    proc = None
    try:
        pb_path = os.path.join(workdir, "playbook.yml")
        inv_path = os.path.join(workdir, "inventory.ini")
        cfg_path = os.path.join(workdir, "ssh_config")
        key_path = os.path.join(workdir, "id")
        cert_path = os.path.join(workdir, "id-cert.pub")

        with open(pb_path, "w", encoding="utf-8") as fh:
            fh.write(req.playbook)
        # Private key must be 0600 or OpenSSH refuses it.
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(req.private_key if req.private_key.endswith("\n") else req.private_key + "\n")
        with open(cert_path, "w", encoding="utf-8") as fh:
            fh.write(req.certificate if req.certificate.endswith("\n") else req.certificate + "\n")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(_build_ssh_config(req, key_path))
        with open(inv_path, "w", encoding="utf-8") as fh:
            fh.write(_build_inventory(req, key_path, cfg_path))

        argv = ["ansible-playbook", "-i", inv_path]
        if req.check_mode:
            argv.append("--check")
        argv.append(pb_path)
        # `timeout` makes the run self-terminate (rc 124) so a wedged play can't
        # hang the stream — same wrapper the backend uses for oscap.
        timeout = max(60, int(req.timeout_secs))
        argv = ["timeout", str(timeout)] + argv

        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": workdir,
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_HOST_KEY_CHECKING": "False",
            "ANSIBLE_RETRY_FILES_ENABLED": "0",
            "ANSIBLE_LOCAL_TEMP": workdir,
            "ANSIBLE_FORCE_COLOR": "0",
            "PYTHONUNBUFFERED": "1",
        }
        if req.check_mode:
            yield _ndjson({"line": "[check mode — no changes will be made]"})

        proc = subprocess.Popen(
            argv, cwd=workdir, env=env, text=True, bufsize=1,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        for line in iter(proc.stdout.readline, ""):
            yield _ndjson({"line": line.rstrip("\n")})
        proc.wait()
        rc = proc.returncode
        msg = f"run timed out after {timeout}s" if rc == 124 else ""
        yield _ndjson({"done": True, "rc": rc, "error": msg})
    except Exception as exc:  # noqa: BLE001 — report any failure to the caller
        if proc and proc.poll() is None:
            proc.kill()
        yield _ndjson({"done": True, "rc": 1, "error": f"runner error: {exc}"})
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@app.post("/run")
def run(req: RunRequest):
    # NDJSON stream: {"line": "..."} per output line, then {"done": true, "rc": N}.
    return StreamingResponse(_stream_run(req), media_type="application/x-ndjson")
