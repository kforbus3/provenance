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
            # Always end with a single newline so the trivial "no newline at end
            # of file" lint rule doesn't fire on pasted content.
            fh.write(content if content.endswith("\n") else content + "\n")
        argv = argv_builder(path, workdir)
        try:
            proc = subprocess.run(
                argv,
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=CHECK_TIMEOUT,
                # Never inherit credentials/agents; nothing here should reach a host.
                # HOME + XDG_CACHE_HOME point ansible-lint at a writable cache so it
                # doesn't warn about an unwritable project/cache directory.
                env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                     "HOME": workdir,
                     "XDG_CACHE_HOME": workdir,
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
        lambda path, workdir: ["ansible-playbook", "--syntax-check", "-i", "localhost,", path],
        req.content,
    )


@app.post("/lint", response_model=CheckResult)
def lint(req: ContentRequest):
    # --project-dir gives ansible-lint a writable place for its cache (the temp
    # dir), silencing the "project directory not writable" warnings.
    return _run_against_tempfile(
        lambda path, workdir: [
            "ansible-lint", "--nocolor", "--parseable", "--project-dir", workdir, path,
        ],
        req.content,
    )


# --- execution -------------------------------------------------------------

class RunHost(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)
    name: str
    address: str
    user: str = "fleet"
    port: int = 22
    # How the FINAL hop to this host authenticates. "fleet_cert" (default) uses the
    # run's Fleet certificate; "vault_ssh_key"/"vault_password" inject a per-host
    # vaulted credential so appliances that don't trust the Fleet CA still work. The
    # jump hop always uses the Fleet certificate.
    auth_method: str = "fleet_cert"
    private_key: str = ""  # vault_ssh_key: this host's private key
    password: str = ""     # vault_password: this host's password
    # RouterOS API device: open a local TCP forward to api_port on this host through the
    # jump, so a community.routeros.api play (connection: local) can reach it — RouterOS's
    # SSH exec channel is unusable for automation. Injects fleet_api_host/fleet_api_port.
    api_tunnel: bool = False
    api_port: int = 8728


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


_COMMON = [
    "    IdentitiesOnly yes",
    "    StrictHostKeyChecking no",
    "    UserKnownHostsFile /dev/null",
    "    ConnectTimeout 15",
    "",
]


def _build_ssh_config(req: RunRequest, key_path: str, vault_key_paths: dict) -> str:
    # A real ssh_config so BOTH hops authenticate correctly and command-line options
    # (which do NOT propagate to a ProxyJump's inner connection) aren't relied on. The
    # jump hop ALWAYS uses the Fleet certificate; the final hop uses the Fleet cert for
    # fleet_cert hosts, or a per-host vaulted key/password for vaulted hosts. ssh_config
    # `Host` patterns match the ADDRESS ansible connects to (ansible_host), not the
    # inventory alias — so per-host stanzas and the catch-all key on the address.
    jhost, jport = _split_host_port(req.jump_host)
    lines = [
        "Host fleet-jump",
        f"    HostName {jhost}",
        f"    Port {jport}",
        f"    User {req.jump_user}",
        f"    IdentityFile {key_path}",
    ] + _COMMON

    vaulted_addrs = []
    for h in req.hosts:
        if h.auth_method == "vault_ssh_key":
            vaulted_addrs.append(h.address)
            lines += [
                f"Host {h.address}",
                "    ProxyJump fleet-jump",
                f"    IdentityFile {vault_key_paths[h.address]}",
            ] + _COMMON
        elif h.auth_method == "vault_password":
            vaulted_addrs.append(h.address)
            lines += [
                f"Host {h.address}",
                "    ProxyJump fleet-jump",
                "    PubkeyAuthentication no",
                "    PreferredAuthentications password,keyboard-interactive",
                "    NumberOfPasswordPrompts 1",
                "    StrictHostKeyChecking no",
                "    UserKnownHostsFile /dev/null",
                "    ConnectTimeout 15",
                "",
            ]

    # Catch-all for fleet_cert hosts — reached via the jump using the Fleet cert.
    # Exclude the jump alias and every vaulted address so they keep their own stanza.
    exclusions = " ".join(["!fleet-jump"] + [f"!{a}" for a in vaulted_addrs])
    lines += [
        f"Host * {exclusions}",
        "    ProxyJump fleet-jump",
        f"    IdentityFile {key_path}",
    ] + _COMMON
    return "\n".join(lines)


def _inv_quote(v: str) -> str:
    # Quote an inventory var value so passwords with spaces/specials parse safely.
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _build_inventory(req: RunRequest, ssh_config_path: str, vault_key_paths: dict) -> str:
    # Identity/keys for the default ssh connection are driven by the ssh_config (per-host
    # IdentityFile / auth), so no GLOBAL ansible_ssh_private_key_file is set — that would
    # force the Fleet key onto vaulted hosts too. Password hosts carry their secret as a
    # per-host var. A vaulted-key host ALSO gets an explicit per-host key file so the
    # network_cli connection (community.routeros / paramiko), which doesn't read the
    # ssh_config, can authenticate; it's the same key, so the raw/ssh path is unaffected.
    common = f"-F {ssh_config_path}"
    lines = ["[all]"]
    for i, h in enumerate(req.hosts):
        entry = f"{h.name} ansible_host={h.address} ansible_port={h.port} ansible_user={h.user}"
        if h.auth_method == "vault_password" and h.password:
            entry += f" ansible_password={_inv_quote(h.password)}"
        if h.auth_method == "vault_ssh_key" and h.address in vault_key_paths:
            entry += f" ansible_ssh_private_key_file={vault_key_paths[h.address]}"
        # RouterOS API host: expose the local port-forward endpoint the runner opens so a
        # community.routeros.api task (connection: local) can `hostname: {{ fleet_api_host }}`
        # port: {{ fleet_api_port }}` — reaching the device's API through the jump tunnel.
        if h.api_tunnel:
            entry += f" fleet_api_host=127.0.0.1 fleet_api_port={_api_local_port(i)}"
        # Privilege-escalation default is PER HOST: enrolled (fleet_cert) Linux hosts run
        # under sudo as before, but a vaulted host is typically an appliance / network
        # device (router, switch) with no sudo, where forcing become breaks every task
        # ("timeout waiting for privilege escalation prompt"). So become defaults OFF for
        # vaulted hosts. A playbook can still opt a host in with an explicit `become: true`
        # (a play/task keyword overrides this inventory default).
        if req.become:
            escalate = h.auth_method in ("", "fleet_cert")
            entry += " ansible_become=true" if escalate else " ansible_become=false"
        lines.append(entry)
    lines += [
        "",
        "[all:vars]",
        f"ansible_ssh_common_args={common}",
        # The network_cli connection (community.routeros etc.) uses paramiko/libssh, which
        # does NOT read the ssh_config ProxyJump — so give it an explicit ProxyCommand that
        # tunnels through the Fleet jump host (authenticated by the Fleet cert in the config).
        # Ignored by the default ssh connection, so raw/command tasks are unaffected.
        f"ansible_paramiko_proxy_command=ssh -F {ssh_config_path} -W %h:%p fleet-jump",
    ]
    if req.become:
        lines += ["ansible_become_method=sudo"]
    return "\n".join(lines) + "\n"


def _api_local_port(index: int) -> int:
    # Deterministic per-host local forward port. MUST match between the inventory var
    # (fleet_api_port) and the ssh -L setup — both enumerate req.hosts in the same order.
    return 18728 + index


def _wait_port(port: int, timeout_s: float) -> bool:
    import socket
    import time
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def _open_api_tunnels(req: RunRequest, ssh_config_path: str):
    # For each RouterOS-API host, open `ssh -L 127.0.0.1:<lp>:<device>:<apiport> -N fleet-jump`
    # (reusing the fleet-jump cert stanza) so a community.routeros.api play reaches the device's
    # API through the jump. Waits (bounded) for each forward to accept so ansible doesn't race it.
    # Returns (procs, notices).
    procs, notices = [], []
    for i, h in enumerate(req.hosts):
        if not h.api_tunnel:
            continue
        lp = _api_local_port(i)
        cmd = [
            "ssh", "-F", ssh_config_path, "-o", "ExitOnForwardFailure=yes",
            "-L", f"127.0.0.1:{lp}:{h.address}:{h.api_port}", "-N", "fleet-jump",
        ]
        procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        if _wait_port(lp, 15):
            notices.append(f"[api tunnel: {h.name} -> {h.address}:{h.api_port} via 127.0.0.1:{lp}]")
        else:
            notices.append(f"[WARNING: api tunnel to {h.name} ({h.address}:{h.api_port}) did not come up]")
    return procs, notices


def _stream_run(req: RunRequest):
    if not req.hosts:
        yield _ndjson({"done": True, "rc": 1, "error": "no target hosts"})
        return
    if len(req.playbook) > MAX_CONTENT:
        yield _ndjson({"done": True, "rc": 1, "error": "playbook is too large"})
        return

    workdir = tempfile.mkdtemp(prefix="fleet-run-")
    proc = None
    tunnels = []
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
        # Per-host vaulted private keys (0600), keyed by the address ansible connects to.
        vault_key_paths = {}
        for i, h in enumerate(req.hosts):
            if h.auth_method == "vault_ssh_key" and h.private_key:
                vp = os.path.join(workdir, f"key_{i}")
                vfd = os.open(vp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(vfd, "w") as vfh:
                    vfh.write(h.private_key if h.private_key.endswith("\n") else h.private_key + "\n")
                vault_key_paths[h.address] = vp
        # ssh_config and inventory are 0600: the inventory embeds vaulted ansible_password
        # values and the ssh_config references the private-key paths. Match the 0600 the
        # key files themselves use, rather than the default (world-readable) umask.
        icfd = os.open(cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(icfd, "w", encoding="utf-8") as fh:
            fh.write(_build_ssh_config(req, key_path, vault_key_paths))
        ivfd = os.open(inv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(ivfd, "w", encoding="utf-8") as fh:
            fh.write(_build_inventory(req, cfg_path, vault_key_paths))

        # Open API port-forwards through the jump for any RouterOS-API hosts before the play.
        tunnels, tnotices = _open_api_tunnels(req, cfg_path)
        for n in tnotices:
            yield _ndjson({"line": n})

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
            # Find the build-time installed collections (community.routeros etc.) even
            # though HOME is the ephemeral workdir.
            "ANSIBLE_COLLECTIONS_PATH": "/usr/share/ansible/collections",
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
        for tp in tunnels:
            if tp.poll() is None:
                tp.terminate()
        shutil.rmtree(workdir, ignore_errors=True)


@app.post("/run")
def run(req: RunRequest):
    # NDJSON stream: {"line": "..."} per output line, then {"done": true, "rc": N}.
    return StreamingResponse(_stream_run(req), media_type="application/x-ndjson")
