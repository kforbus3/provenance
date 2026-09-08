"""Blackfriars — builder-runner sidecar.

A small internal HTTP service the backend calls to build OS images and update
bundles, manage the artefact library, and drive the PXE provisioning stack.

It exists so the Go backend never touches the Docker socket. Building an image
means running a privileged container that loop-mounts a disk and debootstraps
into it; a process that can ask for that can ask for anything, because a socket
that can start a privileged container with `/` bind-mounted is root on the host
with extra steps. Keeping it here means the blast radius of the build path is
one container that does nothing else, rather than the process that also holds
the SSH certificate authority.

What this is NOT is a second control plane. It has no users, no sessions, no
database and no opinion about who may do anything. Every request that reaches it
has already been authorised by the backend, which owns identity, host access,
RBAC and the audit log. Two copies of that would be one copy too many, and the
weaker copy would be the one that mattered.

    GET  /healthz                     liveness
    POST /build/{image,bundle,imager} start a build, return the job
    GET  /jobs, /jobs/{id}            job list, status and log
    DELETE /jobs, /jobs/{id}          forget finished builds
    POST /jobs/{id}/cancel            stop a build for real, container included
    GET  /images, /bundles, /disk     the artefact library
    DELETE /images/{name}, /bundles/{name}
    GET/PUT  /server/env              provisioning stack configuration
    POST /server/{up,down}            start and stop it
    GET  /server/{status,preflight,interfaces,clients}
    GET/PUT  /assignments             MAC -> hostname imaging assignments
    GET/PUT/DELETE /overlay...        files layered into a build
"""

from __future__ import annotations

import base64
import binascii
import hmac
import logging
import subprocess
import os
import stat

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

import orchestrator as orch
from jobs import jobs

app = FastAPI(title="blackfriars-builder-runner", version="1")

log = logging.getLogger("blackfriars-builder-runner")

# Shared-secret authentication, matching the ansible-runner sidecar: the backend
# sends X-Runner-Token, sourced from FLEET_BUILDER_RUNNER_TOKEN. An empty env var
# disables the check for local development and is logged loudly, because this
# service starts privileged containers and an unauthenticated one on a shared
# network is the whole host.
RUNNER_TOKEN = os.environ.get("FLEET_BUILDER_RUNNER_TOKEN", "")
if not RUNNER_TOKEN:
    log.warning(
        "FLEET_BUILDER_RUNNER_TOKEN is empty — this runner is UNAUTHENTICATED and it "
        "can start privileged containers. Set it anywhere but a laptop."
    )


def _require_token(x_runner_token: str = Header(default="")):
    if not RUNNER_TOKEN:
        return
    if not hmac.compare_digest(x_runner_token or "", RUNNER_TOKEN):
        raise HTTPException(status_code=401, detail="invalid or missing runner token")


guarded = [Depends(_require_token)]


class Body(BaseModel):
    """camelCase on the wire, snake_case in Python, like every other body the
    backend sends."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True,
                              extra="ignore")


@app.get("/healthz")
def healthz():
    return {"ok": True}


# --------------------------------- builds ------------------------------------

class ImageBuild(Body):
    distro: str = "debian"
    suite: str = "trixie"
    arch: str = "amd64"
    hostname: str = ""
    username: str = "debian"
    password: str = "debian"
    image_size: str = "auto"
    root_size: int = 3072
    compress: str = "zstd"
    profile: str = "minimal"
    desktop: str = ""
    secure_boot: str = "auto"
    packages: str = ""
    ssh_key: str = ""
    ssh_key_only: bool = False
    own_paths: str = ""
    state_model: str = "overlay"
    slot_private_upper: bool = False
    persist_paths: str = ""
    slot_private_paths: str = ""
    volatile_paths: str = ""
    reset_paths: str = ""
    keep_paths: str = ""
    run_script: str = ""
    encrypt: bool = False
    unlock: str = "keyfile"
    luks_passphrase: str = ""
    tang_url: str = ""
    # The output name, when the caller has already settled it. resolve_output_name
    # has always read this; the field was missing from the model, so extra="ignore"
    # dropped it and the name was re-chosen here regardless of what was sent.
    #
    # It matters for an encrypted build whose recovery passphrase was filed in a
    # secrets manager BEFORE the build started: the passphrase is filed under a
    # name, and if this end picks a different one, the key is filed against an
    # image that never existed.
    name: str = ""
    replace: bool = False


class BundleBuild(Body):
    image: str
    version: str = ""
    description: str = ""
    encrypted: bool = False
    luks_passphrase: str = ""


class ImagerBuild(Body):
    arch: str = "amd64"


def _one_at_a_time(kind: str) -> None:
    """Refuse a second build of the same kind.

    Two image builds at once share /output and the same builder image tag, and
    the failure is not a clean error — it is two loop devices and a half-written
    artefact. The builder has no lock of its own, so this is the lock.
    """
    running = jobs.running(kind)
    if running:
        raise HTTPException(status_code=409,
                            detail=f"{running.label} is already running (job {running.id})")


@app.post("/build/image", dependencies=guarded)
async def build_image(req: ImageBuild):
    _one_at_a_time("image")
    opts = req.model_dump()
    if not opts.get("hostname"):
        opts["hostname"] = f"{opts['distro']}-ab"
    if opts.get("run_script"):
        # Written into the output directory, which the builder already mounts,
        # rather than adding a mount for a single file.
        path = os.path.join(orch.settings.output_dir, ".build-script.sh")
        with open(path, "w") as f:
            f.write(opts["run_script"])
        os.chmod(path, 0o755)
    try:
        cmd, label, env = orch.build_image_cmd(opts)
    except (ValueError, orch.NameInUse) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    job = await jobs.start(type="image", label=label, cmd=cmd, now=orch.now(), env=env)
    return job.public()


@app.post("/build/bundle", dependencies=guarded)
async def build_bundle(req: BundleBuild):
    _one_at_a_time("bundle")
    if "/" in req.image or ".." in req.image:
        raise HTTPException(status_code=400, detail="invalid image name")
    if not os.path.isfile(os.path.join(orch.settings.output_dir, req.image)):
        raise HTTPException(status_code=404, detail=f"no such image: {req.image}")
    cmd, label, env = orch.build_bundle_cmd(
        req.image, req.version, req.description, req.encrypted)
    if req.encrypted:
        env = {**env, "LUKS_PASS": req.luks_passphrase}
    job = await jobs.start(type="bundle", label=label, cmd=cmd, now=orch.now(), env=env)
    return job.public()


@app.post("/build/imager", dependencies=guarded)
async def build_imager(req: ImagerBuild):
    _one_at_a_time("imager")
    cmd, label = orch.build_imager_cmd(req.arch)
    job = await jobs.start(type="imager", label=label, cmd=cmd, now=orch.now())
    return job.public()


@app.get("/jobs", dependencies=guarded)
def list_jobs():
    return {"jobs": jobs.list()}


@app.get("/jobs/{job_id}", dependencies=guarded)
def get_job(job_id: str, offset: int = 0):
    """Job status plus its log from `offset` lines in.

    Polled with an offset rather than streamed. The backend holds the browser's
    connection and can stream to it however it likes; between the backend and
    here, a poll that says where it got to is resumable across a restart of
    either side, which a stream is not.
    """
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="no such job")
    lines = jobs.log_text(job).split("\n") if jobs.log_text(job) else []
    return {**job.public(), "offset": offset,
            "log": lines[offset:], "total": len(lines)}


@app.delete("/jobs/{job_id}", dependencies=guarded)
def forget_job(job_id: str):
    """Drop one finished job and its log."""
    try:
        if not jobs.forget(job_id):
            raise HTTPException(status_code=404, detail="no such job")
    except ValueError as exc:
        # Still running: a 409, not a 500. The caller can act on it -- cancel
        # first -- which is a different thing from the server having broken.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"ok": True}


@app.delete("/jobs", dependencies=guarded)
def forget_finished_jobs():
    """Drop every job that is not running.

    The list is append-only otherwise, and a page showing every build ever run
    is a page nobody reads -- which matters because the one failure worth
    noticing ends up below thirty successes.
    """
    return {"removed": jobs.forget_finished()}


@app.post("/jobs/{job_id}/cancel", dependencies=guarded)
async def cancel_job(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="no such job")
    await jobs.cancel(job)
    return job.public()


# -------------------------------- artefacts ----------------------------------

@app.get("/images", dependencies=guarded)
def images():
    items, truncated = orch.list_images()
    return {"images": items, "truncated": truncated,
            "arches": orch.imager_arches(), "imagerFeatures": orch.imager_features()}


@app.delete("/images/{name}", dependencies=guarded)
def delete_image(name: str):
    try:
        orch.delete_image(name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no such image") from exc
    return {"ok": True}


@app.get("/bundles", dependencies=guarded)
def bundles():
    return {"bundles": orch.list_bundles()}


@app.delete("/bundles/{name}", dependencies=guarded)
def delete_bundle(name: str):
    try:
        return orch.delete_bundle(name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no such bundle") from exc


@app.get("/disk", dependencies=guarded)
def disk():
    return orch.disk_usage()


# ---------------------------- provisioning stack -----------------------------

@app.get("/server/status", dependencies=guarded)
def server_status():
    return orch.server_status()


@app.post("/server/up", dependencies=guarded)
def server_up():
    return {"output": orch.server_up()}


@app.post("/server/down", dependencies=guarded)
def server_down():
    return {"output": orch.server_down()}


@app.get("/server/env", dependencies=guarded)
def server_env():
    return {"env": orch.read_env(), "controlUrl": orch.control_url()}


class ServerEnv(Body):
    env: dict[str, str] = Field(default_factory=dict)


@app.put("/server/env", dependencies=guarded)
def set_server_env(req: ServerEnv):
    try:
        orch.write_env(req.env)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"env": orch.read_env()}


@app.get("/server/preflight", dependencies=guarded)
def server_preflight():
    return {"problems": orch.preflight() + orch.provisioning_preflight()}


@app.get("/server/interfaces", dependencies=guarded)
def server_interfaces():
    ifaces = orch.list_interfaces()
    return {"interfaces": ifaces, "suggestion": orch.suggest_provisioning_net(ifaces)}


@app.get("/server/clients", dependencies=guarded)
def server_clients():
    """Machines on the provisioning network right now.

    This is how you assign an image to a machine WITHOUT knowing its MAC in
    advance: PXE-boot it on the provisioning network, and it appears here with
    the MAC it announced. Reading it out of the rack, or out of a hypervisor's
    settings page, is the workflow this replaces.

    orchestrator.server_clients() has existed since the provisioning stack was
    brought across, and nothing called it -- no route here, none in the backend,
    nothing in the UI. The capability was present and unreachable, which from
    the outside is indistinguishable from missing.
    """
    return {"clients": orch.server_clients()}


# ------------------------------- assignments ---------------------------------

class Assignments(Body):
    items: list[dict] = Field(default_factory=list)


@app.get("/assignments", dependencies=guarded)
def assignments():
    return {"assignments": orch.read_assignments()}


@app.put("/assignments", dependencies=guarded)
def set_assignments(req: Assignments):
    try:
        return {"assignments": orch.write_assignments(req.items)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# --------------------------------- overlay -----------------------------------

class OverlayWrite(Body):
    path: str
    content: str = ""
    # Binary payloads arrive base64-encoded rather than as multipart.
    #
    # `content` is a str and always was, so anything that is not valid UTF-8 --
    # a certificate, a compiled tool, a firmware blob -- could not be written at
    # all, and the overlay is exactly where those belong. Base64 rather than
    # multipart keeps this endpoint, the Go proxy in front of it and the browser
    # all speaking JSON; the cost is 33% on the wire, which for overlay-sized
    # files is not the constraint.
    content_base64: str = ""
    mode: int | None = None


class OverlayMove(Body):
    src: str
    dst: str


class OverlayChmod(Body):
    path: str
    mode: int


@app.get("/overlay", dependencies=guarded)
def overlay():
    return {"files": orch.overlay_files(), "root": orch.overlay_writable()}


@app.get("/overlay/file", dependencies=guarded)
def overlay_read(path: str, max_bytes: int = 1 << 20):
    try:
        return orch.overlay_read(path, max_bytes)
    except orch.OverlayPathError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no such file") from exc


# An overlay file is copied into every image built afterwards, and the builder
# holds the whole thing in memory to do it. Large enough for a binary that
# belongs in an image, small enough that a mistaken upload is not a disk problem.
MAX_OVERLAY_BYTES = int(os.environ.get("MAX_OVERLAY_BYTES", str(16 << 20)))


@app.put("/overlay/file", dependencies=guarded)
def overlay_write(req: OverlayWrite):
    if req.content_base64:
        try:
            data = base64.b64decode(req.content_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise HTTPException(status_code=400,
                                detail="contentBase64 is not valid base64") from exc
    else:
        data = req.content.encode()
    if len(data) > MAX_OVERLAY_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"file is larger than the {MAX_OVERLAY_BYTES // (1024 * 1024)} MiB limit")
    try:
        return orch.overlay_write(req.path, data, req.mode)
    except orch.OverlayPathError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/overlay/download", dependencies=guarded)
def overlay_download(path: str):
    """The raw bytes, base64-encoded, for files the browser cannot edit.

    Same encoding as the write side so one JSON contract covers both directions,
    and so a file that came in as binary reads back byte-identical rather than
    through a decode that would have to guess at an encoding.
    """
    try:
        full, image_path = orch.overlay_resolve(path)
        if not os.path.isfile(full):
            raise FileNotFoundError(image_path)
        st = os.stat(full)
        if st.st_size > MAX_OVERLAY_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"file is larger than the {MAX_OVERLAY_BYTES // (1024 * 1024)} MiB limit")
        with open(full, "rb") as f:
            data = f.read()
    except orch.OverlayPathError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no such file") from exc
    return {
        "path": image_path,
        "size": st.st_size,
        "mode": format(stat.S_IMODE(st.st_mode), "04o"),
        "contentBase64": base64.b64encode(data).decode(),
    }


@app.delete("/overlay/file", dependencies=guarded)
def overlay_delete(path: str):
    try:
        return orch.overlay_delete(path)
    except orch.OverlayPathError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no such file") from exc


@app.post("/overlay/move", dependencies=guarded)
def overlay_move(req: OverlayMove):
    try:
        return orch.overlay_move(req.src, req.dst)
    except orch.OverlayPathError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no such file") from exc


@app.post("/overlay/chmod", dependencies=guarded)
def overlay_chmod(req: OverlayChmod):
    try:
        return orch.overlay_chmod(req.path, req.mode)
    except orch.OverlayPathError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no such file") from exc


# --------------------------- imaging key backup ---------------------------
# Metadata only. There is deliberately no route that returns key material: a
# signing key fetchable over HTTP is one whose custody is whoever holds a session
# cookie, and this one cannot be regenerated.


@app.get("/keys/status", dependencies=guarded)
def keys_status():
    return orch.key_backup_status()


@app.post("/keys/backup", dependencies=guarded)
def keys_backup():
    try:
        return orch.key_backup_create()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/keys/inspect", dependencies=guarded)
def keys_inspect(name: str):
    try:
        return orch.key_backup_inspect(name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
