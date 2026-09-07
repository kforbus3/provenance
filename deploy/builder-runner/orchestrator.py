"""Drives the builder / imager / provisioning server via the Docker socket."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
from datetime import datetime, timezone

from config import settings
from jobs import JOB_TOKEN, container_name

PROJ = settings.project_dir       # path to the repo inside this container

# The image that registers qemu interpreters for cross-architecture builds. Read
# from the same environment variable the socket proxy reads, so the image this
# tries to run and the image that proxy will permit cannot drift apart — they are
# the same string or the build is refused with a message about the wrong one.
BINFMT_IMAGE = os.environ.get("BINFMT_IMAGE", "tonistiigi/binfmt").strip() or "tonistiigi/binfmt"

# Where the host's binfmt_misc registrations are bind-mounted read-only. See the
# builder-runner service in deploy/compose/docker-compose.yml: this container's own
# /proc/sys/fs/binfmt_misc is empty regardless of what the host has registered.
BINFMT_VIEW = os.environ.get("BINFMT_VIEW", "/host/binfmt_misc").rstrip("/")

# Every build container gets a sane open-file limit.
#
# Docker hands a container whatever RLIMIT_NOFILE the daemon inherited. On a host
# whose dockerd unit has LimitNOFILE=infinity that is 1073741816, and rpm closes
# every descriptor from 3 up to the soft limit between fork() and exec() of a
# scriptlet -- a billion close() calls at 100% CPU, per scriptlet. A build looks
# hung forever, always at glibc, the first RPM in the bootstrap with a scriptlet.
#
# build-image.sh caps this itself so it is right however it is invoked; this sets
# it at the container so everything else in there gets it too, and so the cap
# survives a build step that does not go through that script.
NOFILE_ULIMIT = "--ulimit nofile=65536:65536 "


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------- host path discovery ---------------------------
# The builder/imager/server containers are started through the Docker socket, so
# their bind-mount sources must be paths the DAEMON can see (host paths), while
# `docker build` contexts are read by the CLI in here (container paths). Getting
# the host path from a hand-set env var is the single easiest thing to get wrong
# — a stale value silently mounts an empty directory and every build dies with
# `unable to prepare context: path "/project/builder" not found`. So ask the
# daemon what it actually mounted at PROJECT_DIR instead.

# The daemon bind-mounts /etc/hosts, /etc/hostname and /etc/resolv.conf out of
# /var/lib/docker/containers/<id>/, so mountinfo identifies us even when the
# container hostname has been overridden.
_SELF_ID_RE = re.compile(r"/containers/([0-9a-f]{12,})/")


def _self_container_id() -> str:
    try:
        with open("/proc/self/mountinfo") as f:
            m = _SELF_ID_RE.search(f.read())
            if m:
                return m.group(1)
    except OSError:
        pass
    return socket.gethostname().strip()


_detected: str = ""


def host_project_dir() -> str:
    """Host-side path of the repo: explicit override, else our own bind mount.

    Only successful lookups are cached — a transient Docker socket hiccup at
    startup shouldn't pin an empty answer for the life of the process.
    """
    global _detected
    if settings.host_project_dir:
        return settings.host_project_dir.rstrip("/")
    if _detected:
        return _detected
    try:
        proc = subprocess.run(
            ["docker", "inspect", "--format", "{{json .Mounts}}", _self_container_id()],
            capture_output=True, text=True, timeout=15,
        )
        for mount in json.loads(proc.stdout or "[]"):
            if mount.get("Destination") == PROJ and mount.get("Source"):
                _detected = str(mount["Source"]).rstrip("/")
                return _detected
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return ""


def host_output_dir() -> str:
    return f"{host_project_dir()}/output"


def host_overlay_dir() -> str:
    """Where your own files live, host-side, for the builder to bind-mount."""
    return f"{host_project_dir()}/overlay.d"


def overlay_root() -> str:
    """Your files, as seen from inside this container.

    Read and written through this path rather than the host one: they are the
    same directory, and only this one exists from in here.
    """
    return os.path.join(PROJ, "overlay.d")


# The README is this directory's documentation, not payload -- the builder's own
# listing skips it, so a file of that name would be silently left out of every
# image. Refused up front instead.
OVERLAY_RESERVED = ("README.md",)


class OverlayPathError(ValueError):
    """A path that is not somewhere a file may be written. Message is user-facing."""


def overlay_resolve(path: str) -> tuple[str, str]:
    """Map an image path (`/etc/hosts`) to a file under overlay.d.

    Returns (absolute path in this container, normalised image path).

    Everything about this function is containment. The path arrives from the
    browser and ends up at `open()`, so `..` segments, an absolute path that
    escapes on join, and a symlink pointing out of the tree all have to be dead
    before then -- the last one is why the parent is resolved with realpath
    rather than trusting a textual check.
    """
    root = os.path.realpath(overlay_root())
    rel = str(path or "").strip().replace("\\", "/").lstrip("/")
    if not rel:
        raise OverlayPathError("a path is required, e.g. /etc/hosts")
    if any(part in ("..", ".") for part in rel.split("/")):
        raise OverlayPathError("the path may not contain '.' or '..' segments")
    if rel.endswith("/"):
        raise OverlayPathError("the path must name a file, not a directory")
    if len(rel) > 1024:
        raise OverlayPathError("the path is too long")
    if rel in OVERLAY_RESERVED:
        raise OverlayPathError(
            f"/{rel} is this directory's own documentation and is never copied "
            "into an image. Choose another path.")
    full = os.path.join(root, rel)
    # The file itself need not exist yet; its parent chain must not lead out of
    # the tree. realpath resolves symlinks, so a symlinked directory pointing at
    # / is caught here rather than at open().
    parent = os.path.realpath(os.path.dirname(full))
    if parent != root and not parent.startswith(root + os.sep):
        raise OverlayPathError("that path resolves outside overlay.d")
    return full, "/" + rel


def overlay_files() -> list[dict]:
    """What the next build will copy into the image, so the UI can show it."""
    root = overlay_root()
    out: list[dict] = []
    if not os.path.isdir(root):
        return out
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            if rel in OVERLAY_RESERVED:
                continue
            try:
                st = os.stat(full)
            except OSError:
                continue
            out.append({
                "path": "/" + rel.replace(os.sep, "/"),
                "size": st.st_size,
                # cp -a preserves the mode, so what is set here is what lands on
                # the machine -- which makes it part of the file, not a detail.
                "mode": format(stat.S_IMODE(st.st_mode), "04o"),
                "executable": bool(st.st_mode & 0o111),
                "modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                                    .isoformat(timespec="seconds"),
            })
    out.sort(key=lambda r: r["path"])
    return out


def overlay_writable() -> str:
    """Empty if files can be managed from here, else why not.

    The repo is bind-mounted, and a read-only or root-owned mount is the one
    failure that makes every write fail identically. Checked once, up front,
    so the answer is a sentence rather than an errno per attempt.
    """
    root = overlay_root()
    try:
        os.makedirs(root, exist_ok=True)
    except OSError as exc:
        return (f"overlay.d cannot be created ({exc.strerror}). The repository is "
                f"mounted into this container at {PROJ}; it must be writable to "
                f"manage files from here.")
    if not os.access(root, os.W_OK | os.X_OK):
        return (f"overlay.d is not writable by this container (uid {os.getuid()}). "
                f"Check the permissions of the repository directory on the host.")
    return ""


def overlay_write(path: str, data: bytes, mode: int | None = None) -> dict:
    """Create or replace one file, and any directories leading to it."""
    full, image_path = overlay_resolve(path)
    if os.path.isdir(full):
        raise OverlayPathError(f"{image_path} is a directory")
    os.makedirs(os.path.dirname(full), exist_ok=True)
    # Written alongside and renamed: a half-written file here is a half-written
    # file in the next image, and the rename makes the swap atomic.
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(full), prefix=".overlay-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode if mode is not None else 0o644)
        os.replace(tmp, full)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return {"path": image_path, "size": len(data),
            "mode": format(mode if mode is not None else 0o644, "04o")}


def overlay_read(path: str, max_bytes: int) -> dict:
    """One file's contents, for editing in the browser."""
    full, image_path = overlay_resolve(path)
    if not os.path.isfile(full):
        raise FileNotFoundError(image_path)
    st = os.stat(full)
    with open(full, "rb") as f:
        raw = f.read(max_bytes + 1)
    info = {"path": image_path, "size": st.st_size,
            "mode": format(stat.S_IMODE(st.st_mode), "04o"),
            "executable": bool(st.st_mode & 0o111)}
    if st.st_size > max_bytes:
        return {**info, "editable": False,
                "reason": f"larger than {max_bytes // 1024} KiB"}
    try:
        return {**info, "editable": True, "content": raw.decode()}
    except UnicodeDecodeError:
        # A binary file is perfectly valid payload -- it just cannot be typed
        # into a textarea. It stays in the image either way.
        return {**info, "editable": False, "reason": "not text"}


def overlay_chmod(path: str, mode: int) -> dict:
    full, image_path = overlay_resolve(path)
    if not os.path.isfile(full):
        raise FileNotFoundError(image_path)
    os.chmod(full, mode)
    return {"path": image_path, "mode": format(mode, "04o")}


def overlay_move(src: str, dst: str) -> dict:
    full_src, src_path = overlay_resolve(src)
    full_dst, dst_path = overlay_resolve(dst)
    if not os.path.isfile(full_src):
        raise FileNotFoundError(src_path)
    if os.path.exists(full_dst):
        raise OverlayPathError(f"{dst_path} already exists")
    os.makedirs(os.path.dirname(full_dst), exist_ok=True)
    os.replace(full_src, full_dst)
    _overlay_prune(os.path.dirname(full_src))
    return {"path": dst_path}


def overlay_delete(path: str) -> dict:
    full, image_path = overlay_resolve(path)
    if not os.path.isfile(full):
        raise FileNotFoundError(image_path)
    os.remove(full)
    _overlay_prune(os.path.dirname(full))
    return {"path": image_path}


def _overlay_prune(dirpath: str) -> None:
    """Remove directories left empty by a delete or move, up to the root.

    Without this, deleting overlay.d/etc/netplan/10-corp.yaml leaves an empty
    etc/netplan behind, and `cp -a` would then create an empty /etc/netplan in
    every image -- which for netplan specifically means a machine that comes up
    with no network configuration at all.
    """
    root = os.path.realpath(overlay_root())
    current = os.path.realpath(dirpath)
    while current != root and current.startswith(root + os.sep):
        try:
            os.rmdir(current)
        except OSError:
            return
        current = os.path.dirname(current)


def _self_image() -> str:
    """This container's image, reused for throwaway host-namespace helpers."""
    try:
        proc = subprocess.run(
            ["docker", "inspect", "--format", "{{.Config.Image}}", _self_container_id()],
            capture_output=True, text=True, timeout=15,
        )
        # The fallback is this stack's own runner image. It used to name the
        # Flipside web UI, which does not exist here at all — so on the one path
        # that reaches it, the helper `docker run` was guaranteed to fail.
        return proc.stdout.strip() or "blackfriars-builder-runner"
    except (OSError, subprocess.SubprocessError):
        return "blackfriars-builder-runner"


# --------------------------- host interfaces ---------------------------
# Docker's own bridges and virtual links: no physical machine ever PXE-boots on
# one, so listing them only clutters the choice.
_VIRTUAL_IF_RE = re.compile(r"^(docker\d+|br-[0-9a-f]{12}|veth|virbr\d+-nic|tun\d+|tap\d+)")

# `ip -d link` reports linkinfo.info_kind for every synthetic device and omits it
# for real NICs, which is a far better filter than guessing from names. A kernel
# leaves a pile of always-present tunnel stubs lying around (gre0, sit0, tunl0,
# erspan0, ip6tnl0, …) and none of them can carry a PXE client. These kinds are
# the ones that legitimately can, alongside genuine hardware.
_USABLE_IF_KINDS = {"vlan", "bond", "bridge", "macvlan", "team"}


def list_interfaces() -> list[dict]:
    """The host's IPv4 interfaces, so the UI can offer them instead of asking
    the operator to know their own topology.

    We have the Docker socket but not the host's network namespace, so read them
    through a throwaway container that does have it. `default` marks the NIC
    carrying the default route — that is the main LAN, and the one you do *not*
    want a standalone DHCP server on.
    """
    def _run(*cmd: str) -> str:
        proc = subprocess.run(
            ["docker", "run", "--rm", "--network", "host", _self_image(), *cmd],
            capture_output=True, text=True, timeout=60,
        )
        return proc.stdout
    try:
        # `ip -4 addr` omits an interface entirely when it has no IPv4 address,
        # so links are enumerated separately. The provisioning NIC is exactly
        # the one likely to have no address — it faces an isolated segment where
        # this server is supposed to BE the DHCP server — and leaving it out of
        # the list made it impossible to choose.
        links = json.loads(_run("ip", "-d", "-j", "link") or "[]")
        addrs = json.loads(_run("ip", "-j", "-4", "addr") or "[]")
        routes = json.loads(_run("ip", "-j", "-4", "route") or "[]")
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
    default_if = next((r.get("dev") for r in routes if r.get("dst") == "default"), None)

    by_name: dict[str, dict] = {}
    for entry in addrs:
        for addr in entry.get("addr_info", []):
            if addr.get("family") != "inet" or not addr.get("local"):
                continue
            # /31 and /32 can't host a subnet of PXE clients.
            if addr.get("prefixlen", 32) >= 31:
                continue
            by_name.setdefault(entry.get("ifname", ""), addr)

    out: list[dict] = []
    for link in links:
        name = link.get("ifname")
        if not name or name == "lo" or _VIRTUAL_IF_RE.match(name):
            continue
        if link.get("link_type") != "ether":
            continue
        kind = (link.get("linkinfo") or {}).get("info_kind")
        if kind and kind not in _USABLE_IF_KINDS:
            continue
        addr = by_name.get(name)
        item = {
            "name": name,
            "ip": "",
            "prefixlen": 0,
            "network": "",
            "netmask": "",
            "mac": link.get("address", ""),
            "up": link.get("operstate") not in ("DOWN",),
            "carrier": link.get("operstate") == "UP",
            "default": name == default_if,
        }
        if addr:
            try:
                net = ipaddress.ip_network(f"{addr['local']}/{addr['prefixlen']}", strict=False)
                item.update(ip=addr["local"], prefixlen=addr["prefixlen"],
                            network=str(net.network_address), netmask=str(net.netmask))
            except ValueError:
                pass
        out.append(item)
    # Addressless NICs first: on a turnkey setup that is the provisioning one.
    return sorted(out, key=lambda i: (bool(i["ip"]), i["default"], i["name"]))


# Candidate subnets for an unconfigured provisioning NIC, in preference order.
# Deliberately uncommon so they are unlikely to collide with the LAN the server
# is already on.
_CANDIDATE_NETS = ["192.168.50.0/24", "10.42.0.0/24", "172.30.0.0/24", "192.168.150.0/24"]


def suggest_provisioning_net(interfaces: list[dict] | None = None) -> dict:
    """A static address for a NIC that has none, avoiding subnets already in use."""
    interfaces = interfaces if interfaces is not None else list_interfaces()
    taken = []
    for i in interfaces:
        if i.get("ip") and i.get("prefixlen"):
            try:
                taken.append(ipaddress.ip_network(f"{i['ip']}/{i['prefixlen']}", strict=False))
            except ValueError:
                pass
    for cand in _CANDIDATE_NETS:
        net = ipaddress.ip_network(cand)
        if any(net.overlaps(t) for t in taken):
            continue
        # The range comes from suggest_dhcp_range rather than being computed
        # again here. It used to be a second copy that hardcoded +100/+200,
        # which is right for a /24 and produces addresses outside the subnet
        # for anything smaller -- a lease range dnsmasq refuses to start with.
        # Two implementations of one piece of arithmetic drift exactly once,
        # and only one of them was the one with the size check.
        out = {
            "SERVER_IP": str(net.network_address + 1),
            "prefixlen": net.prefixlen,
        }
        out.update(suggest_dhcp_range(str(net.network_address + 1), net.prefixlen))
        return out
    return {}


def suggest_dhcp_range(ip: str, prefixlen: int) -> dict:
    """A lease range inside an interface's own subnet, avoiding .0/.1 and the
    broadcast address, so standalone DHCP needs no manual arithmetic."""
    try:
        net = ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False)
    except ValueError:
        return {}
    size = net.num_addresses
    if size < 8:
        return {}
    lo, hi = min(100, size // 4), min(200, size - 2)
    if lo >= hi:
        lo, hi = 2, size - 2
    return {
        "DHCP_RANGE_START": str(net.network_address + lo),
        "DHCP_RANGE_END": str(net.network_address + hi),
        "DHCP_NETMASK": str(net.netmask),
        "PROXY_SUBNET": str(net.network_address),
    }


def docker_socket_path() -> str:
    """The unix socket this runner talks to the daemon over, from DOCKER_HOST.

    Returns "" for a non-unix DOCKER_HOST (tcp://, ssh://), where there is no
    local path to test and the connection's health is not ours to assert.
    """
    host = os.environ.get("DOCKER_HOST", "").strip()
    if not host:
        return "/var/run/docker.sock"
    if host.startswith("unix://"):
        return host[len("unix://"):] or "/var/run/docker.sock"
    return ""


def preflight() -> list[str]:
    """Problems that would make builds fail, in plain language. Empty = ready."""
    problems: list[str] = []
    if not os.path.isfile(os.path.join(PROJ, "builder", "Dockerfile")):
        problems.append(
            f"The repository is not mounted at {PROJ} in the builder-runner "
            f"container ({PROJ}/builder/Dockerfile is missing). Check the "
            f"`../..:{PROJ}` volume on the builder-runner service in "
            "deploy/compose/docker-compose.yml — if HOST_PROJECT_DIR is set in .env "
            "it must be the absolute host path of this checkout. Unset it to have "
            "the path detected automatically, then bring the stack up again."
        )
    if not host_project_dir():
        problems.append(
            "Could not determine the repository's path on the Docker host, so the "
            "builder container would get an unusable output mount. Set "
            "HOST_PROJECT_DIR in .env to this checkout's absolute host path."
        )
    # Check the socket this runner ACTUALLY uses, not a hard-coded path.
    #
    # It normally talks to the dockerproxy at /shared/docker.sock and never holds
    # the raw socket at all, so testing /var/run/docker.sock reported a problem
    # that was permanently present and permanently untrue — on a correctly
    # deployed stack, which is the worst kind. A preflight that always complains
    # is one people learn to scroll past, and the real entries here are the ones
    # that stop a machine being imaged.
    sock = docker_socket_path()
    if sock and not os.access(sock, os.W_OK):
        problems.append(
            f"The Docker socket is not available at {sock}. The builder runner needs "
            "it to start build containers; check that the `imaging` profile is up "
            "(the dockerproxy service provides it) in deploy/compose/docker-compose.yml."
        )
    # Images are several GiB each and nothing removes them, so an output
    # directory that has been in use for a while is the most likely reason a
    # build dies -- and it dies late, after debootstrap, with a bare "No space
    # left on device" that says nothing about which disk. Say it up front.
    try:
        du = disk_usage()
        free_gb = du["free"] / (1024 ** 3)
        if free_gb < LOW_DISK_GB:
            artifacts_gb = du["artifacts"] / (1024 ** 3)
            problems.append(
                f"Only {free_gb:.1f} GiB free where images are written, and a build "
                f"needs roughly {LOW_DISK_GB:.0f} GiB. Built images account for "
                f"{artifacts_gb:.1f} GiB — delete ones you no longer need on the "
                "Images page."
            )
    except OSError:
        pass
    return problems


# A build writes an 8 GiB image and unpacks a distribution alongside it, and
# Docker's own layers land on the same volume. Below this, builds usually fail.
LOW_DISK_GB = 12.0


# --------------------------- builds ---------------------------
# Build profiles, and the desktop environments each distro can actually
# provide. This is the same mapping build-image.sh enforces; validating against
# it here means an impossible combination is a 400 with the available choices
# in it, rather than a die() twenty minutes into a build the operator has
# already walked away from. The values are the metapackage each choice
# installs — the UI never needs them, but the docs and tests read them from
# here so there is one copy of the mapping on this side, not two.
PROFILES = ("minimal", "server", "desktop")
# auto: use the distribution's signed shim and GRUB when the suite has them.
# on:   fail the build if it cannot, so a fleet that requires Secure Boot is
#       never handed an image that quietly does not support it.
# off:  the old unsigned layout.
SECURE_BOOT_MODES = ("auto", "on", "off")
DESKTOP_ENVS: dict[str, dict[str, str]] = {
    "debian": {
        "gnome": "task-gnome-desktop",
        "kde": "task-kde-desktop",
        "xfce": "task-xfce-desktop",
        "mate": "task-mate-desktop",
        "cinnamon": "task-cinnamon-desktop",
        "lxqt": "task-lxqt-desktop",
    },
    "ubuntu": {
        "gnome": "ubuntu-desktop-minimal",
        "kde": "kde-plasma-desktop",
        "xfce": "xubuntu-core",
        "mate": "ubuntu-mate-core",
        "lxqt": "lubuntu-desktop",
    },
}
# Mirrors build-image.sh's desktop floor: a desktop tree is several GiB
# installed, and the builder raises the slot to this. Validating image_size
# against the raised number keeps the "image too small" check honest.
MIN_ROOT_DESKTOP_MIB = 10240


class NameInUse(Exception):
    """An explicitly requested image name already exists in the library."""

    def __init__(self, name: str, suggestion: str):
        self.name = name
        self.suggestion = suggestion
        super().__init__(f"{name} already exists")


def _image_name_taken(base: str) -> bool:
    """True if any build product for this base name is already in the library.

    Every extension, not just the one this build would write: an uncompressed
    build must not quietly land beside the .zst of the same name, because the
    two are different images with one identity and the Updates page would offer
    a choice between them by name alone.
    """
    out = settings.output_dir
    return any(os.path.exists(os.path.join(out, base + ext))
               for ext in (".img", ".img.zst", ".img.gz"))


def image_output_name(opts: dict) -> str:
    """The image file a build with these options will produce, before compression.

    Shared with the caller because a passphrase has to be filed under this name
    in the secrets manager *before* the build that produces it starts, and the
    two must not be able to disagree about what it is. resolve_output_name()
    settles the question once per build and writes the answer back into opts, so
    this only ever reads it.
    """
    resolved = str(opts.get("name") or "").strip()
    if resolved:
        return resolved if resolved.endswith(".img") else resolved + ".img"
    return (f"{opts.get('distro', 'debian')}-{opts.get('suite', 'trixie')}-"
            f"{opts.get('arch', 'amd64')}-ab.img")


def resolve_output_name(opts: dict) -> str:
    """Decide what this build will be called, and make sure it takes nothing.

    The name used to be distro-suite-arch alone, so a second Debian 13 amd64
    build silently replaced the first. That is not only a lost file: the image
    a deployed machine was made from is what a bundle for it must be built from,
    and the LUKS passphrase in the secrets manager is filed *under this name* --
    so rebuilding overwrote the recovery key of a machine already in the field,
    which nothing would have revealed until someone needed it.

    No name given: a free one is chosen, so the default can never overwrite.
    A name given: it is honoured, and refused if taken unless `replace` says so.
    """
    explicit = str(opts.get("name") or "").strip()
    if explicit:
        base = os.path.basename(explicit)
        for ext in (".img.zst", ".img.gz", ".img"):
            if base.endswith(ext):
                base = base[: -len(ext)]
                break
        base = re.sub(r"[^A-Za-z0-9._-]", "-", base).strip("-.") or "image"
        if _image_name_taken(base) and not opts.get("replace"):
            raise NameInUse(base + ".img", _free_name(base))
        opts["name"] = base + ".img"
        return opts["name"]

    base = (f"{opts.get('distro', 'debian')}-{opts.get('suite', 'trixie')}-"
            f"{opts.get('arch', 'amd64')}-ab")
    # Same sanitization as the explicit-name branch: distro/suite are not
    # otherwise constrained, and this string ends up in a shell command line.
    base = re.sub(r"[^A-Za-z0-9._-]", "-", base).strip("-.") or "image"
    opts["name"] = _free_name(base)
    return opts["name"]


def _free_name(base: str) -> str:
    """`base.img`, or base-2, base-3 … — the first that is not in the library."""
    if not _image_name_taken(base):
        return base + ".img"
    for n in range(2, 1000):
        if not _image_name_taken(f"{base}-{n}"):
            return f"{base}-{n}.img"
    raise RuntimeError(f"could not find a free name based on {base}")


def build_image_cmd(opts: dict) -> tuple[list[str], str, dict]:
    """Return (command, label, env) to build an A/B image.

    Secrets (login password, LUKS passphrase) travel via the environment —
    build-image.sh reads PASSWORD / LUKS_PASS — so they never appear on a
    command line visible in `ps` or in persisted job metadata.
    """
    distro = opts.get("distro", "debian")
    suite = opts.get("suite", "trixie")
    # The builder container runs as the architecture it is building, so
    # debootstrap and every chroot step execute natively rather than under
    # emulation.
    arch = opts.get("arch", "amd64")
    platform = f"linux/{arch}"
    args = [
        "--distro", distro,
        "--suite", suite,
        "--hostname", opts.get("hostname", f"{distro}-ab"),
        "--username", opts.get("username", "debian"),
        "--image-size", ("auto" if opts.get("image_size") in ("auto", 0, "0", "", None)
                         else str(opts["image_size"])),
        "--root-size", str(opts.get("root_size", 3072)),
        "--compress", opts.get("compress", "zstd"),
        "--arch", arch,
    ]
    env = {"PASSWORD": opts.get("password", "debian")}
    # The default profile adds no arguments at all, so a build request that
    # never heard of profiles produces exactly the command it always has.
    profile = str(opts.get("profile") or "minimal")
    if profile != "minimal":
        args += ["--profile", profile]
        if profile == "desktop" and opts.get("desktop"):
            args += ["--desktop", str(opts["desktop"])]
    # `auto` is the builder's default and adds no argument, so a build request
    # that never heard of Secure Boot produces exactly the command it always did.
    secure_boot = str(opts.get("secure_boot") or "auto")
    if secure_boot not in SECURE_BOOT_MODES:
        raise ValueError(f"secure_boot must be one of {', '.join(SECURE_BOOT_MODES)}")
    if secure_boot != "auto":
        args += ["--secure-boot", secure_boot]
    if opts.get("packages"):
        args += ["--packages", opts["packages"]]
    if opts.get("ssh_key"):
        args += ["--ssh-authorized-key", opts["ssh_key"]]
    if opts.get("ssh_key_only"):
        args += ["--ssh-key-only"]
    # Paths the image owns: cleared from a machine's persistent overlay on the
    # update that delivers them, so the image's copy is the one it reads.
    for path in str(opts.get("own_paths", "")).split():
        if path.startswith("/"):
            args += ["--own-path", path]
    # How the image lays out writable state, and which paths are carved out of
    # the default "one overlay shared by both slots". build-image.sh validates
    # all of this and refuses the build rather than shipping a manifest that
    # would only be discovered as wrong at a boot prompt, so nothing here needs
    # to second-guess it beyond dropping obvious junk.
    if opts.get("state_model") and opts["state_model"] != "overlay":
        args += ["--state-model", opts["state_model"]]
    # Each slot gets its own overlay upper layer rather than sharing one. Not a
    # default, and not something an update can turn on or off — a machine
    # records the layout it was imaged with and refuses a change at boot.
    if opts.get("slot_private_upper"):
        args += ["--slot-private-upper"]
    for field, flag in (
        ("persist_paths", "--persist"),
        ("slot_private_paths", "--slot-private"),
        ("volatile_paths", "--volatile"),
        ("reset_paths", "--reset-on-update"),
        ("keep_paths", "--keep-path"),
    ):
        for path in str(opts.get(field, "")).split():
            if path.startswith("/"):
                args += [flag, path]
    if opts.get("run_script"):
        # Written into the output directory, which is already mounted, rather
        # than adding another mount for a single file.
        args += ["--run-script", "/output/.build-script.sh"]
    if opts.get("encrypt"):
        args += ["--encrypt", "--unlock", opts.get("unlock", "keyfile")]
        env["LUKS_PASS"] = opts.get("luks_passphrase", "")
        if opts.get("unlock") == "tang" and opts.get("tang_url"):
            args += ["--tang-url", opts["tang_url"]]
    # The image name carries the architecture, so an amd64 and an arm64 build of
    # the same suite do not overwrite one another in /output.
    out_name = image_output_name(opts)
    # `-e VAR` (no value) makes the docker CLI forward VAR from its own env.
    # An RPM image needs an RPM builder: `dnf --installroot` is the bootstrap, and
    # there is no dnf in the Debian one. A TAG rather than a second image name, so
    # the socket proxy's allowlist -- which already matches debian-ab-builder with
    # any tag -- needs no widening for an image this repository builds itself.
    dockerfile, fam = builder_image_for(opts.get("distro", "debian"))
    builder_tag = f"debian-ab-builder:{fam}-{arch}"
    script = (
        _binfmt_prelude(arch)
        + _docker_build("builder", builder_tag, platform, dockerfile=dockerfile)
        + "echo '--- starting image build ---'\n"
        + f"docker run --rm --name {container_name(JOB_TOKEN)} " + NOFILE_ULIMIT
        + f"--privileged --platform={platform} -v {_q(host_output_dir())}:/output "
        # Read-only: a build must not be able to change the files it is
        # being customized with.
        + f"-v {_q(host_overlay_dir())}:/overlay.d:ro "
        + "-e PASSWORD -e LUKS_PASS "
        + f"{builder_tag} {' '.join(_q(a) for a in args)} --output {_q('/output/' + out_name)}\n"
    )
    label = f"Build {distro}/{suite} {arch} image ({opts.get('hostname', f'{distro}-ab')})"
    return ["bash", "-c", script], label, env


def build_imager_cmd(arch: str = "amd64") -> tuple[list[str], str]:
    """Build the netboot imager for one architecture.

    The imager is a kernel the target machine executes, so an amd64 imager
    cannot boot an arm64 machine however it is served -- building an arm64
    image is only half of supporting arm64, and this is the other half.
    """
    if arch not in ("amd64", "arm64"):
        raise ValueError(f"unsupported imager arch '{arch}'")
    platform = f"linux/{arch}"
    kernel_pkg = f"linux-image-{arch}"
    script = (
        _binfmt_prelude(arch)
        + _docker_build("imager", f"debian-ab-imager:{arch}", platform,
                        build_args=f"--build-arg KERNEL_PKG={kernel_pkg}")
        + f"echo '--- building {arch} imager ---'\n"
        + f"docker run --rm --name {container_name(JOB_TOKEN)} " + NOFILE_ULIMIT
        + f"--platform={platform} -e ARCH={arch} "
        + f"-v {_q(host_output_dir())}:/output debian-ab-imager:{arch}\n"
    )
    return ["bash", "-c", script], f"Build netboot imager ({arch})"


def _binfmt_prelude(arch: str) -> str:
    """Shell that makes cross-architecture builds possible on this host.

    Building an arm64 image or imager on an amd64 host runs arm64 binaries under
    qemu, which the kernel only does once binfmt_misc has an interpreter
    registered. Docker does not do that on its own, so without this the build
    dies deep inside debootstrap with "Exec format error" -- or, for the imager,
    at the first RUN in its Dockerfile.

    The registration is global, idempotent, and survives until reboot, so doing
    it before every cross build costs a few seconds and removes a manual step
    the UI would otherwise have to explain. `uname -m` is the host kernel's,
    even from inside this container, so it is a sound comparison.
    """
    want = {"amd64": "x86_64", "arm64": "aarch64"}.get(arch, "")
    if not want:
        return ""
    # Two ways the interpreter can already be there, and both are checked before
    # anything is run: the host may have it registered permanently (Debian's
    # qemu-user-static does this, and it survives reboots, which the container
    # method does not), or a previous build may have registered it this boot.
    #
    # If it is missing, this ABORTS rather than warning. It used to warn and carry
    # on, and the build then died forty lines later inside a Dockerfile RUN with a
    # bare "exec format error" -- a message about the wrong thing entirely, at a
    # point that gave no hint the cause was a missing binfmt handler noticed
    # minutes earlier. Failing here costs the same build and says why.
    handler = {"amd64": "qemu-x86_64", "arm64": "qemu-aarch64"}[arch]
    return (
        f'if [ "$(uname -m)" != "{want}" ]; then\n'
        # The HOST's registrations, bind-mounted read-only. This container's own
        # /proc/sys/fs/binfmt_misc is empty whatever the host has registered, so
        # reading that would refuse to build on a host where qemu-user-static had
        # already made the build work. The unmounted path is still checked so a
        # deployment predating that mount is no worse off than before.
        f'  if [ -e {BINFMT_VIEW}/{handler} ] || [ -e /proc/sys/fs/binfmt_misc/{handler} ]; then\n'
        f"    echo '--- {handler} already registered on this host ---'\n"
        "  else\n"
        f"    echo '--- registering {handler} so {arch} can be built on this host ---'\n"
        f"    docker run --privileged --rm {_q(BINFMT_IMAGE)} --install {arch} || {{\n"
        f"      echo 'ERROR: {arch} cannot be built on this host: no {handler} binfmt handler'\n"
        "      echo '       is registered, and registering one was refused.'\n"
        "      echo ''\n"
        "      echo '       Either register the interpreters on the host once, which persists'\n"
        "      echo '       across reboots and needs no exception in the Docker socket proxy:'\n"
        "      echo ''\n"
        "      echo '           sudo apt install qemu-user-static binfmt-support'\n"
        "      echo ''\n"
        f"      echo '       or set BINFMT_ALLOW=1 on the dockerproxy service to let each build'\n"
        f"      echo '       register it with the third-party {BINFMT_IMAGE} image.'\n"
        "      exit 1\n"
        "    }\n"
        "  fi\n"
        "fi\n"
    )


# Which builder image a distribution needs. The bootstrap step is the reason:
# `dnf --installroot` needs a working dnf and the rpm it drives, and Debian's
# packaged dnf pointed at a RHEL release is the fragile path -- one that fails
# after twenty minutes of partitioning and encryption have already happened.
#
# Kept in step with build-image.sh's own FAMILY resolution by having exactly one
# list of RPM distributions, here and there. They disagree only if somebody adds
# a distribution to one and not the other, which is what the test asserts.
RPM_DISTROS = ("almalinux", "rocky", "rhel")


def builder_image_for(distro: str) -> tuple[str, str]:
    """(dockerfile, image tag prefix) for a distribution's builder.

    The tag rather than a new image NAME is deliberate: the socket proxy's
    allowlist matches `debian-ab-builder` with any tag, and both builders are
    images this repository builds from its own Dockerfiles -- the same trust
    class. A new name would mean widening that allowlist for something it already
    covers.
    """
    if str(distro).strip().lower() in RPM_DISTROS:
        return "Dockerfile.rpm", "rpm"
    return "Dockerfile", "deb"


def _docker_build(subdir: str, tag: str, platform: str = "linux/amd64",
                  build_args: str = "", dockerfile: str = "") -> str:
    """Shell prelude that builds one of the repo's images.

    The build CONTEXT is a path inside this container (the docker CLI tars it up
    here), unlike the run-time bind mounts above, which the daemon resolves on
    the host. `--progress=plain` keeps BuildKit's output line-oriented so it
    streams to the browser as it happens rather than arriving in one lump at the
    end — this step can take minutes and a silent log looks like a hang.
    """
    return (
        "set -eo pipefail\n"
        f"echo '--- building {subdir} image ---'\n"
        f"docker build --progress=plain --platform={platform} "
        f"{'-f ' + _q(PROJ + '/' + subdir + '/' + dockerfile) + ' ' if dockerfile else ''}"
        f"{build_args + ' ' if build_args else ''}-t {tag} {_q(PROJ + '/' + subdir)}\n"
    )


def _q(s: str) -> str:
    return "'" + str(s).replace("'", "'\\''") + "'"


# --------------------------- images ---------------------------
def _sidecars(path: str) -> dict:
    """Read the builder's .sha256 / .json sidecars for an image, if present."""
    extra: dict = {}
    try:
        with open(path + ".sha256") as f:
            extra["sha256"] = f.read().split()[0]
    except (OSError, IndexError):
        pass
    try:
        with open(path + ".json") as f:
            extra["meta"] = json.load(f)
    except (OSError, ValueError):
        pass
    return extra


def list_images() -> tuple[list[dict], bool]:
    out = settings.output_dir
    items: list[dict] = []
    if os.path.isdir(out):
        for fn in sorted(os.listdir(out)):
            full = os.path.join(out, fn)
            if os.path.isfile(full) and re.search(r"\.img(\.zst|\.gz)?$", fn):
                st = os.stat(full)
                items.append({
                    "name": fn,
                    "size": st.st_size,
                    "created": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
                    **_sidecars(full),
                })
    imager_ready = imager_arches()["amd64"]
    return items, imager_ready


def build_bundle_cmd(image: str, version: str = "", description: str = "",
                     encrypted: bool = False) -> tuple[list[str], str, dict]:
    """Package a built image into a signed RAUC update bundle.

    Runs the builder container with its make-bundle entrypoint. Privileged for
    the same reason the image build is: it attaches the image to a loop device
    and mounts the root slot out of it.
    """
    args = ["--image", f"/output/{image}"]
    if version:
        args += ["--version", version]
    if description:
        args += ["--description", description]
    # The passphrase travels in the environment, never on a command line where
    # it would show up in `ps` and in the job's stored metadata.
    env = {"LUKS_PASS": ""} if not encrypted else {}
    # The DEB builder, whatever family the image inside the bundle came from.
    # Bundling opens the image, repacks the root slot and signs it with rauc --
    # and rauc is a package here and is NOT packaged for the RPM family at all
    # (it is built from source inside an RPM image, which is a different thing
    # from having it on the builder). Nothing in this step is distribution
    # specific, so the builder that has the tool is the one that runs it.
    bundler_tag = "debian-ab-builder:deb-amd64"
    script = (
        _docker_build("builder", bundler_tag, dockerfile="Dockerfile")
        + "echo '--- building update bundle ---'\n"
        + f"docker run --rm --name {container_name(JOB_TOKEN)} " + NOFILE_ULIMIT
        + "--privileged --platform=linux/amd64 "
        + f"-v {_q(host_output_dir())}:/output "
        + ("-e LUKS_PASS " if encrypted else "")
        + f"--entrypoint /build/make-bundle.sh {bundler_tag} "
        + " ".join(_q(a) for a in args) + "\n"
    )
    return ["bash", "-c", script], f"Build update bundle from {image}", env


def bundles_dir() -> str:
    return os.path.join(settings.output_dir, "bundles")


def _latest_pointer() -> str:
    """The bundle `ab-update` with no arguments installs, or "" if unset.

    make-bundle.sh writes this file; nothing else did until deletion existed.
    Directory listing is off on the HTTP server, so this pointer is the only
    way an unattended machine finds a bundle at all.
    """
    try:
        with open(os.path.join(bundles_dir(), "latest")) as f:
            return f.read().strip()
    except OSError:
        return ""


def list_bundles() -> list[dict]:
    """Update bundles available to install, newest first."""
    d = bundles_dir()
    items: list[dict] = []
    if not os.path.isdir(d):
        return items
    latest = _latest_pointer()
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".raucb"):
            continue
        full = os.path.join(d, fn)
        st = os.stat(full)
        row = {
            "name": fn,
            "size": st.st_size,
            "created": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
            # Which row a machine running plain `ab-update` will install. Worth
            # showing rather than leaving to be inferred from the dates: it is
            # the newest *build*, and deleting it changes what the whole fleet
            # gets, so it has to be visible before someone deletes something.
            "is_latest": fn == latest,
        }
        try:
            with open(full + ".json") as f:
                row.update(json.load(f))
        except (OSError, ValueError):
            pass
        items.append(row)
    items.sort(key=lambda r: r["created"], reverse=True)
    return items


def delete_bundle(name: str) -> dict:
    """Remove a bundle, its sidecars, and repair the `latest` pointer.

    The pointer is the whole reason this is not a three-line `os.remove`.
    `ab-update` with no arguments fetches `<server>/bundles/latest` and installs
    whatever it names; deleting that bundle without touching the file leaves
    every unattended machine in the fleet fetching a 404 -- which ab-update
    reports as a download failure or "is not a RAUC bundle", neither of which
    points at a deleted file on the server.

    So the pointer is moved to the newest bundle that is left, and removed
    entirely when the last one goes. Returns what happened, because "the fleet
    now updates to something else" is not a detail to leave unsaid.
    """
    if "/" in name or ".." in name or not name.endswith(".raucb"):
        raise ValueError("invalid name")
    d = bundles_dir()
    path = os.path.join(d, name)
    if not os.path.isfile(path):
        raise FileNotFoundError(name)

    was_latest = _latest_pointer() == name
    os.remove(path)
    for sidecar in (path + ".json", path + ".sha256"):
        if os.path.isfile(sidecar):
            os.remove(sidecar)

    new_latest = None
    if was_latest:
        remaining = list_bundles()          # newest first, and the file is gone
        pointer = os.path.join(d, "latest")
        if remaining:
            new_latest = remaining[0]["name"]
            # Written whole and renamed into place: a machine can be reading
            # this file at the moment it changes, and a half-written pointer is
            # a fleet fetching a truncated filename.
            tmp = pointer + ".tmp"
            with open(tmp, "w") as f:
                f.write(new_latest + "\n")
            os.replace(tmp, pointer)
        elif os.path.isfile(pointer):
            # Nothing left to point at. Removing it makes `ab-update` say "No
            # 'latest' pointer published", which is true and actionable; leaving
            # it would name a bundle that is not there.
            os.remove(pointer)

    return {"deleted": name, "was_latest": was_latest, "new_latest": new_latest}


def imager_arches() -> dict[str, bool]:
    """Which architectures have a netboot imager built.

    amd64 lives at the top of the imager directory, where it always has, so a
    server that predates arm64 support keeps working untouched; other
    architectures get a subdirectory. A machine picks its own at boot time from
    iPXE's ${buildarch}, so both can be present and neither interferes.
    """
    out = settings.output_dir
    def built(d: str) -> bool:
        return os.path.isfile(os.path.join(d, "vmlinuz")) and \
               os.path.isfile(os.path.join(d, "initramfs.img"))
    base = os.path.join(out, "imager")
    return {"amd64": built(base), "arm64": built(os.path.join(base, "arm64"))}


def imager_features() -> list[str]:
    """Which imager.* parameters the built imager understands.

    The imager is a build artifact -- `init` is baked into the initramfs -- so a
    repo that has grown a new parameter does nothing until someone rebuilds it.
    An older imager ignores parameters it does not know, exactly as it should,
    so the machine images perfectly and quietly does not do the new thing. That
    is indistinguishable from the web UI having dropped the field, which is how
    it was reported.

    Empty for an imager built before this stamp existed; callers must treat that
    as "unknown", not as "supports nothing", or every older imager would draw a
    warning about a feature it may well have.
    """
    for sub in ("", "arm64"):
        path = os.path.join(settings.output_dir, "imager", sub, "build.json")
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        feats = data.get("features")
        if isinstance(feats, list):
            return [str(x) for x in feats]
    return []


def delete_image(name: str) -> None:
    if "/" in name or ".." in name:
        raise ValueError("invalid name")
    path = os.path.join(settings.output_dir, name)
    if not re.search(r"\.img(\.zst|\.gz)?$", name) or not os.path.isfile(path):
        raise FileNotFoundError(name)
    os.remove(path)
    for sidecar in (path + ".sha256", path + ".json"):
        if os.path.isfile(sidecar):
            os.remove(sidecar)


def disk_usage() -> dict:
    """Free space on the output volume and how much the artifacts occupy."""
    out = settings.output_dir
    used = 0
    for root, _dirs, files in os.walk(out):
        for fn in files:
            try:
                used += os.stat(os.path.join(root, fn)).st_size
            except OSError:
                pass
    total, _used, free = shutil.disk_usage(out) if os.path.isdir(out) else (0, 0, 0)
    return {"artifacts": used, "free": free, "total": total}


# --------------------------- provisioning server ---------------------------
ENV_PATH = os.path.join(settings.project_dir, "server", ".env")
ENV_EXAMPLE = os.path.join(settings.project_dir, "server", ".env.example")
ENV_KEYS = [
    "SERVER_IP", "SERVER_PREFIXLEN", "IMAGE_FILE", "ACTION", "MODE", "INTERFACE", "PROXY_SUBNET",
    "DHCP_RANGE_START", "DHCP_RANGE_END", "DHCP_NETMASK", "DHCP_ROUTER", "DHCP_DNS", "LEASE_TIME",
    "UNASSIGNED", "RETRY_SECONDS",
    # The fleet's side of the network, as opposed to the imaging side above.
    # These were hand-edited settings, preserved-but-invisible, back when the
    # only thing they affected was where bundles were published. They decide
    # whether the control plane is reachable at all now, and a setting the whole
    # fleet depends on should not be one you have to know to look for.
    "UPDATE_IP", "UPDATE_PORT", "CONTROL_URL",
]


def control_url() -> str:
    """The base URL machines should reach this control plane on.

    Two places can say so, and they are ranked rather than merged. CONTROL_URL
    in the web UI's own environment wins, because that is how someone running
    the UI behind a reverse proxy states the public name; otherwise it comes
    from the provisioning server's .env, which is where the Provisioning page
    writes it and where the iPXE renderer reads it. One value, one meaning, and
    no way for the address handed to a machine to disagree with the address the
    UI reports having handed it.
    """
    if settings.control_url:
        return settings.control_url.rstrip("/")
    try:
        return (read_env().get("CONTROL_URL") or "").rstrip("/")
    except OSError:
        return ""


def provisioning_preflight(cfg: dict | None = None) -> list[str]:
    """What still stands between the current config and a working PXE boot.

    Checked before the server starts so a misconfiguration surfaces in the UI
    rather than as a machine that PXE-boots into nothing.
    """
    cfg = cfg if cfg is not None else read_env()
    problems: list[str] = []

    _images, imager_ready = list_images()
    if not imager_ready:
        problems.append(
            "The netboot imager has not been built. Build it on the Build Image "
            "page — machines download its kernel and initramfs to boot."
        )
    image = cfg.get("IMAGE_FILE", "")
    if not image:
        problems.append("No image selected to deploy.")
    elif not os.path.isfile(os.path.join(settings.output_dir, image)):
        problems.append(f"The selected image '{image}' is not in the image library.")

    if not cfg.get("INTERFACE"):
        problems.append(
            "No provisioning interface selected. One is required: it confines "
            "DHCP and TFTP to that network so this server cannot answer, or "
            "interfere with, anything on your other networks."
        )
    if not cfg.get("SERVER_IP"):
        problems.append("No server IP — pick a provisioning interface to fill it in.")

    if cfg.get("MODE", "dhcp") == "dhcp":
        if not (cfg.get("DHCP_RANGE_START") and cfg.get("DHCP_RANGE_END")):
            problems.append("Standalone DHCP needs a lease range.")
    elif not cfg.get("PROXY_SUBNET"):
        problems.append("Proxy mode needs the subnet of the imaging network.")
    return problems


def read_env() -> dict:
    """Saved config, or turnkey defaults when nothing has been saved yet.

    Deliberately not seeded from .env.example: its illustrative 192.168.1.x
    values look like real settings in the UI, and a wrong-but-plausible server
    IP is worse than an empty field the operator is prompted to fill.
    """
    cfg: dict[str, str] = {}
    if os.path.isfile(ENV_PATH):
        for line in open(ENV_PATH):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    else:
        cfg = default_env()
    return {k: cfg.get(k, "") for k in ENV_KEYS}


def write_env(cfg: dict) -> None:
    # Everything in the file that this page does not manage is carried across.
    # The file is rewritten from ENV_KEYS alone, so anything hand-added -- the
    # UPDATE_IP that publishes /bundles/ on the LAN, for one -- used to vanish
    # the first time somebody saved the Provisioning page, taking OTA with it
    # and giving no sign that it had happened.
    preserved: dict[str, str] = {}
    current: dict[str, str] = {}
    if os.path.isfile(ENV_PATH):
        for line in open(ENV_PATH):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                if k.strip() in ENV_KEYS:
                    current[k.strip()] = v.strip()
                else:
                    preserved[k.strip()] = v.strip()

    # A key the caller did not mention keeps whatever it had; a key sent empty
    # is being cleared. The distinction matters because UPDATE_IP and friends
    # only just became managed keys: an older UI, or any caller that posts the
    # subset of fields it knows about, would otherwise silently delete the
    # setting that makes updates reachable -- which is exactly the failure this
    # function already carries a comment about having caused once.
    merged = {k: (cfg[k] if k in cfg else current.get(k, "")) for k in ENV_KEYS}

    os.makedirs(os.path.dirname(ENV_PATH), exist_ok=True)
    with open(ENV_PATH, "w") as f:
        f.write("# Managed by the web UI\n")
        for k in ENV_KEYS:
            if merged.get(k):
                f.write(f"{k}={merged[k]}\n")
        if preserved:
            f.write("\n# Set by hand; left alone by the web UI.\n")
            for k, v in preserved.items():
                f.write(f"{k}={v}\n")
    # Per-machine scripts embed the server IP and the default action, so they
    # go stale the moment either changes. Rewrite them from the stored
    # assignments rather than leaving machines pointed at the old address.
    try:
        existing = read_assignments()
        if existing:
            write_assignments(existing)
    except (OSError, ValueError):
        pass


# --------------------------- per-machine targeting ---------------------------
# A machine's iPXE dispatcher asks for /hosts/<mac>.ipxe before falling back to
# the default image (see server/http/boot.ipxe.tmpl). Assignments are stored as
# JSON — the source of truth — and the .ipxe files are generated from it, so a
# change of server IP or image regenerates them all consistently.
_MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)


def hosts_dir() -> str:
    return os.path.join(settings.output_dir, "hosts")


def _assign_path() -> str:
    return os.path.join(hosts_dir(), "assignments.json")


def normalize_mac(mac: str) -> str:
    """Canonical colon-separated lowercase, or '' if not a MAC."""
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if _MAC_RE.match(mac) else ""


def _mac_filename(mac: str) -> str:
    """iPXE's ${mac:hexhyp} form — hyphens, lowercase."""
    return mac.replace(":", "-") + ".ipxe"


# RFC 1123: labels of letters, digits and hyphens, not starting or ending with
# one. Dots are allowed so an FQDN can be assigned, and each label is checked.
_HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def normalize_hostname(name: str) -> str:
    """Validate an assigned hostname, or raise ValueError saying why.

    Deliberately strict rather than sanitising. This value is interpolated into
    a kernel command line and then becomes the machine's identity: quietly
    turning "web 01" into "web-01" would mean the name in the UI is not the name
    on the machine, and the first person to notice would be whoever could not
    resolve it.
    """
    h = (name or "").strip()
    if not h:
        return ""
    if len(h) > 253:
        raise ValueError(f"hostname '{h[:32]}…' is longer than 253 characters")
    for label in h.split("."):
        if not _HOSTNAME_LABEL.match(label):
            raise ValueError(
                f"'{h}' is not a valid hostname: each part must be 1-63 letters, "
                "digits or hyphens, and cannot start or end with a hyphen")
    return h


def read_assignments() -> list[dict]:
    try:
        with open(_assign_path()) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    out = []
    for a in data if isinstance(data, list) else []:
        mac = normalize_mac(a.get("mac", ""))
        if mac and a.get("image"):
            out.append({"mac": mac, "image": a["image"],
                        "action": a.get("action") or "", "name": a.get("name", ""),
                        "hostname": a.get("hostname", "")})
    return sorted(out, key=lambda a: a["mac"])


def write_assignments(items: list[dict]) -> list[dict]:
    """Validate, persist, and regenerate the per-machine iPXE scripts."""
    cfg = read_env()
    known = {i["name"] for i in list_images()[0]}
    clean: list[dict] = []
    seen: set[str] = set()
    for a in items or []:
        mac = normalize_mac(a.get("mac", ""))
        if not mac:
            raise ValueError(f"'{a.get('mac', '')}' is not a MAC address")
        if mac in seen:
            raise ValueError(f"{mac} is assigned twice")
        image = (a.get("image") or "").strip()
        if not image:
            raise ValueError(f"{mac} has no image selected")
        if image not in known:
            raise ValueError(f"{mac}: image '{image}' is not in the library")
        seen.add(mac)
        try:
            hostname = normalize_hostname(a.get("hostname", ""))
        except ValueError as exc:
            raise ValueError(f"{mac}: {exc}")
        clean.append({"mac": mac, "image": image,
                      "action": (a.get("action") or "").strip(),
                      "name": (a.get("name") or "").strip(),
                      "hostname": hostname})

    # Two machines answering to one name is a fault worth catching here rather
    # than by whoever eventually cannot tell which of them they are logged into.
    _hosts: dict[str, str] = {}
    for a in clean:
        if not a["hostname"]:
            continue
        first = _hosts.get(a["hostname"].lower())
        if first:
            raise ValueError(
                f"hostname '{a['hostname']}' is assigned to both {first} and {a['mac']}")
        _hosts[a["hostname"].lower()] = a["mac"]

    os.makedirs(hosts_dir(), exist_ok=True)
    tmp = _assign_path() + ".tmp"
    with open(tmp, "w") as f:
        json.dump(clean, f, indent=2)
    os.replace(tmp, _assign_path())

    # Regenerate scripts, dropping any that no longer have an assignment.
    wanted = {_mac_filename(a["mac"]) for a in clean}
    for fn in os.listdir(hosts_dir()):
        if fn.endswith(".ipxe") and fn not in wanted:
            os.remove(os.path.join(hosts_dir(), fn))
    for a in clean:
        _write_host_script(a, cfg)
    return clean


def _write_host_script(a: dict, cfg: dict) -> None:
    ip = cfg.get("SERVER_IP", "")
    action = a["action"] or cfg.get("ACTION") or "reboot"
    label = a["name"] or a["mac"]
    # Passed on the kernel command line, which is the only channel the imager
    # has. Validated as a hostname on the way in, so it cannot contain a space
    # and split into a second parameter. Omitted entirely when unset, so the
    # machine keeps whatever the image was built with.
    host_arg = f" imager.hostname={a['hostname']}" if a.get("hostname") else ""
    # Where this machine will check in from once it is no longer on this
    # network. Everything else on this command line points at SERVER_IP, which
    # is the provisioning segment — the one address the machine is guaranteed to
    # lose. Omitted when unset rather than defaulted to SERVER_IP: the agent
    # already falls back to that on its own, and writing it explicitly would
    # make a deliberate setting indistinguishable from never having set one.
    control_arg = ""
    if cfg.get("CONTROL_URL"):
        control_arg = f" imager.control={cfg['CONTROL_URL'].rstrip('/')}"
    script = f"""#!ipxe
# Generated by the web UI for {a['mac']} — do not edit; edit the assignment.
echo
echo ====================================================
echo   A/B Network Imager
echo   Machine: {label}
echo   Hostname: {a['hostname'] or '(from the image)'}
echo   Image  : {a['image']}
echo   Action : {action} after imaging
echo ====================================================
echo Booting the imager... this machine's disk will be re-imaged.
echo

# The imager is a kernel the machine executes, so it has to match the machine.
# ${{buildarch}} is iPXE's own variable, expanded at boot on the machine itself --
# this file is written once and served to whatever asks for it. Without the
# branch an arm64 machine with a specific assignment is handed the amd64 imager,
# while the same machine falling through to the default script gets the right
# one, which is a confusing way to find out.
iseq ${{buildarch}} arm64 && set imgdir imager/arm64 || set imgdir imager

# || goto noimager on both: a missing or unreachable imager should say so and
# reboot, not abort the script and drop the machine at an iPXE prompt.
kernel http://{ip}/${{imgdir}}/vmlinuz imager.url=http://{ip}/images/{a['image']} imager.action={action} imager.compress=auto{host_arg}{control_arg} console=tty0 console=ttyS0,115200 || goto noimager
initrd http://{ip}/${{imgdir}}/initramfs.img || goto noimager
boot

:noimager
echo
echo No imager available for this machine's architecture (${{buildarch}}).
echo Build it on the Build Image page, or: ./imager/run.sh --arch arm64
echo
sleep 30
reboot
"""
    with open(os.path.join(hosts_dir(), _mac_filename(a["mac"])), "w") as f:
        f.write(script)


def _compose(*args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "HOST_OUTPUT_DIR": host_output_dir()}
    return subprocess.run(
        ["docker", "compose", "-f", os.path.join(settings.project_dir, "server", "docker-compose.yml"), *args],
        capture_output=True, text=True, env=env, timeout=120,
    )


def server_status() -> dict:
    # compose refuses to run at all without the env_file, and its raw complaint
    # ("stat /project/server/.env: no such file...") reads like a fault rather
    # than the ordinary "you haven't configured this yet" that it is.
    if not os.path.isfile(ENV_PATH):
        return {"running": False,
                "detail": "Not configured yet — save the settings below to create server/.env."}
    proc = _compose("ps", "--format", "json")
    running = "dnsmasq" in proc.stdout and "running" in proc.stdout.lower()
    return {"running": running, "detail": proc.stdout.strip() or proc.stderr.strip()}


def server_up() -> str:
    return (_compose("up", "-d", "--build").stderr or "started").strip()


def default_env() -> dict:
    """Turnkey starting point: standalone DHCP on its own segment.

    Proxy mode depends on the LAN's existing DHCP server; standalone owns the
    provisioning network outright, which is what makes it self-contained.
    """
    return {"MODE": "dhcp", "ACTION": "reboot", "LEASE_TIME": "1h",
            "UNASSIGNED": "image", "RETRY_SECONDS": "30"}


def server_down() -> str:
    return (_compose("down").stderr or "stopped").strip()


def _docker_logs(container: str, tail: int, since: str = "") -> list[str]:
    cmd = ["docker", "logs", "--tail", str(tail)]
    if since:
        cmd += ["--since", since]
    cmd.append(container)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except Exception:
        return []
    return (proc.stdout + proc.stderr).splitlines()


# How far back to look for machines on the provisioning network. A machine that
# has not been heard from within this window has finished, been powered off, or
# rebooted into the image it just received -- in every case it is no longer
# imaging, and leaving it on screen turns the list into a boot history that only
# ever grows. Deriving this from the log window rather than a timestamp in the
# line is deliberate: dnsmasq's own prefix carries no year, so anything parsed
# out of it breaks across a new year and around a restart.
CLIENT_WINDOW = "15m"


# nginx access-log line: IP ... "GET /path HTTP/1.1" status bytes
_NGINX_RE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]*\] "GET (/\S*) HTTP/[^"]*" (\d{3}) (\d+)')


def server_clients() -> list[dict]:
    """Machines active on the provisioning network right now.

    Merges dnsmasq (PXE/DHCP/TFTP) and nginx (imager + image downloads) logs.
    Only the last CLIENT_WINDOW is considered, and a machine that has finished
    downloading its image is dropped: it is about to reboot into that image and
    is no longer a machine waiting to be provisioned. Live progress for a
    machine mid-write belongs to the imaging registry, which the machine itself
    reports into -- this list answers the narrower question of who is on the
    network and needs an image assigned.
    """
    seen: dict[str, dict] = {}
    for line in _docker_logs("debian-ab-dnsmasq", 400, since=CLIENT_WINDOW):
        mac = re.search(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", line)
        if not mac:
            continue
        m = mac.group(0)
        entry = seen.setdefault(m, {"mac": m, "ip": "", "event": "", "last": ""})
        ip = re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", line)
        if ip:
            entry["ip"] = ip.group(0)
        if "DHCPACK" in line:
            entry["event"] = "got boot info"
        elif "tftp" in line.lower() and "sent" in line.lower():
            entry["event"] = "downloading bootloader"
        elif "BOOTP" in line or "PXE" in line:
            entry["event"] = "PXE booting"
        entry["last"] = line[:19]

    # nginx completes a log line only when the transfer finishes, so a logged
    # 200 for the image file means the machine has fully downloaded (and
    # therefore written) the image.
    by_ip: dict[str, str] = {}
    for line in _docker_logs("debian-ab-http", 300, since=CLIENT_WINDOW):
        m = _NGINX_RE.match(line)
        if not m:
            continue
        ip, path, status, _nbytes = m.groups()
        if status not in ("200", "206"):
            continue
        if path.startswith("/imager/"):
            by_ip.setdefault(ip, "booting imager")
        elif path.startswith("/images/") and re.search(r"\.img(\.zst|\.gz)?$", path):
            by_ip[ip] = "imaged"
    for entry in seen.values():
        if entry["ip"] in by_ip:
            entry["event"] = by_ip.pop(entry["ip"])
    # HTTP clients dnsmasq never saw (e.g. proxyDHCP handled by the router).
    for ip, event in by_ip.items():
        seen[ip] = {"mac": "—", "ip": ip, "event": event, "last": ""}
    return [e for e in seen.values() if e["event"] != "imaged"]


# --------------------------- imaging key backup ---------------------------
# What the database backup cannot hold: the RAUC signing key, the MAC->hostname
# assignments, and the provisioning stack's configuration.
#
# The key never leaves the host. These calls report on it and produce an archive
# BESIDE it; nothing here returns key material, and there is deliberately no
# download route. A signing key that can be fetched over HTTP is a signing key
# whose custody is whoever holds a session cookie -- and losing this one means no
# deployed machine can ever be updated again, while leaking it means anyone can
# sign an update every one of them installs without complaint.

KEY_BACKUP_SCRIPT = os.path.join(PROJ, "scripts", "imaging", "imaging-keys-backup.sh")

# Mirrors the script's own PATHS. Kept in step by the test that reads both.
KEY_BACKUP_PATHS = (
    ("output/rauc-keys", "the update signing key and its certificate — irreplaceable"),
    ("output/hosts/assignments.json", "which MAC gets which hostname when it is imaged"),
    ("server/.env", "the provisioning stack's network configuration"),
)

# Where archives are written and looked for. Inside the project, because that is
# what the runner has mounted, and beside the thing being backed up rather than
# somewhere a later cleanup would not think to look.
def key_backup_dir() -> str:
    return os.path.join(PROJ, "output", "key-backups")


def key_backup_status() -> dict:
    """What would be backed up, whether it is there, and what backups exist."""
    items = []
    for rel, why in KEY_BACKUP_PATHS:
        full = os.path.join(PROJ, rel)
        present = os.path.exists(full)
        size = 0
        if present:
            if os.path.isdir(full):
                for dirpath, _d, files in os.walk(full):
                    for fn in files:
                        try:
                            size += os.path.getsize(os.path.join(dirpath, fn))
                        except OSError:
                            pass
            else:
                try:
                    size = os.path.getsize(full)
                except OSError:
                    pass
        items.append({"path": rel, "why": why, "present": present, "size": size})

    backups = []
    d = key_backup_dir()
    if os.path.isdir(d):
        for fn in sorted(os.listdir(d), reverse=True):
            if not fn.endswith(".tar.gz"):
                continue
            full = os.path.join(d, fn)
            try:
                st = os.stat(full)
            except OSError:
                continue
            backups.append({
                "name": fn,
                "size": st.st_size,
                "created": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                                   .isoformat(timespec="seconds"),
            })

    # The signing key is the one that cannot be regenerated, so its absence from
    # every backup is the fact worth surfacing rather than a count of files.
    have_key = any(i["path"] == "output/rauc-keys" and i["present"] for i in items)
    return {
        "items": items,
        "backups": backups,
        "dir": d,
        "haveSigningKey": have_key,
        "scriptPresent": os.path.isfile(KEY_BACKUP_SCRIPT),
    }


def _safe_backup_name(name: str) -> str:
    """A backup filename, refusing anything that is not one.

    It arrives from a browser and is joined to a directory, so a separator or a
    `..` in it is the whole attack.
    """
    clean = os.path.basename(str(name or "").strip())
    if clean != str(name or "").strip() or not clean.endswith(".tar.gz"):
        raise ValueError("not a backup archive name")
    return clean


def key_backup_create() -> dict:
    """Run the script, leaving the archive on the host. Returns its metadata."""
    if not os.path.isfile(KEY_BACKUP_SCRIPT):
        raise FileNotFoundError("the backup script is not in this checkout")
    d = key_backup_dir()
    os.makedirs(d, mode=0o700, exist_ok=True)
    name = f"imaging-keys-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.tar.gz"
    dest = os.path.join(d, name)
    proc = subprocess.run(["bash", KEY_BACKUP_SCRIPT, "backup", dest],
                          capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "backup failed").strip()[:500])
    st = os.stat(dest)
    h = hashlib.sha256()
    with open(dest, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return {
        "name": name,
        "size": st.st_size,
        "sha256": h.hexdigest(),
        "path": dest,
        # The script says so on stdout when the key is absent; carried through
        # because "a backup was written" and "a backup with the key in it was
        # written" are different facts and only one of them is reassuring.
        "output": (proc.stdout or "").strip()[:4000],
    }


def key_backup_inspect(name: str) -> dict:
    """The names inside an archive. Names only -- never contents."""
    clean = _safe_backup_name(name)
    full = os.path.join(key_backup_dir(), clean)
    if not os.path.isfile(full):
        raise FileNotFoundError("no such backup")
    proc = subprocess.run(["tar", "-tzf", full], capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError("not a readable archive")
    entries = [l for l in proc.stdout.splitlines() if l.strip()]
    return {
        "name": clean,
        "entries": entries,
        "containsSigningKey": any("rauc-keys/key.pem" in e for e in entries),
    }
