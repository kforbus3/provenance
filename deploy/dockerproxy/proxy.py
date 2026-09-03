#!/usr/bin/env python3
"""A Docker API proxy that only passes the calls Flipside actually makes.

The web UI drives builds by starting sibling containers through the Docker
socket, and the socket was bind-mounted into it raw. That is the whole Docker
API: `exec` into any container on the host, read any container's environment,
create one with `/` bind-mounted, pull and run any image from anywhere. A web
application with a remote-code-execution bug and a raw Docker socket is a web
application with host root, and every security review says so.

This sits in front of it and passes an allowlist: the container lifecycle calls
the orchestrator makes, image builds, and nothing else. Requests are logged, so
what the UI asks the daemon to do is finally visible.

Every request is checked, including the second one on a kept-alive connection --
see Handler, where that is the whole design.

**What this does not fix, stated plainly.** The image builder must run
privileged -- it attaches loop devices, mounts filesystems and runs debootstrap
-- and a privileged container can reach the host kernel however it likes. So
anyone able to *start a build* can still reach host root by construction, and no
proxy can change that. What the allowlist removes is everything else: reaching
into unrelated containers on the same host, running an arbitrary image,
mounting host paths outside the project, and enumerating whatever else the host
is running. Treat the operator role as host-root-equivalent regardless, and give
Flipside its own host. See docs/DEPLOYMENT.md.

No dependencies: a security control whose supply chain is larger than the thing
it protects is a poor trade, and the whole of it should be readable in one
sitting.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import socketserver
import sys
import threading

UPSTREAM = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")
LISTEN = os.environ.get("PROXY_SOCKET", "/shared/docker.sock")
# Host path the web UI is allowed to bind-mount from. Everything it legitimately
# mounts is inside the project directory or its output; anything else is a
# request to read or write part of the host, which is not something a build
# needs.
PROJECT_DIR = os.environ.get("HOST_PROJECT_DIR", "")
# Which container to ask when HOST_PROJECT_DIR is not set (see project_root).
WEBUI_CONTAINER = os.environ.get("WEBUI_CONTAINER", "debian-ab-webui")
# Image names a container may be created from. The builder and imager tags are
# built locally by the UI itself; the compose stack's images are built from the
# repo too. A container created from anything else is not a build.
IMAGE_ALLOW = re.compile(os.environ.get(
    "IMAGE_ALLOW",
    r"^(debian-ab-(builder|imager|webui|dnsmasq|http|dockerproxy))(:[\w.\-]+)?$"))
# Only these images may be created with elevated privileges: the builder and the
# imager genuinely need loop devices and mounts. Nothing else does, and a
# privileged container is a host-root container.
PRIVILEGED_ALLOW = re.compile(r"^debian-ab-(builder|imager)(:[\w.\-]+)?$")

log = logging.getLogger("dockerproxy")

# (method, path pattern). Anchored, and matched against the path with its query
# string stripped -- a rule that matched a prefix would let `/containers/json`
# through as `/containers/json/../../whatever`, and the Docker API is happy to
# normalise that upstream.
#
# Deliberately absent, and each for a reason:
#   /containers/{id}/exec, /exec/*      running a command in any container
#   /images/create                      pulling an arbitrary image from anywhere
#   /commit, /push                      exfiltrating a container as an image
#   /volumes, /networks (write)         reshaping what other containers can see
#   /secrets, /configs, /swarm, /nodes  cluster credentials
#   /plugins                            code loaded into the daemon itself
RULES: list[tuple[str, re.Pattern[str]]] = [
    ("GET",    re.compile(r"^/(v[\d.]+/)?_ping$")),
    ("HEAD",   re.compile(r"^/(v[\d.]+/)?_ping$")),
    ("GET",    re.compile(r"^/(v[\d.]+/)?version$")),
    ("GET",    re.compile(r"^/(v[\d.]+/)?info$")),

    # Containers: create, run, watch, clean up. `json` is the list the compose
    # plugin needs to find the stack's own containers.
    ("GET",    re.compile(r"^/(v[\d.]+/)?containers/json$")),
    ("POST",   re.compile(r"^/(v[\d.]+/)?containers/create$")),
    ("GET",    re.compile(r"^/(v[\d.]+/)?containers/[\w.\-]+/json$")),
    ("POST",   re.compile(r"^/(v[\d.]+/)?containers/[\w.\-]+/start$")),
    ("POST",   re.compile(r"^/(v[\d.]+/)?containers/[\w.\-]+/stop$")),
    ("POST",   re.compile(r"^/(v[\d.]+/)?containers/[\w.\-]+/kill$")),
    ("POST",   re.compile(r"^/(v[\d.]+/)?containers/[\w.\-]+/wait$")),
    ("POST",   re.compile(r"^/(v[\d.]+/)?containers/[\w.\-]+/restart$")),
    ("GET",    re.compile(r"^/(v[\d.]+/)?containers/[\w.\-]+/logs$")),
    # Attach, which is how `docker run` in the foreground streams a container's
    # output -- and every build this project runs is a foreground `docker run`
    # whose output becomes the job log. Denying it does not harden anything
    # useful; it just means builds produce no output.
    #
    # Not the same thing as exec, which stays denied. Attach connects to a
    # container's existing stdio; exec starts a new process of the caller's
    # choosing inside any container on the host. The second is the escape.
    ("POST",   re.compile(r"^/(v[\d.]+/)?containers/[\w.\-]+/attach$")),
    ("DELETE", re.compile(r"^/(v[\d.]+/)?containers/[\w.\-]+$")),

    # Images: build them, list them, and remove the ones we built.
    ("POST",   re.compile(r"^/(v[\d.]+/)?build$")),
    # BuildKit, which is what `docker build` actually uses on every current
    # Docker. It does not use /build at all: it opens a hijacked session for the
    # build context and speaks gRPC over /grpc. Without these two, every build
    # fails with a bare 403 that names neither the call nor the reason -- which
    # is exactly how this was found, by a build that silently would not run.
    #
    # This does not widen the trust boundary. A build is already arbitrary code
    # in a container by definition, and BuildKit's sources come from the client
    # session (this proxy's client, i.e. the web UI) and from images, not from
    # arbitrary host paths. The boundary that matters is "can start a build",
    # and the documentation already says that is host-root-equivalent because
    # the image builder runs privileged.
    ("POST",   re.compile(r"^/(v[\d.]+/)?session$")),
    ("POST",   re.compile(r"^/(v[\d.]+/)?grpc$")),
    ("GET",    re.compile(r"^/(v[\d.]+/)?images/json$")),
    ("GET",    re.compile(r"^/(v[\d.]+/)?images/[\w.\-/:]+/json$")),
    ("DELETE", re.compile(r"^/(v[\d.]+/)?images/[\w.\-/:]+$")),

    # The compose plugin reads these to work out what it already has.
    ("GET",    re.compile(r"^/(v[\d.]+/)?networks$")),
    ("GET",    re.compile(r"^/(v[\d.]+/)?networks/[\w.\-]+$")),
    ("POST",   re.compile(r"^/(v[\d.]+/)?networks/create$")),
    # compose attaches its containers to the stack network after creating them.
    ("POST",   re.compile(r"^/(v[\d.]+/)?networks/[\w.\-]+/connect$")),
    ("POST",   re.compile(r"^/(v[\d.]+/)?networks/[\w.\-]+/disconnect$")),
    ("DELETE", re.compile(r"^/(v[\d.]+/)?networks/[\w.\-]+$")),
    ("GET",    re.compile(r"^/(v[\d.]+/)?volumes$")),
    ("GET",    re.compile(r"^/(v[\d.]+/)?events$")),
]

# Requests whose body has to be looked at before they are allowed through.
INSPECT = re.compile(r"^/(v[\d.]+/)?containers/create$")


class Denied(Exception):
    pass


def allowed(method: str, path: str) -> bool:
    bare = path.split("?", 1)[0]
    return any(m == method and p.match(bare) for m, p in RULES)


def check_create(body: bytes) -> None:
    """Validate a container-create payload, or raise Denied.

    This is where the proxy earns most of its keep. The path allowlist alone
    would let a compromised UI create a container from any image with `/`
    bind-mounted read-write, which is host root by a different door than the one
    that was just closed.
    """
    try:
        spec = json.loads(body or b"{}")
    except ValueError:
        raise Denied("container create body is not JSON")
    if not isinstance(spec, dict):
        raise Denied("container create body is not an object")

    image = str(spec.get("Image") or "")
    if not IMAGE_ALLOW.match(image):
        raise Denied(f"image {image!r} is not one this proxy will run")

    host = spec.get("HostConfig") or {}
    if not isinstance(host, dict):
        raise Denied("HostConfig is not an object")

    if host.get("Privileged") and not PRIVILEGED_ALLOW.match(image):
        raise Denied(f"{image!r} may not run privileged")

    # Binds arrive as "src:dst" or "src:dst:opts", and also as Mounts[] in
    # newer clients. Both are checked: allowing one and forgetting the other is
    # the whole hole, and the docker CLI picks between them by version.
    for bind in host.get("Binds") or []:
        source = str(bind).split(":", 1)[0]
        _check_source(source)
    for mount in host.get("Mounts") or []:
        if isinstance(mount, dict) and mount.get("Type") == "bind":
            _check_source(str(mount.get("Source") or ""))

    # A container in the host's PID or network namespace, or with the host's
    # devices, is not confined by any of the above.
    for key in ("PidMode", "IpcMode", "UTSMode", "UsernsMode"):
        if str(host.get(key) or "").startswith("host"):
            raise Denied(f"{key}=host is not allowed")
    if host.get("Devices") and not PRIVILEGED_ALLOW.match(image):
        raise Denied(f"{image!r} may not be given host devices")
    for cap in host.get("CapAdd") or []:
        if str(cap).upper() in ("ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE") \
                and not PRIVILEGED_ALLOW.match(image):
            raise Denied(f"{image!r} may not add {cap}")


_project_root_cache: list[str] = []


def project_root() -> str:
    """The host path the project lives at, discovered rather than configured.

    HOST_PROJECT_DIR wins if it is set, but it usually is not: the web UI works
    its own out by inspecting its container's mounts over the socket, precisely
    so nobody has to write the path down twice. This proxy asks the daemon the
    same question about the same container, so the two cannot disagree -- a
    hand-configured value that drifts from the real mount would refuse every
    legitimate build with a message about a path that looks correct.

    Cached after the first success. Before the web UI container exists there is
    nothing to ask, and until then binds are refused rather than guessed at.
    """
    if PROJECT_DIR:
        return PROJECT_DIR
    if _project_root_cache:
        return _project_root_cache[0]
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(UPSTREAM)
        with sock:
            sock.sendall(f"GET /containers/{WEBUI_CONTAINER}/json HTTP/1.1\r\n"
                         "Host: docker\r\nConnection: close\r\n\r\n".encode())
            raw = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                raw += chunk
        body = raw.partition(b"\r\n\r\n")[2]
        # Connection: close, so the daemon answers without chunking; if it did
        # chunk, json.loads fails and we fall through to refusing binds, which
        # is the safe direction.
        spec = json.loads(body)
        for mount in spec.get("Mounts") or []:
            if mount.get("Destination") == "/project" and mount.get("Source"):
                _project_root_cache.append(str(mount["Source"]))
                log.info("discovered project root %s from %s",
                         _project_root_cache[0], WEBUI_CONTAINER)
                return _project_root_cache[0]
    except (OSError, ValueError, KeyError) as exc:
        log.debug("could not discover the project root: %s", exc)
    return ""


def _check_source(source: str) -> None:
    if not source:
        return
    # The Docker socket, by any of its names. Handing it to a container is
    # handing that container everything this proxy exists to withhold.
    if source.rstrip("/").endswith("docker.sock"):
        raise Denied("the Docker socket may not be mounted into a container")
    if not source.startswith("/"):
        return                      # a named volume, not a host path
    configured = project_root()
    if not configured:
        raise Denied("the project's host path is not known yet, so no bind can "
                     "be checked against it; set HOST_PROJECT_DIR if it cannot "
                     "be discovered")
    root = os.path.normpath(configured)
    resolved = os.path.normpath(source)
    if resolved != root and not resolved.startswith(root + os.sep):
        raise Denied(f"{source!r} is outside the project directory")


def read_headers(sock: socket.socket, buffered: bytes = b"") \
        -> tuple[bytes, bytes, str, str, list[tuple[str, str]]]:
    """Read one request's headers. Returns (raw_head, leftover, method, path, headers).

    `buffered` is whatever was already read past the previous request on this
    connection — the docker CLI reuses connections, so the next request line is
    routinely sitting in the same recv() as the last body byte.

    Headers come back as a list of pairs, not a dict. A dict collapses repeated
    headers, and that is not academic: BuildKit's session request sends one
    `X-Docker-Expose-Session-Grpc-Method` header per gRPC method it is
    registering. Collapsed to one, the daemon registers a single method, the
    filesync service is never advertised, and every build fails with
    `failed to read dockerfile: no local sources enabled` -- an error that names
    the Dockerfile and says nothing about headers or about a proxy.
    """
    buf = buffered
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            if not buf:
                raise EOFError("connection closed")
            break
        buf += chunk
        # A request line and headers are small. Anything claiming otherwise is
        # not a Docker client, and buffering it would be the denial of service.
        if len(buf) > 256 * 1024:
            raise Denied("request headers are implausibly large")
    if not buf:
        raise EOFError("connection closed")
    head, sep, rest = buf.partition(b"\r\n\r\n")
    if not sep:
        raise Denied("malformed request")
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 2:
        raise Denied("malformed request line")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        key, _, value = line.partition(":")
        if key:
            headers.append((key.strip(), value.strip()))
    return head + b"\r\n\r\n", rest, parts[0], parts[1], headers


def header(headers: list[tuple[str, str]], name: str) -> str:
    name = name.lower()
    for key, value in headers:
        if key.lower() == name:
            return value
    return ""


def is_upgrade(headers: list[tuple[str, str]]) -> bool:
    """Does this request want the connection handed over wholesale?

    BuildKit's /session and /grpc do, and so would attach and exec if they were
    allowed. After an upgrade the connection stops being HTTP, so there is
    nothing further to inspect and nothing further can be smuggled -- the check
    that mattered already happened on the request that asked for it.
    """
    return "upgrade" in header(headers, "connection").lower() \
        or bool(header(headers, "upgrade"))


def _recv_exactly(sock: socket.socket, have: bytes, n: int) -> tuple[bytes, bytes]:
    """Return (first n bytes, whatever was already read past them)."""
    while len(have) < n:
        chunk = sock.recv(min(65536, n - len(have)))
        if not chunk:
            break
        have += chunk
    return have[:n], have[n:]


def _recv_line(sock: socket.socket, have: bytes) -> tuple[bytes, bytes]:
    """Return (one CRLF-terminated line including the CRLF, the remainder)."""
    while b"\r\n" not in have:
        chunk = sock.recv(65536)
        if not chunk:
            raise Denied("connection ended mid-request")
        have += chunk
        if len(have) > 64 * 1024:
            raise Denied("chunk header is implausibly large")
    line, _, rest = have.partition(b"\r\n")
    return line + b"\r\n", rest


def forward_body(client: socket.socket, upstream: socket.socket,
                 headers: list[tuple[str, str]], rest: bytes) -> bytes:
    """Send exactly this request's body upstream. Returns anything left over.

    Framing is parsed rather than assumed, because "everything after the
    headers" is not the body -- it is the body *and whatever the client
    pipelined behind it*. Relaying the lot would hand the daemon a second
    request the allowlist never saw, which is the hole this whole class of proxy
    exists to avoid. Leftover bytes are returned so the caller can refuse them
    rather than pass them on.

    Not left to the daemon to sort out. Go's HTTP server happens to stop reading
    a connection once a request carried `Connection: close`, so in practice it
    would ignore a pipelined second request -- but "safe because the upstream is
    written in Go" is not a property this proxy should be relying on.
    """
    encoding = header(headers, "transfer-encoding").lower()
    if "chunked" in encoding:
        while True:
            line, rest = _recv_line(client, rest)
            upstream.sendall(line)
            size_text = line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                raise Denied("malformed chunk size")
            if size == 0:
                # Trailers, then the blank line that ends them.
                while True:
                    line, rest = _recv_line(client, rest)
                    upstream.sendall(line)
                    if line == b"\r\n":
                        return rest
            body, rest = _recv_exactly(client, rest, size + 2)   # + CRLF
            upstream.sendall(body)
    try:
        length = int(header(headers, "content-length") or 0)
    except ValueError:
        length = 0
    if length:
        body, rest = _recv_exactly(client, rest, length)
        upstream.sendall(body)
    return rest


def relay(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        # Half-close so the other direction can finish: a build streams its
        # output long after the request body has ended.
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def refuse(sock: socket.socket, reason: str, status: str = "403 Forbidden") -> None:
    body = json.dumps({"message": f"refused by the Flipside Docker proxy: {reason}"}).encode()
    sock.sendall(b"HTTP/1.1 " + status.encode() + b"\r\n"
                 b"Content-Type: application/json\r\n"
                 b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                 b"Connection: close\r\n\r\n" + body)


class Handler(socketserver.BaseRequestHandler):
    """Exactly one request per connection, which is what makes the check sound.

    The docker CLI keeps connections alive and sends the next request down the
    same socket. A proxy that inspected the first request and then became a
    transparent tunnel would pass everything after it -- `GET /version`, then
    `POST /containers/other/exec` on the same socket, and the allowlist never
    sees the second one. That is not a corner case; it is how the client
    normally behaves.

    Rather than parse response framing to know where one exchange ends and the
    next begins, the forwarded request carries `Connection: close`. The daemon
    answers and hangs up, the client re-dials for its next call, and every
    request arrives at a proxy that has not yet decided anything. A unix-socket
    connection per API call costs nothing worth measuring.

    Upgraded connections (BuildKit's session and gRPC) are exempt, because after
    an upgrade the connection stops being HTTP: there is nothing further to
    inspect, and nothing further can be smuggled past a check that already
    happened on the request that asked for the upgrade.
    """

    def handle(self) -> None:
        client: socket.socket = self.request
        try:
            raw_head, rest, method, path, headers = read_headers(client)
        except EOFError:
            return
        except Denied as exc:
            log.warning("malformed request: %s", exc)
            self._safe(refuse, client, str(exc), "400 Bad Request")
            return
        except OSError:
            return
        self._one(client, raw_head, rest, method, path, headers)

    def _safe(self, fn, *args) -> None:
        try:
            fn(*args)
        except OSError:
            pass

    def _one(self, client: socket.socket, raw_head: bytes, rest: bytes,
             method: str, path: str, headers: list[tuple[str, str]]) -> None:
        bare = path.split("?", 1)[0]
        if not allowed(method, path):
            log.warning("DENY %s %s (not on the allowlist)", method, bare)
            self._safe(refuse, client, f"{method} {bare} is not on the allowlist")
            return

        if INSPECT.match(bare):
            try:
                length = int(header(headers, "content-length") or 0)
            except ValueError:
                length = 0
            # Only ever a small JSON document. `docker build` sends the whole
            # build context as its body, which is why that path is relayed
            # without inspection rather than read into memory first.
            if length > 1024 * 1024:
                log.warning("DENY %s %s (create body of %d bytes)", method, bare, length)
                self._safe(refuse, client, "container create body is implausibly large")
                return
            body = rest
            while len(body) < length:
                chunk = client.recv(min(65536, length - len(body)))
                if not chunk:
                    break
                body += chunk
            try:
                check_create(body)
            except Denied as exc:
                log.warning("DENY %s %s: %s", method, bare, exc)
                self._safe(refuse, client, str(exc))
                return
            rest = body

        upgrade = is_upgrade(headers)
        log.info("ALLOW %s %s%s", method, bare, " (upgrade)" if upgrade else "")

        try:
            upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            upstream.connect(UPSTREAM)
        except OSError as exc:
            log.error("upstream %s unreachable: %s", UPSTREAM, exc)
            self._safe(refuse, client, f"the Docker daemon is unreachable: {exc}",
                       "502 Bad Gateway")
            return

        with upstream:
            # Replayed byte for byte. Rebuilding the request from parsed pieces
            # is a second serialiser to keep in step with the parser, and it
            # only has to differ once -- BuildKit's session hands the connection
            # over with headers that have to arrive exactly as sent.
            head = raw_head
            if not upgrade:
                # One request per upstream connection, and the client's
                # connection ends with it. That is what makes the check above
                # sound: without it a keep-alive connection would carry a second
                # request nobody looked at. An upgraded connection is exempt
                # because it stops being HTTP the moment the daemon accepts it.
                head = self._force_close(raw_head)
            try:
                upstream.sendall(head)
                if upgrade:
                    # Hand the connection over: after this it is no longer HTTP,
                    # so there is no framing to respect and nothing further to
                    # check. Both directions relay until one end hangs up.
                    upstream.sendall(rest)
                    up = threading.Thread(target=relay, args=(client, upstream),
                                          daemon=True)
                    up.start()
                    relay(upstream, client)
                    up.join(timeout=5)
                    return
                leftover = forward_body(client, upstream, headers, rest)
            except Denied as exc:
                log.warning("DENY %s %s: %s", method, bare, exc)
                self._safe(refuse, client, str(exc), "400 Bad Request")
                return
            except OSError:
                return
            if leftover.strip():
                # A pipelined second request. Real clients do not do this -- Go's
                # transport waits for each response -- so this is somebody
                # trying to get a request past the check by hiding it behind an
                # allowed one. The first request has already gone upstream; the
                # second stops here.
                log.warning("DENY pipelined request after %s %s (%d bytes dropped)",
                            method, bare, len(leftover))
            # One direction only: the request is complete, and the response is
            # read until the daemon closes -- which it does, because the
            # forwarded request carried Connection: close.
            relay(upstream, client)

    @staticmethod
    def _force_close(raw_head: bytes) -> bytes:
        lines = raw_head.split(b"\r\n")
        kept = [ln for ln in lines
                if ln and not ln.lower().startswith(b"connection:")
                and not ln.lower().startswith(b"keep-alive:")]
        kept.append(b"Connection: close")
        return b"\r\n".join(kept) + b"\r\n\r\n"


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    request_queue_size = 128
    # Without this a restart hits "Address already in use" on the socket file,
    # which for a unix socket means a leftover inode rather than a busy port --
    # and the container then crash-loops on a file it could simply remove.
    allow_reuse_address = True


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(message)s",
                        stream=sys.stdout)
    if not os.path.exists(UPSTREAM):
        log.error("no Docker socket at %s", UPSTREAM)
        return 1
    if not PROJECT_DIR:
        log.info("HOST_PROJECT_DIR is unset; the project root will be read from "
                 "%s's own mounts on the first bind that needs checking.",
                 WEBUI_CONTAINER)
    try:
        os.unlink(LISTEN)
    except FileNotFoundError:
        pass
    os.makedirs(os.path.dirname(LISTEN), exist_ok=True)
    server = Server(LISTEN, Handler)
    # The web UI runs as root in its container today, but the socket should not
    # depend on that staying true; 0660 with the shared group is enough.
    os.chmod(LISTEN, 0o660)
    log.info("listening on %s, forwarding allowlisted calls to %s", LISTEN, UPSTREAM)
    log.info("images allowed: %s", IMAGE_ALLOW.pattern)
    log.info("privileged allowed for: %s", PRIVILEGED_ALLOW.pattern)
    log.info("host binds confined to: %s",
             PROJECT_DIR or f"(discovered from {WEBUI_CONTAINER} on first use)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
