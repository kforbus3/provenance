#!/usr/bin/env python3
"""The proxy's decisions, without needing a Docker daemon to make them.

scripts/test-docker-proxy.sh drives the real thing and is the better test; it
needs a daemon, which not every machine running the suite has. These are the
decisions themselves, so a rule loosened by accident is caught anywhere.

Everything here is an escape that works if the Docker socket is raw. That is
the point: the proxy is only worth having if each of these is refused, and
"refused" is a property that quietly stops being true when somebody adds a rule
to make a build work again.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("HOST_PROJECT_DIR", "/srv/flipside")
import proxy  # noqa: E402

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name} {extra}")


def denied(spec) -> bool:
    try:
        proxy.check_create(json.dumps(spec).encode())
        return False
    except proxy.Denied:
        return True


print("== the calls this project makes are on the allowlist ==")
for method, path in [
    ("GET", "/v1.45/version"), ("GET", "/_ping"), ("GET", "/info"),
    ("POST", "/containers/create"), ("POST", "/v1.45/containers/abc/start"),
    ("POST", "/containers/abc/wait"), ("GET", "/containers/abc/logs?follow=1"),
    ("DELETE", "/containers/abc"), ("POST", "/build?t=debian-ab-builder"),
    # BuildKit's two endpoints. `docker build` on any current Docker uses these
    # and not /build, so leaving them off makes every build fail with a bare
    # 403 -- the "too tight" failure this proxy's tests exist to catch, and how
    # it was found: a build that silently would not run.
    ("POST", "/session"), ("POST", "/grpc"),
    ("GET", "/containers/json?all=1"), ("GET", "/images/json"),
    ("POST", "/networks/create"), ("POST", "/networks/abc/connect"),
    # Attach is allowed: `docker run` in the foreground streams a container's
    # output through it, and every build here is a foreground run whose output
    # becomes the job log. Exec is not, and that is the distinction that
    # matters -- attach connects to a container's existing stdio, exec starts a
    # new process of the caller's choosing inside any container on the host.
    ("POST", "/containers/abc/attach?stream=1&stdout=1"),
]:
    check(f"{method} {path}", proxy.allowed(method, path))

print("== the ways out of a container are not ==")
for method, path in [
    # Each of these is a documented container escape when the socket is raw.
    ("POST", "/containers/other/exec"),
    ("POST", "/exec/abc/start"),
    ("POST", "/images/create?fromImage=attacker/image"),
    ("POST", "/commit?container=other&repo=exfil"),
    ("POST", "/images/x/push"),
    ("GET", "/secrets"),
    ("GET", "/configs"),
    ("GET", "/swarm"),
    ("POST", "/swarm/join"),
    ("GET", "/nodes"),
    ("POST", "/plugins/pull"),
    ("PUT", "/containers/abc/archive"),          # writing files into a container
    ("GET", "/containers/abc/archive"),          # and reading them out
    ("POST", "/containers/abc/update"),
    # An allowlist matching a prefix rather than the whole path would pass this,
    # and the daemon normalises it upstream into the endpoint it names.
    ("GET", "/containers/json/../../secrets"),
    ("GET", "/v1.45/containers/json/../../../secrets"),
]:
    check(f"{method} {path}", not proxy.allowed(method, path))

print("== a create payload cannot ask for the host ==")
check("an arbitrary image is refused", denied({"Image": "alpine:latest"}))
check("a registry path that merely contains an allowed name is refused",
      denied({"Image": "evil.example.com/debian-ab-builder"}))
check("the builder itself is allowed", not denied({"Image": "debian-ab-builder:amd64"}))

check("mounting / is refused",
      denied({"Image": "debian-ab-builder", "HostConfig": {"Binds": ["/:/host"]}}))
check("mounting a host path outside the project is refused",
      denied({"Image": "debian-ab-builder", "HostConfig": {"Binds": ["/etc:/e:ro"]}}))
check("a bind inside the project is allowed",
      not denied({"Image": "debian-ab-builder",
                  "HostConfig": {"Binds": ["/srv/flipside/output:/output"]}}))
# The prefix check has to be on a path boundary. /srv/flipside-evil starts with
# /srv/flipside, and a naive startswith() would let it through.
check("a sibling directory sharing the prefix is refused",
      denied({"Image": "debian-ab-builder",
              "HostConfig": {"Binds": ["/srv/flipside-evil:/x"]}}))
check("a traversal that resolves outside the project is refused",
      denied({"Image": "debian-ab-builder",
              "HostConfig": {"Binds": ["/srv/flipside/../..:/x"]}}))
check("mounting the Docker socket is refused",
      denied({"Image": "debian-ab-builder",
              "HostConfig": {"Binds": ["/var/run/docker.sock:/var/run/docker.sock"]}}))
# Checking Binds and forgetting Mounts[] is the whole hole; the CLI picks
# between the two spellings by API version, so both have to be covered.
check("the Mounts[] spelling of the same thing is refused",
      denied({"Image": "debian-ab-builder",
              "HostConfig": {"Mounts": [{"Type": "bind", "Source": "/", "Target": "/h"}]}}))
check("a named volume is not treated as a host path",
      not denied({"Image": "debian-ab-builder", "HostConfig": {"Binds": ["vol:/data"]}}))

print("== privilege is confined to the images that genuinely need it ==")
check("the web UI may not run privileged",
      denied({"Image": "debian-ab-webui", "HostConfig": {"Privileged": True}}))
# The builder attaches loop devices and mounts filesystems; it cannot do its job
# otherwise, which is why the proxy cannot make this host root-proof and the
# documentation says so rather than implying otherwise.
check("the builder may", not denied({"Image": "debian-ab-builder",
                                     "HostConfig": {"Privileged": True}}))
check("host devices are refused for anything else",
      denied({"Image": "debian-ab-http",
              "HostConfig": {"Devices": [{"PathOnHost": "/dev/sda"}]}}))
for mode in ("PidMode", "IpcMode", "UTSMode", "UsernsMode"):
    check(f"{mode}=host is refused",
          denied({"Image": "debian-ab-builder", "HostConfig": {mode: "host"}}))
check("SYS_ADMIN cannot be added to a non-builder image",
      denied({"Image": "debian-ab-http", "HostConfig": {"CapAdd": ["SYS_ADMIN"]}}))
# Host networking is required: dnsmasq answers DHCP and TFTP on the provisioning
# segment, and cannot from inside a bridge network.
check("host networking is still allowed, because PXE needs it",
      not denied({"Image": "debian-ab-http", "HostConfig": {"NetworkMode": "host"}}))

print("== malformed payloads are refused rather than passed through ==")
try:
    proxy.check_create(b"not json")
    check("a body that is not JSON is refused", False)
except proxy.Denied:
    check("a body that is not JSON is refused", True)
try:
    proxy.check_create(b"[1,2,3]")
    check("a body that is not an object is refused", False)
except proxy.Denied:
    check("a body that is not an object is refused", True)
try:
    proxy.check_create(b'{"Image":"debian-ab-builder","HostConfig":"nope"}')
    check("a HostConfig that is not an object is refused", False)
except proxy.Denied:
    check("a HostConfig that is not an object is refused", True)

print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
