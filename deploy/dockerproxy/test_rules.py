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

print("== compose can recreate a container, but not steal a trusted name ==")
# Compose renames the old container out of the way before creating its
# replacement. Without this route ANY `compose up` that replaces a container
# fails halfway -- which took the PXE HTTP server down and left a container
# stuck in Created.
check("POST /containers/abc/rename is allowed",
      proxy.allowed("POST", "/v1.45/containers/abc/rename?name=old_http"))

def renamed_to(name):
    try:
        proxy.check_rename(f"/v1.45/containers/abc/rename?name={name}")
        return False
    except proxy.Denied:
        return True

# The one thing rename must not do. The proxy resolves the runner BY NAME to
# learn where the project lives, and the project root is what every bind-mount
# check is measured against -- so a container able to claim that name could
# move the goalposts for all of them.
for protected in ("provenance-builder-runner", "provenance-dockerproxy-1"):
    check(f"cannot rename INTO {protected}", renamed_to(protected))
    check(f"  ... nor with a leading slash", renamed_to("/" + protected))
check("an ordinary name is still fine", not renamed_to("debian-ab-http"))

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

# The rename regression. Host-NIC discovery runs a throwaway container from the
# RUNNER'S OWN image in the host network namespace; when the compose images were
# renamed to `provenance-` and this allowlist was not, that create was refused,
# the orchestrator swallowed the error, and the Provisioning page showed an empty
# interface list — no interface to PXE on, and nothing saying why.
check("the runner's own image is allowed (host-NIC discovery runs it)",
      not denied({"Image": "provenance-builder-runner"}))
check("the runner's own image is allowed with a tag",
      not denied({"Image": "provenance-builder-runner:latest"}))
check("the renamed proxy image is allowed",
      not denied({"Image": "provenance-dockerproxy"}))
# Allowing it to RUN must not have allowed it to run as root on the host: only
# the builder and imager genuinely need loop devices and mounts.
check("the runner may NOT be privileged",
      denied({"Image": "provenance-builder-runner", "HostConfig": {"Privileged": True}}))
check("a registry path merely containing the runner name is refused",
      denied({"Image": "evil.example.com/provenance-builder-runner"}))
check("a lookalike provenance image is refused",
      denied({"Image": "provenance-backend"}))

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

print("== the binfmt registrar is OFF by default ==")
# It is a third-party image from Docker Hub run as host root. Everything else this
# proxy will run is built from this repository, and that exception should never
# arrive without somebody choosing it.
check("the binfmt image is refused by default", denied({"Image": "tonistiigi/binfmt"}))
check("and may not run privileged by default",
      denied({"Image": "tonistiigi/binfmt", "HostConfig": {"Privileged": True}}))
check("pulling it is refused by default",
      not proxy.allowed("POST", "/v1.45/images/create?fromImage=tonistiigi/binfmt"))

print("== enabled, it is permitted and nothing else is ==")
proxy.BINFMT_ALLOW = True
proxy.BINFMT_IMAGE = "tonistiigi/binfmt"
try:
    check("the binfmt image may now run", not denied({"Image": "tonistiigi/binfmt"}))
    check("and may run privileged, which is what it is for",
          not denied({"Image": "tonistiigi/binfmt", "HostConfig": {"Privileged": True}}))
    # docker run pulls what it does not have, so without this the setting would
    # fail at the pull instead of the create -- applied-looking and not applied.
    check("pulling exactly it is permitted",
          proxy.allowed("POST", "/v1.45/images/create?fromImage=tonistiigi/binfmt"))
    check("with a tag split across fromImage and tag",
          proxy.allowed("POST", "/v1.45/images/create?fromImage=tonistiigi/binfmt&tag=latest"))
    # Enabling one image must not become a general pull capability.
    check("pulling anything else is still refused",
          not proxy.allowed("POST", "/v1.45/images/create?fromImage=alpine"))
    check("a lookalike registry path is refused",
          denied({"Image": "evil.example.com/tonistiigi/binfmt"}))
    check("a tagged lookalike is refused",
          denied({"Image": "tonistiigi/binfmt-evil"}))
    check("and the enabled name does not widen privilege for others",
          denied({"Image": "debian-ab-http", "HostConfig": {"Privileged": True}}))

    # Pinning by digest is the recommended form; the daemon sends the digest in
    # `tag`, joined with '@' rather than ':'.
    proxy.BINFMT_IMAGE = "tonistiigi/binfmt@sha256:" + "a" * 64
    check("a digest-pinned image matches when split across the two parameters",
          proxy.allowed("POST", "/v1.45/images/create?fromImage=tonistiigi/binfmt&tag=sha256:" + "a" * 64))
    check("and the unpinned name is then refused",
          denied({"Image": "tonistiigi/binfmt"}))
finally:
    proxy.BINFMT_ALLOW = False
    proxy.BINFMT_IMAGE = "tonistiigi/binfmt"

print("== turning it back off closes it again ==")
check("refused once disabled", denied({"Image": "tonistiigi/binfmt"}))
check("pull refused once disabled",
      not proxy.allowed("POST", "/v1.45/images/create?fromImage=tonistiigi/binfmt"))

print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
