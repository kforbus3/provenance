#!/bin/bash
# Drive a real Docker daemon through the proxy, and try to get past it.
#
# The allowlist is the security control, and the two ways it fails are opposite
# and both quiet:
#
#   too tight  -- a build stops working, with an error from the docker CLI that
#                 says "403" and nothing about which call or why. This is the
#                 likely failure, because the CLI and the compose plugin make
#                 calls nobody wrote down.
#   too loose  -- the socket is still a socket. `docker exec` into another
#                 container, or a container with / mounted, and the proxy is
#                 decoration.
#
# So this exercises both directions against the real daemon: the calls the
# project actually makes must work, and the escapes must be refused.
#
#   ./scripts/test-docker-proxy.sh          # needs a working docker
set -u

PROXY="$(cd "$(dirname "$0")/.." && pwd)/dockerproxy/proxy.py"
[ -f "$PROXY" ] || { echo "not found: $PROXY" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || { echo "SKIP: no docker CLI"; exit 0; }
docker info >/dev/null 2>&1 || { echo "SKIP: no reachable docker daemon"; exit 0; }

WORK="$(mktemp -d)"
trap 'kill ${PROXY_PID:-0} 2>/dev/null; docker rm -f dp-test-victim >/dev/null 2>&1;
      docker rmi -f debian-ab-builder:dptest >/dev/null 2>&1; rm -rf "$WORK"' EXIT

ok=0; fail=0
pass() { ok=$((ok+1)); echo "  PASS  $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL  $1 ${2:-}"; }

mkdir -p "$WORK/shared" "$WORK/ctx"
# A project root for the bind check, so a legitimate mount has somewhere to be.
mkdir -p "$WORK/project/output"

HOST_PROJECT_DIR="$WORK/project" PROXY_SOCKET="$WORK/shared/docker.sock" \
    LOG_LEVEL=DEBUG python3 "$PROXY" > "$WORK/proxy.log" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 50); do [ -S "$WORK/shared/docker.sock" ] && break; sleep 0.2; done
[ -S "$WORK/shared/docker.sock" ] || {
    echo "the proxy never started:"; cat "$WORK/proxy.log"; exit 1; }

export DOCKER_HOST="unix://$WORK/shared/docker.sock"

# Raw calls, for the ones the CLI will not make on request.
api() {  # api <METHOD> <PATH> [BODY]
    curl -s -o "$WORK/body" -w "%{http_code}" -X "$1" \
        --unix-socket "$WORK/shared/docker.sock" \
        ${3:+-H "Content-Type: application/json"} ${3:+-d "$3"} \
        "http://localhost$2"
}

echo "== the calls this project makes still work =="
docker version >/dev/null 2>&1 && pass "docker version" || bad "docker version"
docker images >/dev/null 2>&1 && pass "docker images" || bad "docker images"
docker ps >/dev/null 2>&1 && pass "docker ps" || bad "docker ps"

# A build, which is how every image in this project is produced.
cat > "$WORK/ctx/Dockerfile" <<'EOF'
FROM busybox:latest
RUN echo built > /marker
EOF
# Reported as a failure with its output, not as a skip. A build that will not
# run is the single likeliest way this proxy breaks the project, and the first
# version of this test hid exactly that behind a SKIP: `docker build` uses
# BuildKit on every current Docker, which does not touch /build at all -- it
# opens a hijacked /session and speaks gRPC over /grpc. Neither was on the
# allowlist, so every build failed with a bare 403, and the test said "skipped".
# Tagged as the builder from the start rather than built and then renamed:
# `docker tag` is POST /images/{name}/tag, which is not on the allowlist and
# should not be -- the project builds its images with -t and never renames one.
if docker build -t debian-ab-builder:dptest "$WORK/ctx" > "$WORK/build.log" 2>&1; then
    pass "docker build"
else
    if grep -qiE "network|dial tcp|no such host|lookup|TLS handshake" "$WORK/build.log"; then
        # No network on the runner is not a proxy failure and must not be
        # reported as one -- but say so, rather than staying quiet.
        echo "  SKIP  docker build (this runner cannot reach a registry)"
    else
        bad "docker build" "(output below)"
        tail -20 "$WORK/build.log" | sed 's/^/        /'
        echo "        --- every call the proxy saw during the build ---"
        sed 's/^/        /' "$WORK/proxy.log"
    fi
fi

# Running a container from an allowed image, which is what a job is.
if docker image inspect debian-ab-builder:dptest >/dev/null 2>&1; then
    if out="$(docker run --rm debian-ab-builder:dptest cat /marker 2>&1)"; then
        [ "$out" = "built" ] && pass "docker run of an allowed image" \
                             || bad "docker run of an allowed image" "$out"
    else
        bad "docker run of an allowed image" "$out"
    fi
    # And privileged, because the real builder needs loop devices.
    docker run --rm --privileged debian-ab-builder:dptest true >/dev/null 2>&1 \
        && pass "the builder may run privileged" \
        || bad "the builder may run privileged"
    # A legitimate bind, inside the project.
    docker run --rm -v "$WORK/project:/project" debian-ab-builder:dptest \
        ls /project >/dev/null 2>&1 \
        && pass "a bind inside the project is allowed" \
        || bad "a bind inside the project is allowed"
fi

echo "== the escapes are refused =="
# Each of these is a way out of the container if the socket is raw. They are the
# reason the proxy exists, so each is tried for real rather than asserted about.

code=$(api POST "/containers/create" \
  '{"Image":"busybox:latest","HostConfig":{"Binds":["/:/host"]}}')
[ "$code" = "403" ] && pass "an arbitrary image is refused" \
                    || bad "an arbitrary image is refused" "got $code"

code=$(api POST "/containers/create" \
  '{"Image":"debian-ab-builder:dptest","HostConfig":{"Binds":["/:/host"]}}')
[ "$code" = "403" ] && pass "mounting / is refused even for an allowed image" \
                    || bad "mounting / is refused even for an allowed image" "got $code"

code=$(api POST "/containers/create" \
  '{"Image":"debian-ab-builder:dptest","HostConfig":{"Binds":["/etc:/etc-host:ro"]}}')
[ "$code" = "403" ] && pass "mounting a host path outside the project is refused" \
                    || bad "mounting a host path outside the project is refused" "got $code"

code=$(api POST "/containers/create" \
  '{"Image":"debian-ab-builder:dptest","HostConfig":{"Binds":["/var/run/docker.sock:/var/run/docker.sock"]}}')
[ "$code" = "403" ] && pass "mounting the Docker socket is refused" \
                    || bad "mounting the Docker socket is refused" "got $code"

# The newer Mounts[] spelling of the same thing. Checking Binds and forgetting
# this is the whole hole, and the CLI chooses between them by version.
code=$(api POST "/containers/create" \
  '{"Image":"debian-ab-builder:dptest","HostConfig":{"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}]}}')
[ "$code" = "403" ] && pass "the Mounts[] spelling is refused too" \
                    || bad "the Mounts[] spelling is refused too" "got $code"

code=$(api POST "/containers/create" \
  '{"Image":"debian-ab-webui","HostConfig":{"Privileged":true}}')
[ "$code" = "403" ] && pass "a non-builder image may not run privileged" \
                    || bad "a non-builder image may not run privileged" "got $code"

code=$(api POST "/containers/create" \
  '{"Image":"debian-ab-builder:dptest","HostConfig":{"PidMode":"host"}}')
[ "$code" = "403" ] && pass "the host PID namespace is refused" \
                    || bad "the host PID namespace is refused" "got $code"

# Reaching into something else on the host. This is the one that matters most:
# a shared Docker host runs other people's workloads.
docker run -d --name dp-test-victim busybox:latest sleep 300 >/dev/null 2>&1 || true
code=$(api POST "/containers/dp-test-victim/exec" \
  '{"Cmd":["cat","/etc/shadow"],"AttachStdout":true}')
[ "$code" = "403" ] && pass "exec into another container is refused" \
                    || bad "exec into another container is refused" "got $code"

code=$(api POST "/images/create?fromImage=alpine&tag=latest" '')
[ "$code" = "403" ] && pass "pulling an arbitrary image is refused" \
                    || bad "pulling an arbitrary image is refused" "got $code"

code=$(api GET "/secrets" '')
[ "$code" = "403" ] && pass "swarm secrets are refused" || bad "swarm secrets are refused" "got $code"

code=$(api POST "/commit?container=dp-test-victim&repo=exfil" '')
[ "$code" = "403" ] && pass "committing a container to an image is refused" \
                    || bad "committing a container to an image is refused" "got $code"

# Path tricks: the daemon normalises, so an allowlist matching a prefix would
# let a denied endpoint through under an allowed-looking name.
code=$(api GET "/containers/json/../../secrets" '')
[ "$code" = "403" ] && pass "a traversal in the path is refused" \
                    || bad "a traversal in the path is refused" "got $code"

echo "== a second request on the same connection is not smuggled through =="
# The docker CLI keeps connections alive. A proxy that checked the first request
# and then relayed raw would pass everything after it -- and "everything after
# it" is chosen by whoever is talking to the proxy. This sends an allowed
# request and a denied one down one socket, pipelined, and asserts the daemon
# never answers the second.
if python3 "$(dirname "$0")/dp-pipeline-check.py" "$WORK/shared/docker.sock"; then
    pass "a pipelined denied request does not reach the daemon"
else
    bad "a pipelined denied request does not reach the daemon"
fi

echo "== every decision is logged =="
grep -q "^.*DENY POST /containers/create" "$WORK/proxy.log" \
    && pass "denials are logged with the call" \
    || bad "denials are logged with the call"
# The logged path keeps the API version prefix the client sent, so this is
# /v1.51/version rather than /version -- matching the bare form failed against a
# proxy that was logging perfectly.
grep -qE "ALLOW GET (/v[0-9.]+)?/version" "$WORK/proxy.log" \
    && pass "so are the calls that were allowed" \
    || { bad "so are the calls that were allowed"; grep ALLOW "$WORK/proxy.log" | head -5 | sed 's/^/        /'; }

echo
echo "$ok passed, $fail failed"
[ "$fail" -eq 0 ]
