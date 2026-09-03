#!/bin/bash
# A machine being imaged must be able to reach the endpoint it reports into.
#
# The imager posts progress to <image host>/api/imaging/report. It is given no
# other address: the iPXE scripts pass imager.url= and nothing else, so init
# derives the report URL from the image's host. That host is the provisioning
# nginx, which served static files and had no /api/ route at all -- so every
# report 404'd into the file root, and because reporting is deliberately
# best-effort and silent, a machine could image perfectly and never once appear
# on the Imaging page with nothing anywhere to explain it.
#
# This runs the real container: the real entrypoint renders the real template,
# and a stub stands in for the web UI. It asserts the two machine-facing
# endpoints arrive, and -- just as important -- that nothing else does.
#
#   docker run is used directly; this needs a docker daemon, not privileges.
#     bash scripts/test-imaging-report-route.sh
set -u

NET=abtest-report-net
STUB=abtest-report-stub
HTTP=abtest-report-http
IMG=ci-abhttp

PASS=0; FAIL=0
ok()   { echo "  ok    $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }

cleanup() {
    docker rm -f "$STUB" "$HTTP" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    [ -n "${DATA:-}" ] && rm -rf "$DATA"
}
trap cleanup EXIT
cleanup

REPO="$(cd "$(dirname "$0")/.." && pwd)"

docker build -q -t "$IMG" "$REPO/server/http" >/dev/null || { echo "HARNESS-FAIL: build"; exit 1; }
docker network create "$NET" >/dev/null || { echo "HARNESS-FAIL: network"; exit 1; }

# The stub logs the method and path of everything it receives, so the assertion
# is "the request actually arrived", not merely "nginx returned something".
docker run -d --name "$STUB" --network "$NET" python:3.12-slim \
    python -c '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def _log(self):
        print(f"HIT {self.command} {self.path}", flush=True)
        self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
    do_POST = _log
    do_GET = _log
    def log_message(self, *a): pass
http.server.HTTPServer(("0.0.0.0", 8080), H).serve_forever()
' >/dev/null || { echo "HARNESS-FAIL: stub"; exit 1; }

docker run -d --name "$HTTP" --network "$NET" \
    -e SERVER_IP=0.0.0.0 -e IMAGE_FILE=none.img -e "WEBUI_ADDR=$STUB:8080" \
    "$IMG" >/dev/null || { echo "HARNESS-FAIL: http"; exit 1; }

# Wait for nginx rather than sleeping a fixed amount.
for _ in $(seq 1 40); do
    docker run --rm --network "$NET" curlimages/curl:latest -s -o /dev/null \
        --max-time 2 "http://$HTTP/health" 2>/dev/null && break
    sleep 0.5
done

req() {   # req <method> <path> -> HTTP status
    docker run --rm --network "$NET" curlimages/curl:latest -s -o /dev/null \
        -w '%{http_code}' --max-time 5 -X "$1" "http://$HTTP$2" 2>/dev/null
}

echo "== the endpoints a machine reports into are routed to the web UI =="
code=$(req POST /api/imaging/report)
[ "$code" = "200" ] && ok "POST /api/imaging/report -> $code" \
                    || bad "POST /api/imaging/report -> $code (404 means the report is discarded)"
code=$(req POST /api/imaging/checkin)
[ "$code" = "200" ] && ok "POST /api/imaging/checkin -> $code" \
                    || bad "POST /api/imaging/checkin -> $code"

# The status alone is not proof: nginx could answer 200 from the file root.
LOG="$(docker logs "$STUB" 2>&1)"
printf '%s\n' "$LOG" | grep -q "HIT POST /api/imaging/report" \
    && ok "the report actually reached the web UI, not the file root" \
    || bad "nothing arrived at the web UI (stub log: $(printf '%s' "$LOG" | tr '\n' ' '))"
printf '%s\n' "$LOG" | grep -q "HIT POST /api/imaging/checkin" \
    && ok "the check-in actually reached the web UI" \
    || bad "the check-in did not arrive"

echo ""
echo "== and nothing else on the API is published to the imaging segment =="
# These are the admin surface. They are all behind require_auth, but the imaging
# network has no business being able to reach them at all -- a prefix proxy over
# /api/ would have done exactly that, which is why the locations are exact.
for path in /api/images /api/bundles /api/secrets/entries /api/server/config /api/imaging; do
    code=$(req GET "$path")
    [ "$code" = "404" ] && ok "GET $path -> 404 (not proxied)" \
                        || bad "GET $path -> $code; the admin API is reachable from the imaging network"
done
# The delete endpoint shares the /api/imaging/ prefix; a prefix match would
# expose it, an exact match does not. Asserted by what the web UI received
# rather than by status code: nginx's static handler answers DELETE with 405
# rather than 404, and pinning the code would make this test about nginx's
# choice of rejection instead of about whether the request was forwarded.
req DELETE /api/imaging/aa:bb:cc:dd:ee:ff >/dev/null
if docker logs "$STUB" 2>&1 | grep -q "HIT DELETE"; then
    bad "DELETE /api/imaging/<id> reached the web UI; a prefix match slipped through"
else
    ok "DELETE /api/imaging/<id> never reached the web UI (exact match holds)"
fi

echo ""
echo "== secrets that live under output/ are not served to the imaging segment =="
# output/ is mounted at /data and symlinked to /images, so everything the web
# UI keeps there shares a root with the image library. The RAUC signing
# private key is the sharpest case: anything on the imaging segment that could
# GET /images/rauc-keys/key.pem could sign bundles the whole fleet installs,
# and the certificate baked into every image cannot be rotated without
# re-imaging. This ran with autoindex on and no deny rules for months.
DATA="$REPO/output/route-test-data"
rm -rf "$DATA"
mkdir -p "$DATA/rauc-keys" "$DATA/hosts" "$DATA/jobs" "$DATA/bundles"
echo "FAKE SIGNING KEY"   > "$DATA/rauc-keys/key.pem"
echo '{"token":"secret"}' > "$DATA/.secrets-store.json"
echo '{"event":"imaged"}' > "$DATA/deployments.jsonl"
echo '{}'                 > "$DATA/hosts/assignments.json"
echo "job log"            > "$DATA/jobs/job-1.log"
echo "IMAGE BYTES"        > "$DATA/test-ab.img"
echo "BUNDLE"             > "$DATA/bundles/test.raucb"
# Read-only on purpose: the entrypoint must cope with a /data it cannot write
# (its mkdirs are -p over directories that already exist).
docker rm -f "$HTTP" >/dev/null 2>&1
docker run -d --name "$HTTP" --network "$NET" \
    -e SERVER_IP=0.0.0.0 -e IMAGE_FILE=none.img -e "WEBUI_ADDR=$STUB:8080" \
    -v "$DATA":/data:ro \
    "$IMG" >/dev/null
for _ in $(seq 1 40); do
    docker run --rm --network "$NET" curlimages/curl:latest -s -o /dev/null \
        --max-time 2 "http://$HTTP/health" 2>/dev/null && break
    sleep 0.5
done
for path in /images/rauc-keys/key.pem /images/.secrets-store.json \
            /images/deployments.jsonl /images/hosts/assignments.json \
            /hosts/assignments.json /images/jobs/job-1.log; do
    code=$(req GET "$path")
    [ "$code" = "404" ] && ok "GET $path -> 404" \
                        || bad "GET $path -> $code; a server-side secret is published to the imaging network"
done
# The deny rules must not take the things machines DO fetch with them.
code=$(req GET /images/test-ab.img)
[ "$code" = "200" ] && ok "GET /images/test-ab.img -> 200 (images still served)" \
                    || bad "GET /images/test-ab.img -> $code; the deny rules broke the image library"
code=$(req GET /bundles/test.raucb)
[ "$code" = "200" ] && ok "GET /bundles/test.raucb -> 200 (bundles still served)" \
                    || bad "GET /bundles/test.raucb -> $code; the deny rules broke bundle serving"
code=$(req GET /images/)
[ "$code" != "200" ] && ok "GET /images/ -> $code (no directory listing)" \
                     || bad "GET /images/ -> 200; the directory listing is back"

echo ""
echo "== a WEBUI_ADDR that cannot resolve must not take PXE down =="
# nginx resolves proxy_pass names at config load and refuses to start if it
# cannot. PXE dying because the web UI moved would be a far worse failure than
# losing the progress display, so the entrypoint checks and falls back.
docker rm -f "$HTTP" >/dev/null 2>&1
docker run -d --name "$HTTP" --network "$NET" \
    -e SERVER_IP=0.0.0.0 -e IMAGE_FILE=none.img -e "WEBUI_ADDR=no-such-host.invalid:8080" \
    "$IMG" >/dev/null
up=""
for _ in $(seq 1 40); do
    if docker run --rm --network "$NET" curlimages/curl:latest -s -o /dev/null \
        --max-time 2 "http://$HTTP/health" 2>/dev/null; then up=1; break; fi
    sleep 0.5
done
[ -n "$up" ] && ok "nginx still serves PXE with an unresolvable WEBUI_ADDR" \
             || bad "nginx did not come up; an unreachable web UI took PXE down with it"
docker logs "$HTTP" 2>&1 | grep -q "Falling back to 127.0.0.1:8080" \
    && ok "the fallback was reported, not silent" \
    || bad "nothing said the address was unusable"

echo ""
echo "  passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
