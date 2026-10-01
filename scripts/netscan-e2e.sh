#!/bin/sh
# End-to-end check of the network scanner against a target it MUST find things on.
#
# Starts the net-scanner sidecar and the deliberately weak target
# (deploy/testfabric/weak) on a private Docker network, installs nuclei templates,
# scans the target, and fails unless every planted weakness is reported. It also
# scans an address nothing answers on, which must come back "unreachable" -- never
# "reachable, no findings".
#
# Needs Docker and, unless NETSCAN_TEMPLATES_TGZ points at an offline templates
# archive, internet access for the template download.
set -eu
cd "$(dirname "$0")/.."
NET=prov-netscan-e2e
TOKEN=e2e-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
cleanup() {
  docker rm -f netscan-e2e-scanner netscan-e2e-weak >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker build -q -t provenance-net-scanner:e2e deploy/net-scanner >/dev/null
docker build -q -t prov-weak-target:e2e deploy/testfabric/weak >/dev/null
docker network create --subnet 172.31.240.0/24 "$NET" >/dev/null
docker run -d --name netscan-e2e-weak --network "$NET" --ip 172.31.240.40 prov-weak-target:e2e >/dev/null
docker run -d --name netscan-e2e-scanner --network "$NET" --ip 172.31.240.2 \
  -e NETSCAN_TOKEN="$TOKEN" -p 127.0.0.1::8001 provenance-net-scanner:e2e >/dev/null

PORT=$(docker port netscan-e2e-scanner 8001/tcp | head -1 | sed 's/.*://')
URL="http://127.0.0.1:$PORT"
# The API binds the container-network address, so it is published through the
# Docker proxy on that address; wait for it.
i=0; until curl -fsS "$URL/healthz" >/dev/null 2>&1; do i=$((i+1)); [ $i -gt 60 ] && { echo "scanner never came up"; docker logs netscan-e2e-scanner; exit 1; }; sleep 1; done

if [ -n "${NETSCAN_TEMPLATES_TGZ:-}" ]; then
  curl -fsS -H "X-Netscan-Token: $TOKEN" --data-binary @"$NETSCAN_TEMPLATES_TGZ" "$URL/templates/import" >/dev/null
else
  curl -fsS -m 900 -X POST -H "X-Netscan-Token: $TOKEN" "$URL/templates/update" >/dev/null
fi

echo "scanning the weak target (full TCP range; takes a couple of minutes)..."
curl -fsS -m 1800 -H "X-Netscan-Token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target":"172.31.240.40","tcpPorts":"full","udp":true}' "$URL/scan" > /tmp/netscan-e2e.json

python3 - /tmp/netscan-e2e.json <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
ids = {f["templateId"] for f in r["findings"]}
ports = set(r["openPorts"])
print("open ports:", sorted(ports))
print("findings:", sorted(ids))
problems = []
if not r["reachable"]:
    problems.append("target reported unreachable")
for p in (80, 443, 6379):
    if p not in ports:
        problems.append(f"port {p} not found open")
for tid in ("exposed-redis", "deprecated-tls", "git-config"):
    if tid not in ids:
        problems.append(f"expected finding {tid} missing")
for f in r["findings"]:
    if any(t in f.get("tags", []) for t in ("bruteforce", "default-login", "dos", "intrusive")):
        problems.append(f"excluded check ran: {f['templateId']}")
if problems:
    print("FAIL:", *problems, sep="\n  ")
    sys.exit(1)
print("weak target: OK")
PY

echo "scanning an address nothing answers on..."
curl -fsS -m 600 -H "X-Netscan-Token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target":"172.31.240.99","tcpPorts":[22,80,443],"aliveProbePorts":[22]}' "$URL/scan" > /tmp/netscan-e2e-dark.json
python3 - /tmp/netscan-e2e-dark.json <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
if r["reachable"]:
    print("FAIL: a dark address was reported reachable:", r); sys.exit(1)
print("dark address: unreachable (%s): OK" % r["reason"])
PY
