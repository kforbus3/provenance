#!/bin/bash
# The machine half of the control plane, driven as a machine drives it.
#
# The server half is covered by webui/backend/tests/test_fleet_rollout.py. This
# covers the part that runs on the machine, where every mistake is expensive and
# invisible: an agent that cannot parse a directive, or forgets which server it
# was moved to, or reinstalls the same bundle on every beat, is a fleet-wide
# problem discovered one machine at a time.
#
# It runs the real ab-agent.sh, not a copy. The script's paths are overridable
# by environment for exactly this -- a harness that reimplemented the parsing
# would be testing the reimplementation.
#
#   ./scripts/test-fleet-agent.sh
set -u

AGENT="$(cd "$(dirname "$0")/.." && pwd)/builder/overlay/usr/local/sbin/ab-agent.sh"
[ -x "$AGENT" ] || { echo "not executable: $AGENT" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null' EXIT

ok=0; fail=0
pass() { ok=$((ok+1)); echo "  PASS  $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL  $1 ${2:-}"; }
check() { if [ "$2" = "$3" ]; then pass "$1"; else bad "$1" "(expected '$3', got '$2')"; fi; }

# --- a server that answers whatever the current scenario says ----------------
#
# A file rather than a fixed reply: the interesting behaviour is what the agent
# does across several beats as the answer changes, which is exactly the sequence
# a rollout puts a machine through.
mkdir -p "$WORK/srv"
echo "ok=true
action=none" > "$WORK/srv/reply"
: > "$WORK/srv/requests"

python3 - "$WORK" <<'PY' &
import http.server, sys, urllib.parse
work = sys.argv[1]

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length") or 0)).decode()
        with open(f"{work}/srv/requests", "a") as f:
            f.write(f"{self.path}\t{body}\t{self.headers.get('x-flipside-agent-token','')}\n")
        reply = open(f"{work}/srv/reply").read().encode()
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)
    def log_message(self, *a): pass

srv = http.server.HTTPServer(("127.0.0.1", 0), H)
with open(f"{work}/srv/port", "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
PY
SERVER_PID=$!

for _ in $(seq 1 50); do [ -s "$WORK/srv/port" ] && break; sleep 0.1; done
[ -s "$WORK/srv/port" ] || { echo "the stub server never came up" >&2; exit 1; }
PORT="$(cat "$WORK/srv/port")"
BASE="http://127.0.0.1:$PORT"

# --- a machine's worth of files ---------------------------------------------
mkdir -p "$WORK/boot" "$WORK/lib"
printf '%s\n' "1.0" > "$WORK/lib/version"
cat > "$WORK/update-stub" <<EOF
#!/bin/sh
# Stands in for ab-update.sh. Records the URL it was told to install and obeys
# \$WORK/update-rc so a failing install can be exercised too.
echo "\$1" >> "$WORK/installed"
exit "\$(cat "$WORK/update-rc" 2>/dev/null || echo 0)"
EOF
chmod +x "$WORK/update-stub"

export AB_AGENT_CONF="$WORK/agent.conf"
export AB_AGENT_STATE_DIR="$WORK/state"
export AB_AGENT_MARKER="$WORK/boot/ab-deploy.json"
export AB_AGENT_VERSION_FILE="$WORK/lib/version"
export AB_AGENT_BOOT_DIR="$WORK/boot"
# No slot on the kernel command line until the test that needs one writes it.
printf 'BOOT_IMAGE=/vmlinuz root=LABEL=rootfs-a\n' > "$WORK/cmdline"
export AB_AGENT_CMDLINE="$WORK/cmdline"
export AB_AGENT_UPDATE_CMD="$WORK/update-stub"

# Nothing here may reboot the machine running the test suite.
mkdir -p "$WORK/bin"
for stub in shutdown wall systemctl logger; do
    printf '#!/bin/sh\necho "%s $*" >> "%s/called"\nexit 0\n' "$stub" "$WORK" > "$WORK/bin/$stub"
    chmod +x "$WORK/bin/$stub"
done
export PATH="$WORK/bin:$PATH"

field() {   # field <request-line-number> <key>
    sed -n "${1}p" "$WORK/srv/requests" | cut -f2 | tr '&' '\n' \
        | sed -n "s/^$2=//p" | python3 -c 'import sys,urllib.parse;print(urllib.parse.unquote_plus(sys.stdin.read().strip()))'
}

echo "== a machine with no configuration seeds itself from the imager's marker =="
printf '{"checkin_url":"%s/api/imaging/checkin","control_url":"%s","id":"aa:bb:cc:dd:ee:ff","hostname":"web01"}\n' \
    "$BASE" "$BASE" > "$AB_AGENT_MARKER"
"$AGENT" >/dev/null 2>&1
check "it checked in" "$(wc -l < "$WORK/srv/requests" | tr -d ' ')" "1"
check "under the id the imager gave it" "$(field 1 id)" "aa:bb:cc:dd:ee:ff"
check "reporting the version stamped into the image" "$(field 1 version)" "1.0"
check "and it wrote the server down" \
      "$(grep -c "SERVER=\"$BASE\"" "$AB_AGENT_CONF")" "1"

echo "== a marker with only the old checkin_url still yields a server =="
# Machines imaged before imager.control= existed have no control_url at all.
# Falling back to the origin of the check-in URL is what lets them appear at
# all, rather than being invisible until someone visits each one.
rm -f "$AB_AGENT_CONF"
printf '{"checkin_url":"%s/api/imaging/checkin","id":"aa:bb:cc:dd:ee:ff"}\n' "$BASE" > "$AB_AGENT_MARKER"
"$AGENT" >/dev/null 2>&1
check "an older marker still reaches the server" \
      "$(wc -l < "$WORK/srv/requests" | tr -d ' ')" "2"

echo "== the server can move the whole fleet to a different address =="
# The way out of the imaging-address trap: the machines that can still reach the
# old address are told the new one, and remember it.
printf 'ok=true\naction=none\ncontrol_url=https://flipside.example.com\n' > "$WORK/srv/reply"
"$AGENT" >/dev/null 2>&1
check "the agent adopted the advertised address" \
      "$(grep -c 'SERVER="https://flipside.example.com"' "$AB_AGENT_CONF")" "1"
# ...and having adopted it, it must not keep talking to the old one.
before="$(wc -l < "$WORK/srv/requests" | tr -d ' ')"
"$AGENT" >/dev/null 2>&1
check "and stopped reporting to the old one" \
      "$(wc -l < "$WORK/srv/requests" | tr -d ' ')" "$before"

echo "== --set-server is the manual way back =="
# Stop advertising the new address first, or the agent correctly moves straight
# back to it and the rest of this file talks to a server that does not exist.
printf 'ok=true\naction=none\n' > "$WORK/srv/reply"
"$AGENT" --set-server "$BASE" >/dev/null 2>&1
"$AGENT" >/dev/null 2>&1
check "a hand-set server takes effect" \
      "$(wc -l < "$WORK/srv/requests" | tr -d ' ')" "$((before + 1))"
"$AGENT" --set-server "ftp://nope" >/dev/null 2>&1
check "a URL that is not http(s) is refused" "$?" "1"

echo "== an offered update is installed exactly once =="
printf 'ok=true\naction=update\nbundle_url=%s/bundles/x.raucb\nversion=2.0\nrollout=r-1234\n' \
    "$BASE" > "$WORK/srv/reply"
"$AGENT" >/dev/null 2>&1
check "the bundle was installed" "$(wc -l < "$WORK/installed" | tr -d ' ')" "1"
check "from the URL the server named" \
      "$(cat "$WORK/installed")" "$BASE/bundles/x.raucb"
check "and the machine was told to reboot" \
      "$(grep -c '^shutdown -r' "$WORK/called")" "1"
# The machine has not rebooted yet, so it is still on 1.0 and the server -- which
# cannot know that -- keeps offering. Installing again would rewrite the inactive
# slot on every beat, and on a five-minute timer that is a machine that never
# stops downloading.
"$AGENT" >/dev/null 2>&1
check "a second beat before the reboot does not install again" \
      "$(wc -l < "$WORK/installed" | tr -d ' ')" "1"

echo "== after the reboot it reports the new version and goes quiet =="
printf '%s\n' "2.0" > "$AB_AGENT_VERSION_FILE"      # the reboot landed on the new slot
printf 'ok=true\naction=none\n' > "$WORK/srv/reply"
"$AGENT" >/dev/null 2>&1
last=$(wc -l < "$WORK/srv/requests" | tr -d ' ')
check "it reports the version it is actually running" "$(field "$last" version)" "2.0"
check "and is no longer claiming to be mid-update" "$(field "$last" update_state)" "idle"

echo "== a slot updated by a bundle reports the bundle's version, not the image's =="
# The image stamps /usr/lib/flipside/version at build time; a bundle's install
# hook stamps /boot/<slot>/ab-version for the slot it wrote. The second has to
# win, or a machine that has been updated keeps reporting the version it was
# originally imaged with -- every rollout containing it runs forever, and
# nothing says why.
mkdir -p "$WORK/boot/B"
printf '%s\n' "9.9-from-bundle" > "$WORK/boot/B/ab-version"
printf 'BOOT_IMAGE=/vmlinuz root=LABEL=rootfs-b rauc.slot=B quiet\n' > "$WORK/cmdline"
"$AGENT" >/dev/null 2>&1
last=$(wc -l < "$WORK/srv/requests" | tr -d ' ')
check "the per-slot stamp wins over the image's" "$(field "$last" version)" "9.9-from-bundle"
check "and the slot it came from is reported too" "$(field "$last" slot)" "B"
# A slot with no stamp -- never updated, straight from the imager -- still
# reports the image's own version rather than nothing.
rm -f "$WORK/boot/B/ab-version"
"$AGENT" >/dev/null 2>&1
last=$(wc -l < "$WORK/srv/requests" | tr -d ' ')
check "an un-updated slot falls back to the image stamp" \
      "$(field "$last" version)" "$(cat "$AB_AGENT_VERSION_FILE")"

echo "== a failed install is reported, not swallowed =="
echo 1 > "$WORK/update-rc"
printf '%s\n' "2.0" > "$AB_AGENT_VERSION_FILE"
rm -f "$AB_AGENT_STATE_DIR/agent-state"
printf 'ok=true\naction=update\nbundle_url=%s/bundles/bad.raucb\nversion=3.0\nrollout=r-9\n' \
    "$BASE" > "$WORK/srv/reply"
"$AGENT" >/dev/null 2>&1
last=$(wc -l < "$WORK/srv/requests" | tr -d ' ')
check "the failure reaches the server" "$(field "$last" update_state)" "failed"
check "naming the rollout it belonged to" "$(field "$last" update_rollout)" "r-9"
check "and the machine was not rebooted for it" \
      "$(grep -c '^shutdown -r' "$WORK/called")" "1"
echo 0 > "$WORK/update-rc"

echo "== REBOOT=manual leaves the reboot to a person =="
rm -f "$AB_AGENT_STATE_DIR/agent-state"
sed -i.bak 's/^REBOOT=.*/REBOOT=manual/' "$AB_AGENT_CONF"
printf 'ok=true\naction=update\nbundle_url=%s/bundles/y.raucb\nversion=4.0\nrollout=r-2\n' \
    "$BASE" > "$WORK/srv/reply"
"$AGENT" >/dev/null 2>&1
check "the bundle was still installed" "$(wc -l < "$WORK/installed" | tr -d ' ')" "3"
check "but nothing rebooted the machine" \
      "$(grep -c '^shutdown -r' "$WORK/called")" "1"
sed -i.bak 's/^REBOOT=.*/REBOOT=auto/' "$AB_AGENT_CONF"

echo "== the agent token is sent when one is configured =="
rm -f "$AB_AGENT_STATE_DIR/agent-state"
printf 'ok=true\naction=none\n' > "$WORK/srv/reply"
sed -i.bak 's/^TOKEN=.*/TOKEN="s3cret token"/' "$AB_AGENT_CONF"
"$AGENT" >/dev/null 2>&1
last=$(wc -l < "$WORK/srv/requests" | tr -d ' ')
# A token with a space in it is the case that breaks when the header is built
# with ${TOKEN:+-H "..."}: the quotes inside a parameter expansion are not
# re-evaluated, so curl gets the header name and the token as separate
# arguments and sends neither. Every machine then silently fails to check in.
check "the whole token arrives as one header" \
      "$(sed -n "${last}p" "$WORK/srv/requests" | cut -f3)" "s3cret token"
sed -i.bak 's/^TOKEN=.*/TOKEN=""/' "$AB_AGENT_CONF"

echo "== a server that cannot be reached is not an error worth failing over =="
"$AGENT" --set-server "http://127.0.0.1:1" >/dev/null 2>&1
"$AGENT" >/dev/null 2>&1; rc=$?
check "an unreachable server exits 1, which the unit treats as success" "$rc" "1"
"$AGENT" --set-server "$BASE" >/dev/null 2>&1

echo "== ENABLED=0 turns the agent off without uninstalling it =="
sed -i.bak 's/^ENABLED=.*/ENABLED=0/' "$AB_AGENT_CONF"
before=$(wc -l < "$WORK/srv/requests" | tr -d ' ')
"$AGENT" >/dev/null 2>&1
check "a disabled agent does not check in" \
      "$(wc -l < "$WORK/srv/requests" | tr -d ' ')" "$before"

echo
echo "$ok passed, $fail failed"
[ "$fail" -eq 0 ]
