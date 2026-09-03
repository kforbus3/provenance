#!/bin/bash
# Drive ab-update.sh with stubbed rauc/curl/df to check the streaming fallback
# and the failure diagnostics -- no bundle, no server, no machine, ~1 second.
#
# This exists because the real thing (scripts/test-update-bundle.sh) builds two
# 8 GiB images and boots them under QEMU, so it only runs nightly. The streaming
# fallback was broken for a week under that arrangement: it fired only on the
# one error a 'plain' bundle produces, so a dm-verity failure went straight to
# "update failed" with no retry, and the nightly was the only thing that knew.
# A failure mode that takes 90 minutes to observe is one nobody observes.
set -u
cd "$(dirname "$0")/.." || exit 1
T=/tmp/abu; rm -rf $T; mkdir -p $T/bin; export PATH="$T/bin:$PATH"
URL="http://example/bundles/x.raucb"
fail=0
check() { if [ "$2" = "$3" ]; then echo "  ok   $1"; else echo "  FAIL $1: got '$2' want '$3'"; fail=1; fi; }
has()   { case "$2" in *"$3"*) echo "  ok   $1";; *) echo "  FAIL $1: missing '$3'"; fail=1;; esac; }
hasnt() { case "$2" in *"$3"*) echo "  FAIL $1: unexpected '$3'"; fail=1;; *) echo "  ok   $1";; esac; }

# rauc stub: fails on a URL with $STREAM_ERR, succeeds on a local path.
mk_rauc() {
cat > $T/bin/rauc <<EOF
#!/bin/bash
case "\$2" in
  http*) echo "\$STREAM_ERR"; exit 1;;
  *)     echo "installing"; echo "  100% Installing done."; exit 0;;
esac
EOF
chmod +x $T/bin/rauc
}
mk_curl() {  # $1 = content-length, $2 = download exit code, $3 = bytes for -r 0-3
cat > $T/bin/curl <<EOF
#!/bin/bash
for a in "\$@"; do case "\$a" in -*I*) echo "Content-Length: $1"; exit 0;; esac; done
# The magic-byte probe. Empty (the default) stands for a server that would not
# answer a range request: ab-update cannot tell, so it must not refuse.
for a in "\$@"; do case "\$a" in -r) printf '%s' '${3-}'; exit 0;; esac; done
# A download writes the file named by -o, so the same probe can read it back.
o=""; p=""
for a in "\$@"; do
    [ "\$p" = "-o" ] && o="\$a"
    p="\$a"
done
[ -n "\$o" ] && printf '%s' '${3-}' > "\$o"
exit $2
EOF
chmod +x $T/bin/curl
}
mk_df() {    # $1 = free KiB
cat > $T/bin/df <<EOF
#!/bin/sh
echo "Filesystem 1024-blocks Used Available Capacity Mounted"
echo "/dev/x 100000000 0 $1 1% /var/tmp"
EOF
chmod +x $T/bin/df
}

echo "== 1. dm-verity streaming failure: fallback fires, install succeeds =="
mk_rauc; mk_curl 367001600 0; mk_df 100000000
export STREAM_ERR="LastError: Failed mounting bundle: Failed to load dm table: Argument list too long"
out=$(bash builder/overlay/usr/local/sbin/ab-update.sh "$URL" 2>&1); rc=$?
check "exit 0" "$rc" "0"
has   "fallback announced" "$out" "Streaming the update failed"
has   "reports success"    "$out" "Reboot to switch slots"

echo "== 2. legacy 'plain' streaming refusal still falls back =="
export STREAM_ERR="Bundle format 'plain' not supported in streaming mode"
out=$(bash builder/overlay/usr/local/sbin/ab-update.sh "$URL" 2>&1); rc=$?
check "exit 0" "$rc" "0"
has   "fallback announced" "$out" "Streaming the update failed"

echo "== 3. not enough space: says so, does not download =="
mk_curl 367001600 0; mk_df 1000          # ~1 MiB free, bundle 350 MiB
export STREAM_ERR="LastError: Failed mounting bundle: Failed to load dm table"
out=$(bash builder/overlay/usr/local/sbin/ab-update.sh "$URL" 2>&1); rc=$?
check "nonzero exit" "$([ $rc -ne 0 ] && echo yes)" "yes"
has   "explains space" "$out" "Not enough room in /var/tmp"
has   "names the size" "$out" "350 MiB"

echo "== 4. diagnostics match the error: verity =="
has "streaming hint shown" "$out" "This is a streaming problem"
hasnt "no bogus key hint"  "$out" "trust problem"

echo "== 5. diagnostics match the error: bad signature =="
mk_curl 367001600 1; mk_df 100000000     # download also fails
export STREAM_ERR="Failed to verify signature: certificate verification failed"
out=$(bash builder/overlay/usr/local/sbin/ab-update.sh "$URL" 2>&1); rc=$?
has   "trust hint shown"     "$out" "trust problem"
hasnt "no bogus verity hint" "$out" "This is a streaming problem"
has   "quotes real error"    "$out" "certificate verification failed"

echo "== 6. streaming works: no fallback, no download =="
cat > $T/bin/rauc <<'EOF'
#!/bin/bash
echo "  100% Installing done."; exit 0
EOF
chmod +x $T/bin/rauc
out=$(bash builder/overlay/usr/local/sbin/ab-update.sh "$URL" 2>&1); rc=$?
check "exit 0" "$rc" "0"
hasnt "no fallback" "$out" "Streaming the update failed"

echo "== 7. the URL answers with HTML: refuse before rauc sees it =="
# The web UI's SPA returns its front page for any unknown path, so a bundle URL
# on the wrong port downloads a React app under a .raucb name. RAUC read the
# last eight bytes of that page as the signature size and reported a corrupt
# bundle, which sent the first person to read it looking at signing keys.
mk_rauc; mk_df 100000000
mk_curl 4096 0 '<!DOCTYPE html>'
export STREAM_ERR="should not get this far"
out=$(bash builder/overlay/usr/local/sbin/ab-update.sh "http://server:8080/bundles/x.raucb" 2>&1); rc=$?
check "exit 4"            "$rc" "4"
has   "says not a bundle" "$out" "is not a RAUC bundle"
has   "names the port"    "$out" "Port 8080 is the web UI"
hasnt "rauc not invoked"  "$out" "installing"

echo "== 8. a real bundle passes the check =="
mk_curl 367001600 0 'hsqs'
export STREAM_ERR="LastError: Failed to load dm table"
out=$(bash builder/overlay/usr/local/sbin/ab-update.sh "$URL" 2>&1); rc=$?
check "exit 0"            "$rc" "0"
has   "fallback still ok" "$out" "Streaming the update failed"

echo "== 9. a server that will not answer the probe does not block the update =="
# Cannot-tell must not be treated as no. A server without range support, or a
# machine without curl, would otherwise refuse an update that works.
mk_curl 367001600 0 ''
out=$(bash builder/overlay/usr/local/sbin/ab-update.sh "$URL" 2>&1); rc=$?
check "exit 0"           "$rc" "0"
hasnt "no bogus refusal" "$out" "is not a RAUC bundle"

echo
[ "$fail" = 0 ] && echo "ALL PASS" || echo "FAILURES"
exit $fail
