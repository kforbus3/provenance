#!/bin/sh
# Provenance test fabric — managed host entrypoint.
#
# Starts sshd only. WireGuard is intentionally NOT configured here: the Provenance
# Terminal enrollment flow connects over SSH, generates the host's WireGuard
# keypair, brings up wg0, and registers the peer on the jump host. The
# wireguard-go binary is present for enrollment to use.
set -e

SELF_NAME="${WG_NAME:-managed}"

mkdir -p /etc/wireguard /run/sshd
umask 077

# Ensure host keys exist, then run sshd in the foreground.
ssh-keygen -A >/dev/null 2>&1 || true
echo "[${SELF_NAME}] sshd up; WireGuard provisioned on demand by enrollment"
exec /usr/sbin/sshd -D -e
