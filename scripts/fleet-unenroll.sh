#!/bin/sh
# Fleet Terminal — remove Fleet's footprint from a managed host.
#
# Run this ON THE HOST, as root, when Fleet could not tear the host down itself:
# the host was already unreachable when it was deleted, it was removed from the
# database directly, or it was enrolled by a Fleet deployment that no longer exists.
#
#   sudo sh fleet-unenroll.sh              # default account name ("fleet")
#   sudo sh fleet-unenroll.sh -u ops       # host was enrolled with a different SSH user
#   sudo sh fleet-unenroll.sh --dry-run    # print what would be removed, change nothing
#
# What it removes: the NOPASSWD sudoers grant, both shared accounts (and their home
# directories), the trusted CA, the certificate principal files, the sshd drop-in,
# and the revocation list. It also retires the WireGuard interface if Fleet created
# one.
#
# What it does NOT touch: authorized_keys, any other sudoers file, and any sshd
# configuration Fleet did not write. sshd is reloaded only if `sshd -t` still passes.
#
# Removing the accounts ends any session running as them — including yours, if you
# connected through Fleet. Run it from a login you control (console, or a key in your
# own authorized_keys).
set -u

# Byte-wise collation. Under many locales a bracket range like [a-z] also matches
# uppercase, which let "Bad" through the login-name check below — and makes awk's
# and grep's matching depend on the host's locale, which is not something a cleanup
# script should vary by.
LC_ALL=C
export LC_ALL

LOGIN=fleet
DRY=0
WG_IF="${FLEET_WG_INTERFACE:-wgfleet}"

# Print the leading comment block (everything before the first non-comment line).
usage() {
	awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"
	exit "${1:-0}"
}

while [ $# -gt 0 ]; do
	case "$1" in
		-u|--user) LOGIN="${2:?-u needs an account name}"; shift 2 ;;
		-i|--wg-interface) WG_IF="${2:?-i needs an interface name}"; shift 2 ;;
		-n|--dry-run) DRY=1; shift ;;
		-h|--help) usage 0 ;;
		*) echo "unknown argument: $1" >&2; usage 1 ;;
	esac
done

# Reject anything that is not a portable login name. Note `*` in a shell glob is
# standalone, not a quantifier on the preceding bracket — so the check has to be
# written as "contains a character outside the set", not "[a-z_][a-z0-9_-]*".
case "$LOGIN" in
	''|*[!a-z0-9_-]*|[!a-z_]*)
		echo "refusing: '$LOGIN' is not a valid login name ([a-z_][a-z0-9_-]*)" >&2
		exit 1 ;;
esac
NOSUDO="${LOGIN}-login"

if [ "$DRY" -eq 0 ] && [ "$(id -u)" != 0 ]; then
	echo "must run as root (try: sudo sh $0)" >&2
	exit 1
fi

say() { echo "[fleet] $*"; }
do_() {
	if [ "$DRY" -eq 1 ]; then echo "[dry-run] $*"; else "$@"; fi
}

say "removing Fleet's footprint (accounts: $LOGIN, $NOSUDO)"

# 1. The sudoers grant and the SSH trust material.
for f in \
	/etc/sudoers.d/fleet \
	/etc/ssh/fleet_ca.pub \
	/etc/ssh/fleet_krl \
	/etc/ssh/auth_principals/"$LOGIN" \
	/etc/ssh/auth_principals/"$NOSUDO" \
	/etc/ssh/sshd_config.d/00-fleet.conf
do
	[ -e "$f" ] || continue
	do_ rm -f "$f" && say "removed $f"
done
if [ -d /etc/ssh/auth_principals ]; then
	do_ rmdir /etc/ssh/auth_principals 2>/dev/null && say "removed empty /etc/ssh/auth_principals"
fi

# 2. Hosts whose sshd_config has no Include got the directives appended under a
#    "# Fleet Terminal" marker. Drop exactly that block and nothing else.
if grep -q '^# Fleet Terminal$' /etc/ssh/sshd_config 2>/dev/null; then
	if [ "$DRY" -eq 1 ]; then
		echo "[dry-run] would remove the '# Fleet Terminal' block from /etc/ssh/sshd_config"
	else
		cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.fleet-backup
		awk '
			/^# Fleet Terminal$/ { skip=1; next }
			skip && /^(PubkeyAuthentication|TrustedUserCAKeys|AuthorizedPrincipalsFile) / { next }
			skip { skip=0 }
			{ print }
		' /etc/ssh/sshd_config.fleet-backup > /etc/ssh/sshd_config.fleet-new &&
			mv -f /etc/ssh/sshd_config.fleet-new /etc/ssh/sshd_config &&
			say "removed the Fleet block from /etc/ssh/sshd_config (backup: sshd_config.fleet-backup)"
	fi
fi

# 3. Reload sshd only if what remains is valid — a host whose config is broken keeps
#    the sshd it is already running rather than being cut off by this cleanup.
if [ "$DRY" -eq 1 ]; then
	echo "[dry-run] would validate with 'sshd -t' and reload sshd"
elif sshd -t 2>/dev/null; then
	systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || \
		service sshd reload 2>/dev/null || service ssh reload 2>/dev/null || pkill -HUP sshd 2>/dev/null
	say "sshd reloaded"
	rm -f /etc/ssh/sshd_config.fleet-backup
else
	say "WARNING: 'sshd -t' failed after cleanup — sshd NOT reloaded"
	if [ -f /etc/ssh/sshd_config.fleet-backup ]; then
		mv -f /etc/ssh/sshd_config.fleet-backup /etc/ssh/sshd_config
		say "restored /etc/ssh/sshd_config from the backup; inspect it before reloading"
	fi
fi

# 4. The shared accounts. Any process still running as them has to go first, or
#    userdel refuses and the account survives with its sudo grant already removed.
for U in "$LOGIN" "$NOSUDO"; do
	id "$U" >/dev/null 2>&1 || { say "no account $U"; continue; }
	if [ "$DRY" -eq 1 ]; then
		echo "[dry-run] would kill processes owned by $U and remove the account"
		continue
	fi
	pkill -KILL -u "$U" 2>/dev/null
	sleep 1
	userdel -r "$U" 2>/dev/null || deluser --remove-home "$U" 2>/dev/null || userdel "$U" 2>/dev/null
	if id "$U" >/dev/null 2>&1; then
		say "WARNING: could not remove account $U — remove it by hand"
	else
		say "removed account $U"
	fi
done

# 5. The WireGuard overlay, if Fleet created one. The config is renamed rather than
#    deleted so the host's old identity is recoverable and visible to an operator.
if [ -e "/etc/wireguard/$WG_IF.conf" ] || ip link show "$WG_IF" >/dev/null 2>&1; then
	if [ "$DRY" -eq 1 ]; then
		echo "[dry-run] would bring down and disable $WG_IF"
	else
		command -v systemctl >/dev/null 2>&1 && {
			systemctl disable --now "wg-quick@$WG_IF" >/dev/null 2>&1
			systemctl disable --now fleet-wg-reresolve.timer >/dev/null 2>&1
		}
		command -v wg-quick >/dev/null 2>&1 && wg-quick down "$WG_IF" >/dev/null 2>&1
		ip link show "$WG_IF" >/dev/null 2>&1 && ip link delete "$WG_IF" >/dev/null 2>&1
		[ -f "/etc/wireguard/$WG_IF.conf" ] && \
			mv -f "/etc/wireguard/$WG_IF.conf" "/etc/wireguard/$WG_IF.conf.fleet-disabled"
		say "retired WireGuard interface $WG_IF"
	fi
fi

do_ rm -f /usr/local/sbin/fleet-unenroll.sh
say "done"
