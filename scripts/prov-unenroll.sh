#!/bin/sh
# Provenance — remove Provenance's footprint from a managed host.
#
# Run this ON THE HOST, as root, when Provenance could not tear the host down itself:
# the host was already unreachable when it was deleted, it was removed from the
# database directly, or it was enrolled by a Provenance deployment that no longer exists.
#
#   sudo sh prov-unenroll.sh              # default account name ("fleet")
#   sudo sh prov-unenroll.sh -u ops       # host was enrolled with a different SSH user
#   sudo sh prov-unenroll.sh --dry-run    # print what would be removed, change nothing
#
# What it removes: the NOPASSWD sudoers grant, both shared accounts (and their home
# directories), the trusted CA, the certificate principal files, the sshd drop-in,
# and the revocation list. It also removes whichever overlay client Provenance
# provisioned — the WireGuard interface and its keys, or the OpenVPN client and its
# certificate material.
#
# Removing the host's copy of an OpenVPN certificate does not REVOKE it. If the key
# may have been copied off this host, delete the host in Provenance with teardown ticked
# as well, which revokes it and republishes the server's CRL.
#
# What it does NOT touch: authorized_keys, any other sudoers file, and any sshd
# configuration Provenance did not write. sshd is reloaded only if `sshd -t` still passes.
#
# Removing the accounts ends any session running as them — including yours, if you
# connected through Provenance. Run it from a login you control (console, or a key in your
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
WG_IF="${PROV_WG_INTERFACE:-wgprov}"

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

say() { echo "[prov] $*"; }
do_() {
	if [ "$DRY" -eq 1 ]; then echo "[dry-run] $*"; else "$@"; fi
}

say "removing Provenance's footprint (accounts: $LOGIN, $NOSUDO)"

# 1. The sudoers grant and the SSH trust material. Both generations of names: a
#    host enrolled before the product was renamed carries the fleet_* spellings,
#    and leaving those would leave a TRUSTED CA and a NOPASSWD sudoers entry on a
#    host the operator believes they have just unenrolled.
for f in \
	/etc/sudoers.d/prov \
	/etc/sudoers.d/fleet \
	/etc/ssh/prov_ca.pub \
	/etc/ssh/prov_krl \
	/etc/ssh/fleet_ca.pub \
	/etc/ssh/fleet_krl \
	/etc/ssh/auth_principals/"$LOGIN" \
	/etc/ssh/auth_principals/"$NOSUDO" \
	/etc/ssh/sshd_config.d/00-prov.conf \
	/etc/ssh/sshd_config.d/00-fleet.conf
do
	[ -e "$f" ] || continue
	do_ rm -f "$f" && say "removed $f"
done
if [ -d /etc/ssh/auth_principals ]; then
	do_ rmdir /etc/ssh/auth_principals 2>/dev/null && say "removed empty /etc/ssh/auth_principals"
fi

# 1b. The KRL directive. It is appended separately from the marker block, and on a
#    host with no /etc/ssh/sshd_config.d it lands in the main sshd_config. Removing
#    the KRL file above while a directive still names it leaves an sshd that fails
#    its next reload -- long after this script ran.
if grep -qE '^RevokedKeys /etc/ssh/(prov|fleet)_krl' /etc/ssh/sshd_config 2>/dev/null; then
	if [ "$DRY" -eq 1 ]; then
		echo "[dry-run] would remove the RevokedKeys directive from /etc/ssh/sshd_config"
	else
		sed -i -E '\#^RevokedKeys /etc/ssh/(prov|fleet)_krl#d' /etc/ssh/sshd_config &&
			say "removed the RevokedKeys directive from /etc/ssh/sshd_config"
	fi
fi

# 2. Hosts whose sshd_config has no Include got the directives appended under a
#    marker. Drop exactly that block and nothing else. Either marker: the one on
#    disk is whichever release enrolled this host ("# Fleet Terminal" before the
#    rename, "# Provenance" after).
if grep -qE '^# (Provenance|Fleet Terminal)$' /etc/ssh/sshd_config 2>/dev/null; then
	if [ "$DRY" -eq 1 ]; then
		echo "[dry-run] would remove the '# Provenance' block from /etc/ssh/sshd_config"
	else
		cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.prov-backup
		awk '
			/^# (Provenance|Fleet Terminal)$/ { skip=1; next }
			skip && /^(PubkeyAuthentication|TrustedUserCAKeys|AuthorizedPrincipalsFile) / { next }
			skip { skip=0 }
			{ print }
		' /etc/ssh/sshd_config.prov-backup > /etc/ssh/sshd_config.prov-new &&
			mv -f /etc/ssh/sshd_config.prov-new /etc/ssh/sshd_config &&
			say "removed the Provenance block from /etc/ssh/sshd_config (backup: sshd_config.prov-backup)"
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
	rm -f /etc/ssh/sshd_config.prov-backup
else
	say "WARNING: 'sshd -t' failed after cleanup — sshd NOT reloaded"
	if [ -f /etc/ssh/sshd_config.prov-backup ]; then
		mv -f /etc/ssh/sshd_config.prov-backup /etc/ssh/sshd_config
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

# 5. The WireGuard overlay, if Provenance created one. Config and key material are
#    removed: this is a decommission, not a transport switch, so there is no later
#    membership for the host's old identity to be recovered for.
if [ -e "/etc/wireguard/$WG_IF.conf" ] || ip link show "$WG_IF" >/dev/null 2>&1; then
	if [ "$DRY" -eq 1 ]; then
		echo "[dry-run] would bring down $WG_IF and remove its config and keys"
	else
		command -v systemctl >/dev/null 2>&1 && {
			systemctl disable --now "wg-quick@$WG_IF" >/dev/null 2>&1
			systemctl disable --now prov-wg-reresolve.timer >/dev/null 2>&1
		}
		command -v wg-quick >/dev/null 2>&1 && wg-quick down "$WG_IF" >/dev/null 2>&1
		ip link show "$WG_IF" >/dev/null 2>&1 && ip link delete "$WG_IF" >/dev/null 2>&1
		# Removed, not renamed. A renamed config plus the private key beside it is a
		# working tunnel definition left on a machine nothing manages any more; the
		# hub no longer lists the peer, but the credential should not outlive the
		# host's membership either.
		rm -f "/etc/wireguard/$WG_IF.conf" "/etc/wireguard/$WG_IF.conf.prov-disabled"
		rm -f "/etc/wireguard/$WG_IF.privatekey" "/etc/wireguard/$WG_IF.publickey"
		rm -f /etc/systemd/system/prov-wg-reresolve.service \
		      /etc/systemd/system/prov-wg-reresolve.timer
		command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1
		say "removed WireGuard interface $WG_IF and its key material"
	fi
fi

# 6. The certificate overlay (OpenVPN), if Provenance provisioned one. Unlike WireGuard —
#    where the hub's peer list is an allowlist, so removing the peer is itself the
#    revocation — an OpenVPN client authenticates with a certificate the server
#    accepts on its own merits. Everything needed to reconnect lives in one
#    directory, so it is removed outright rather than renamed.
#
#    NOTE: this destroys the host's COPY. It does not revoke the certificate. If the
#    key may have been taken off this host, revoke it in Provenance (deleting the host with
#    teardown does) so the server's CRL refuses it.
if [ -d /etc/openvpn/prov ] || [ -e /etc/openvpn/prov-overlay.conf ] || [ -e /etc/openvpn/client/prov-overlay.conf ]; then
	if [ "$DRY" -eq 1 ]; then
		echo "[dry-run] would stop the openvpn client and remove /etc/openvpn/prov"
	else
		command -v systemctl >/dev/null 2>&1 && {
			systemctl disable --now openvpn@prov-overlay >/dev/null 2>&1
			systemctl disable --now openvpn-client@prov-overlay >/dev/null 2>&1
		}
		for _p in $(pgrep -x openvpn 2>/dev/null); do
			if tr '\0' ' ' < "/proc/$_p/cmdline" 2>/dev/null | grep -qF -- '/etc/openvpn/prov/client.ovpn'; then
				kill "$_p" 2>/dev/null
			fi
		done
		rm -f /run/prov-ovpn-client.pid
		rm -f /etc/openvpn/prov/ca.crt /etc/openvpn/prov/client.crt /etc/openvpn/prov/client.key \
		      /etc/openvpn/prov/client.ovpn /etc/openvpn/prov/client.ovpn.prov-disabled \
		      /etc/openvpn/prov/peer-isolation.sh
		rm -f /etc/openvpn/prov-overlay.conf /etc/openvpn/prov-overlay.conf.prov-disabled \
		      /etc/openvpn/client/prov-overlay.conf /etc/openvpn/client/prov-overlay.conf.prov-disabled
		rmdir /etc/openvpn/prov 2>/dev/null
		# The peer-isolation chains go with it; they are scoped to the tunnel device,
		# and tun0 is a name the kernel reuses for the next VPN this host runs.
		if command -v iptables >/dev/null 2>&1; then
			for _pair in "INPUT PROV-OVPN-IN" "OUTPUT PROV-OVPN-OUT"; do
				set -- $_pair
				_chain=$1; _own=$2
				_n=0
				while [ $_n -lt 20 ]; do
					_rule=$(iptables -S "$_chain" 2>/dev/null | grep -m1 -- "-j $_own" | sed "s/^-A $_chain //")
					[ -n "$_rule" ] || break
					iptables -D "$_chain" $_rule 2>/dev/null || break
					_n=$((_n+1))
				done
				iptables -F "$_own" 2>/dev/null
				iptables -X "$_own" 2>/dev/null
			done
		fi
		say "removed the openvpn overlay client and its certificate material"
		if [ -e /etc/openvpn/prov ]; then
			say "NOTE: /etc/openvpn/prov still holds files Provenance did not write; left in place"
		fi
	fi
fi

do_ rm -f /usr/local/sbin/prov-unenroll.sh
say "done"
