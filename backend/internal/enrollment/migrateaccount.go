package enrollment

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/kforbus3/provenance/backend/internal/controlplane"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// The rename moved the default managed-host account from "fleet" to "prov". Hosts
// enrolled before it keep the account they have — hosts.ssh_user names the account
// that actually exists on the host, and rewriting that row without touching the
// host would point the backend at an account sshd has never heard of.
//
// Moving a host across is therefore a deliberate operation performed over SSH, and
// this is it. It is not specific to the rename: it takes any target account name,
// so an operator who wants a different one gets the same verified path.

// accountName bounds what may be passed to useradd/userdel on a managed host.
// The value is interpolated into a root shell script, so this is a security
// boundary, not a nicety. POSIX portable username charset, plus a length cap.
var accountName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)

// MigrateOptions controls how far the migration goes.
type MigrateOptions struct {
	// User is the account to move to. Empty means the current default.
	User string `json:"user"`
	// RemoveOld deletes the superseded account and its on-host artefacts.
	//
	// DEFAULT FALSE, deliberately. Creating an account is reversible and deleting
	// one is not, and the two failure modes are not comparable: an extra idle
	// account is untidy, while a deleted one can take an operator's own access with
	// it. Retiring is a separate, explicit pass run after the fleet is verified
	// healthy on the new account.
	RemoveOld bool `json:"removeOld"`
	// ConfirmControlPlane is required to touch a host that Provenance's own access
	// depends on. Without it such a host is refused.
	ConfirmControlPlane bool `json:"confirmControlPlane"`
}

// MigrateResult reports what the migration did, step by step, so the UI can show
// the same detail an enrollment shows.
type MigrateResult struct {
	Host     string `json:"host"`
	From     string `json:"from"`
	To       string `json:"to"`
	Migrated bool   `json:"migrated"`
	// OldAccountLeft is true when the superseded account is still on the host,
	// because RemoveOld was not set. The caller needs to know the host is not
	// finished, not just that nothing failed.
	OldAccountLeft bool     `json:"oldAccountLeft"`
	Steps          []string `json:"steps"`
}

// MigrateLoginAccount moves a host from its current Provenance login account to
// newUser, together with the on-disk artefacts that carry the old product name.
//
// The ordering is the entire design, because the connection performing the
// migration is authenticated AS the account being replaced:
//
//  1. create and trust the new accounts ALONGSIDE the existing ones;
//  2. prove a fresh certificate login as the new account actually works;
//  3. only then remove the old accounts and their sudoers/CA/sshd artefacts;
//  4. persist hosts.ssh_user last.
//
// A failure at any step leaves the host exactly as it was, still reachable through
// the account the row names. The one thing never done is removing the bridge
// before standing on the far bank.
func (s *Service) MigrateLoginAccount(ctx context.Context, host *models.Host, opts MigrateOptions) (*MigrateResult, error) {
	if host == nil {
		return nil, fmt.Errorf("no host")
	}
	newUser := strings.TrimSpace(opts.User)
	if newUser == "" {
		newUser = "prov"
	}
	if !accountName.MatchString(newUser) {
		return nil, fmt.Errorf("invalid account name %q: must match %s", newUser, accountName)
	}
	oldUser := strings.TrimSpace(host.SSHUser)
	if oldUser == "" {
		oldUser = "prov"
	}
	res := &MigrateResult{Host: host.Hostname, From: oldUser, To: newUser}
	if oldUser == newUser {
		res.Steps = append(res.Steps, "already on "+newUser+"; nothing to do")
		return res, nil
	}
	// Never remove an account Provenance did not create. The migration's last step
	// deletes the old account outright, so this is the difference between retiring
	// our own account and deleting the operator's.
	//
	// "root" is the obvious case, but not the only one: a host enrolled against an
	// existing account (coreswitch logs in as "admin") would have had that account
	// deleted. Allow only the names enrollment itself creates -- the current default
	// and the one it had before the rename.
	if !provenanceManagedAccount(oldUser) {
		return nil, fmt.Errorf("host logs in as %q, which Provenance did not create; "+
			"migrating would delete that account. Change the host's SSH user first if this is wrong", oldUser)
	}

	// A host Provenance's own access depends on -- the jump host, the machine the
	// stack runs on, anything tagged control-plane -- is refused unless the caller
	// says so explicitly. This is the guard that was missing: a bulk sweep included
	// the Provenance host, replaced its login account, and deleted the account its
	// operators connect with. controlplane.Is is the same check scan remediation
	// uses, not a second implementation of it.
	if controlplane.Is(host, s.cfg) && !opts.ConfirmControlPlane {
		return nil, fmt.Errorf("%s is part of Provenance's own control plane; "+
			"migrating its login account can sever access to the whole fleet. "+
			"Confirm explicitly for this host, one at a time, with a way back in that "+
			"does not depend on Provenance", host.Hostname)
	}

	caKeys, err := s.store.ListActiveCAPublicKeys(ctx, "user")
	if err != nil || len(caKeys) == 0 {
		return nil, fmt.Errorf("no active user CA: %w", orErr(err, "none returned"))
	}

	var lastErr error
	for _, addr := range dedupeAddrs(host.WGAddress, host.Address, host.Hostname) {
		conn, derr := s.gw.DialSystemForHost(ctx, host.ID, addr, host.SSHPort, oldUser)
		if derr != nil {
			lastErr = fmt.Errorf("%s: %w", addr, derr)
			continue
		}
		priv := func(script string) (string, error) {
			return run(conn.Client, "sudo sh -c "+shellQuote(script))
		}

		// 1) Create and trust the new accounts. caTrustScript is idempotent and
		// writes only the new-generation artefacts, so the old ones are untouched
		// and the current session keeps working throughout.
		out, rerr := priv(s.caTrustScript(newUser, strings.Join(caKeys, "\n"), host.ID))
		if rerr != nil || !strings.Contains(out, "CA_OK") {
			conn.Close()
			return nil, fmt.Errorf("install trust for %s on %s: %w (%s)", newUser, addr,
				orErr(rerr, out), oneLine(strings.TrimSpace(out)))
		}
		res.Steps = append(res.Steps, "created and trusted "+newUser+" / "+newUser+"-login")
		conn.Close()

		// 2) Prove it. A separate connection, authenticating as the new account with
		// a freshly minted certificate — the same check enrollment makes. Until this
		// passes, nothing is removed and nothing is written to the database.
		if _, verr := s.validateCertLogin(ctx, host.ID, host.WGAddress, addr, host.SSHPort, newUser); verr != nil {
			return nil, fmt.Errorf("verify certificate login as %s on %s: %w (old account left in place)",
				newUser, addr, verr)
		}
		res.Steps = append(res.Steps, "verified certificate login as "+newUser)

		// 3) Record it BEFORE removing anything. The row is what makes the new
		// account reachable; until it is written the host is only reachable through
		// the old one. Doing this last meant a failed write left a host whose old
		// account was already gone and whose row still named it -- reachable by
		// nothing. ChangeHostSSHUser, not SetHostSSHUser: that one only fills a
		// blank, so it matched no rows here and reported success.
		if serr := s.store.ChangeHostSSHUser(ctx, host.ID, newUser); serr != nil {
			return nil, fmt.Errorf("%s now has a working %q account but recording it FAILED: %w. "+
				"Nothing was removed, so the host is still reachable as %q",
				host.Hostname, newUser, serr, oldUser)
		}
		res.Steps = append(res.Steps, "recorded ssh_user="+newUser)

		// 4) Retiring the old account is opt-in, and deliberately not the default:
		// creating an account is reversible and deleting one is not.
		if !opts.RemoveOld {
			res.OldAccountLeft = true
			res.Steps = append(res.Steps, "left "+oldUser+" in place (retire it separately once the fleet is verified)")
			res.Migrated = true
			s.log.Info("adopted new host login account", "host", host.Hostname,
				"from", oldUser, "to", newUser, "addr", addr, "old_account_left", true)
			return res, nil
		}
		conn2, derr := s.gw.DialSystemForHost(ctx, host.ID, addr, host.SSHPort, newUser)
		if derr != nil {
			res.OldAccountLeft = true
			res.Steps = append(res.Steps, "WARNING: could not reconnect as "+newUser+" to retire "+oldUser+"; left it in place")
			res.Migrated = true
			return res, nil
		}
		out, rerr = run(conn2.Client, "sudo sh -c "+shellQuote(retireAccountScript(oldUser)))
		conn2.Close()
		if rerr != nil || !strings.Contains(out, "RETIRE_OK") {
			res.OldAccountLeft = true
			res.Steps = append(res.Steps, "WARNING: could not fully remove "+oldUser+": "+oneLine(strings.TrimSpace(out)))
			s.log.Warn("login account migration left artefacts behind",
				"host", host.Hostname, "old", oldUser, "new", newUser, "err", orErr(rerr, out))
		} else {
			res.Steps = append(res.Steps, "removed "+oldUser+" and its sudoers/CA/sshd artefacts")
		}
		res.Migrated = true
		s.log.Info("migrated host login account", "host", host.Hostname, "from", oldUser, "to", newUser, "addr", addr)
		return res, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reachable address")
	}
	return nil, fmt.Errorf("connect to host: %w", lastErr)
}

// retireAccountScript removes a superseded Provenance login account and the
// artefacts that carried the old product name.
//
// The sshd drop-in and the appended marker block are removed BEFORE the CA file
// they reference, because `sshd -t` fails on a TrustedUserCAKeys pointing at a
// file that no longer exists — and a host whose sshd config does not validate is
// one reload away from refusing every connection.
func retireAccountScript(oldUser string) string {
	return fmt.Sprintf(`set -e
OLD='%s'
NOSUDO="${OLD}-login"

# sshd config first: it references the CA file removed further down.
rm -f /etc/ssh/sshd_config.d/00-fleet.conf
# The KRL directive is appended separately from the marker block, and on a host
# with no /etc/ssh/sshd_config.d it lands in the MAIN sshd_config, nowhere near
# that block. Leaving it while deleting the file it names passes sshd -t now and
# fails on the host's NEXT reload or reboot -- i.e. the host locks itself out long
# after this ran, with nothing to connect the two events.
sed -i '\#^RevokedKeys /etc/ssh/fleet_krl#d' /etc/ssh/sshd_config 2>/dev/null || true
for d in /etc/ssh/sshd_config.d/*.conf; do
  [ -e "$d" ] || continue
  sed -i '\#^RevokedKeys /etc/ssh/fleet_krl#d' "$d" 2>/dev/null || true
done

# Remove ONLY the directives naming the OLD CA -- never a whole marker block.
#
# A host with no sshd_config.d Include has its directives appended to the main
# sshd_config under a marker, and enrollment appended a SECOND block for the new
# CA. Stripping "the marker block" matched both and took the new trust with the
# old, leaving a host that trusts no CA at all. sshd -t cannot catch that: a
# config that trusts nothing is perfectly valid. So this edits by CA path, and the
# check below is a positive assertion rather than a syntax check.
sed -i '\#^TrustedUserCAKeys /etc/ssh/fleet_ca.pub#d' /etc/ssh/sshd_config 2>/dev/null || true
# A marker left with no directives under it is noise; drop it only if the block it
# introduced is now empty.
awk '
  /^# (Provenance|Fleet Terminal)$/ { marker=$0; next }
  marker != "" {
    if ($0 ~ /^(PubkeyAuthentication|TrustedUserCAKeys|AuthorizedPrincipalsFile|RevokedKeys) /) {
      print marker; marker=""; print; next
    }
    print marker; marker=""
  }
  { print }
  END { }
' /etc/ssh/sshd_config > /etc/ssh/sshd_config.prov-new 2>/dev/null &&
  mv -f /etc/ssh/sshd_config.prov-new /etc/ssh/sshd_config

# POSITIVE assertion: the host must still trust the current CA. Checked across the
# main config AND the drop-ins, because either may carry it.
if ! { grep -qs "^TrustedUserCAKeys /etc/ssh/prov_ca.pub" /etc/ssh/sshd_config ||
       grep -qsr "^TrustedUserCAKeys /etc/ssh/prov_ca.pub" /etc/ssh/sshd_config.d/ ; }; then
  echo "[prov] CA trust for /etc/ssh/prov_ca.pub is missing after cleanup; restoring it"
  { echo ''; echo '# Provenance'; echo 'PubkeyAuthentication yes';
    echo 'TrustedUserCAKeys /etc/ssh/prov_ca.pub';
    echo 'AuthorizedPrincipalsFile /etc/ssh/auth_principals/%%u'; } >> /etc/ssh/sshd_config
fi

# Validate before reloading. A config that does not parse must not be activated.
if ! sshd -t 2>/dev/null; then
  echo "[prov] sshd -t failed after removing the old block; leaving everything in place"
  exit 1
fi
( systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || \
  service sshd reload 2>/dev/null || service ssh reload 2>/dev/null || pkill -HUP sshd 2>/dev/null ) || true

rm -f /etc/ssh/fleet_ca.pub /etc/ssh/fleet_krl
rm -f /etc/sudoers.d/fleet
rm -f /etc/ssh/auth_principals/"$OLD" /etc/ssh/auth_principals/"$NOSUDO"

# The accounts. userdel refuses while a process of theirs is running; this
# connection belongs to the NEW account, so the old one should be idle.
for U in "$NOSUDO" "$OLD"; do
  id "$U" >/dev/null 2>&1 || continue
  pkill -u "$U" 2>/dev/null || true
  userdel -r "$U" 2>/dev/null || deluser --remove-home "$U" 2>/dev/null || userdel "$U" 2>/dev/null || \
    echo "[prov] WARNING: could not remove account $U"
done

# Any remaining state directory from the old name.
rm -rf /etc/fleet
echo RETIRE_OK`, oldUser)
}

// provenanceManagedAccount reports whether an account name is one enrollment
// creates itself, and may therefore be retired by a migration.
//
// Deliberately a fixed list rather than "anything that is not root": the point is
// to delete only accounts we made. An operator-nominated account looks identical
// on the wire and is not ours to remove.
func provenanceManagedAccount(name string) bool {
	switch name {
	case "prov", "fleet":
		return true
	}
	return false
}
