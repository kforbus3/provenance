package enrollment

import (
	"context"
	"fmt"
	"regexp"
	"strings"

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

// MigrateResult reports what the migration did, step by step, so the UI can show
// the same detail an enrollment shows.
type MigrateResult struct {
	Host     string   `json:"host"`
	From     string   `json:"from"`
	To       string   `json:"to"`
	Migrated bool     `json:"migrated"`
	Steps    []string `json:"steps"`
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
func (s *Service) MigrateLoginAccount(ctx context.Context, host *models.Host, newUser string) (*MigrateResult, error) {
	if host == nil {
		return nil, fmt.Errorf("no host")
	}
	newUser = strings.TrimSpace(newUser)
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
	// Never remove an account Provenance did not create. "root" and any account an
	// operator nominated as the bootstrap user are theirs, not ours.
	if oldUser == "root" {
		return nil, fmt.Errorf("host logs in as root; migrating would delete the host's root account")
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

		// 3) Now the old generation can go.
		conn2, derr := s.gw.DialSystemForHost(ctx, host.ID, addr, host.SSHPort, newUser)
		if derr != nil {
			return nil, fmt.Errorf("reconnect as %s on %s: %w (old account left in place)", newUser, addr, derr)
		}
		out, rerr = run(conn2.Client, "sudo sh -c "+shellQuote(retireAccountScript(oldUser)))
		conn2.Close()
		if rerr != nil || !strings.Contains(out, "RETIRE_OK") {
			// The new account works and the row has not moved yet, so the host is
			// reachable either way. Report it rather than failing the migration:
			// leftover artefacts are a cleanup problem, not an outage.
			res.Steps = append(res.Steps, "WARNING: could not fully remove "+oldUser+": "+oneLine(strings.TrimSpace(out)))
			s.log.Warn("login account migration left artefacts behind",
				"host", host.Hostname, "old", oldUser, "new", newUser, "err", orErr(rerr, out))
		} else {
			res.Steps = append(res.Steps, "removed "+oldUser+" and its sudoers/CA/sshd artefacts")
		}

		// 4) Last: point the row at the account that has now been proven to work.
		if serr := s.store.SetHostSSHUser(ctx, host.ID, newUser); serr != nil {
			return nil, fmt.Errorf("host migrated on disk but recording it failed: %w", serr)
		}
		res.Steps = append(res.Steps, "recorded ssh_user="+newUser)
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
if grep -qE '^# (Provenance|Fleet Terminal)$' /etc/ssh/sshd_config 2>/dev/null; then
  if grep -q 'TrustedUserCAKeys /etc/ssh/fleet_ca.pub' /etc/ssh/sshd_config 2>/dev/null; then
    cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.provbak-$(date +%%s)
    awk '
      /^# (Provenance|Fleet Terminal)$/ { skip=1; next }
      skip && /^(PubkeyAuthentication|TrustedUserCAKeys|AuthorizedPrincipalsFile) / { next }
      skip { skip=0 }
      { print }
    ' /etc/ssh/sshd_config > /etc/ssh/sshd_config.prov-new &&
      mv -f /etc/ssh/sshd_config.prov-new /etc/ssh/sshd_config
  fi
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
