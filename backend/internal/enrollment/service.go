// Package enrollment automates onboarding a managed host: it provisions the
// WireGuard tunnel (peer on the jump host + interface on the managed host),
// brings the interface up, collects host facts, and records the result. The
// host's WireGuard private key is generated on the host and never leaves it.
package enrollment

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/krl"
	"github.com/fleet-terminal/backend/internal/models"
	princ "github.com/fleet-terminal/backend/internal/principals"
	"github.com/fleet-terminal/backend/internal/sshgw"
	"github.com/fleet-terminal/backend/internal/store"

	"log/slog"

	"github.com/google/uuid"
)

// Service performs host enrollment over SSH.
type Service struct {
	store *store.Store
	cfg   *config.Config
	log   *slog.Logger
	gw    *sshgw.Gateway
}

// New constructs the enrollment Service.
func New(st *store.Store, cfg *config.Config, log *slog.Logger, gw *sshgw.Gateway) *Service {
	return &Service{store: st, cfg: cfg, log: log, gw: gw}
}

// Result summarizes an enrollment run.
type Result struct {
	Job     *models.EnrollmentJob `json:"job"`
	WGAddr  string                `json:"wgAddress"`
	HostPub string                `json:"hostPublicKey"`
}

// Enroll provisions WireGuard + trust for a host using the caller's session
// credentials. It is idempotent: re-running re-applies configuration.
// EnrollParams controls how enrollment reaches the host for the initial bootstrap.
type EnrollParams struct {
	// Method selects how the bootstrap SSH connection authenticates:
	//   "password" — an SSH password (host has no prior setup);
	//   "key"      — an existing SSH private key already trusted in the host's
	//                authorized_keys (for hosts with password auth disabled);
	//   "agent"    — the operator's forwarded SSH agent (private key never leaves
	//                their machine; only signatures cross the wire);
	//   "trusted"  — the caller's session certificate (host already trusts the CA).
	// All but "trusted" install the Fleet CA trust + login user; "trusted" assumes
	// it is already present.
	Method        string
	BootstrapUser string
	Password      string
	// auth is an SSH auth method supplied programmatically (e.g. an agent-backed
	// callback for the "agent" method). Not part of the JSON request.
	auth ssh.AuthMethod
	// PrivateKey is a PEM-encoded SSH private key used for the "key" method. It is
	// held only in memory for the bootstrap connection and never persisted.
	PrivateKey string
	// KeyPassphrase decrypts PrivateKey when it is passphrase-protected.
	KeyPassphrase string
	// SudoPassword is the password for `sudo` when the bootstrap user has
	// password-required sudo. If empty, the SSH password is reused (password
	// method) or passwordless sudo is assumed (key/trusted methods).
	SudoPassword string
	// WGEndpoint overrides the jump host's WireGuard endpoint (host:port) written
	// into the managed host's config — i.e. the publicly-routable address the host
	// uses to reach the VPN server. Defaults to FLEET_WG_JUMP_ENDPOINT.
	WGEndpoint string
	// ViaJump routes the bootstrap SSH connection through the jump host instead
	// of connecting directly from the backend.
	ViaJump bool
	// SkipWireGuard enrolls a host that is directly reachable from the jump host
	// (e.g. on the jump host's LAN, or the host that runs Fleet itself), so the
	// WireGuard overlay is unnecessary. The host keeps no overlay address and the
	// gateway reaches it through the jump host at its management address.
	SkipWireGuard bool
}

func (p EnrollParams) method() string {
	switch p.Method {
	case "password", "key", "agent":
		return p.Method
	default:
		return "trusted"
	}
}

// bootstrapping reports whether the method must install the CA trust on the host
// (true for password/key/agent; false for trusted, which assumes it already
// exists).
func (p EnrollParams) bootstrapping() bool {
	return p.method() != "trusted"
}

// AgentParams builds enrollment params that authenticate the bootstrap SSH
// connection with an operator's forwarded SSH agent.
func AgentParams(auth ssh.AuthMethod, bootstrapUser, sudoPassword, wgEndpoint string, viaJump bool) EnrollParams {
	return EnrollParams{
		Method: "agent", auth: auth, BootstrapUser: bootstrapUser,
		SudoPassword: sudoPassword, WGEndpoint: wgEndpoint, ViaJump: viaJump,
	}
}

func (s *Service) Enroll(ctx context.Context, sessionID uuid.UUID, host *models.Host, actor *uuid.UUID, params EnrollParams) (*Result, error) {
	mgmtAddr := host.Address
	if mgmtAddr == "" {
		mgmtAddr = host.Hostname // fall back to a resolvable name
	}
	loginUser := host.SSHUser
	if loginUser == "" {
		loginUser = "fleet"
	}
	job, err := s.store.CreateEnrollmentJob(ctx, host.ID, fmt.Sprintf("%s:%d", mgmtAddr, host.SSHPort), "", actor)
	if err != nil {
		return nil, err
	}
	step := func(name, status, detail string) {
		_ = s.store.AppendEnrollmentStep(ctx, job.ID, models.EnrollmentStep{
			Name: name, Status: status, Detail: detail, Timestamp: time.Now(),
		})
	}
	fail := func(name string, err error) (*Result, error) {
		step(name, "failed", err.Error())
		_ = s.store.FinishEnrollmentJob(ctx, job.ID, "failed", err.Error())
		_, _ = s.store.AppendAudit(ctx, models.AuditEvent{
			ActorID: actor, Action: "host.enroll_failed", TargetKind: "host", TargetID: host.ID.String(),
			Detail: map[string]any{"step": name, "error": err.Error()},
		})
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	// For a directly-reachable host, drop any stale WireGuard overlay address up
	// front. The gateway tries a host's WireGuard address first; a leftover overlay
	// IP on a host that has no tunnel is a dead end that shadows the reachable
	// management address. Clearing it early means a later-failing enrollment can't
	// leave the stale address behind (which is what made the Docker host itself
	// unreachable until it was cleared by hand).
	if params.SkipWireGuard {
		if err := s.store.SetHostWGAddress(ctx, host.ID, ""); err != nil {
			s.log.Warn("clear stale wg address", "host", host.Hostname, "err", err)
		} else {
			host.WGAddress = ""
		}
	}

	// 1) Reach the jump host (the VPN server, which already trusts the CA) and
	//    read its WireGuard public key.
	jumpAddr, jumpPort := splitHostPort(s.cfg.JumpHost, 22)
	jumpClient, err := s.gw.DialDirect(ctx, sessionID.String(), jumpAddr, jumpPort, s.cfg.JumpUser)
	if err != nil {
		return fail("connect_jump_host", err)
	}
	defer jumpClient.Close()
	jumpPub, err := run(jumpClient, "sudo cat /etc/wireguard/publickey 2>/dev/null || cat /etc/wireguard/publickey")
	if err != nil || strings.TrimSpace(jumpPub) == "" {
		return fail("read_jump_public_key", orErr(err, "jump host has no WireGuard public key"))
	}
	jumpPub = strings.TrimSpace(jumpPub)
	step("connect_jump_host", "ok", "jump WG pubkey "+short(jumpPub))

	// 2) Connect to the host for bootstrap. With "password" we authenticate with a
	//    bootstrap credential (the host need not trust the CA yet); with "trusted"
	//    we use the session certificate. The connection is either direct from the
	//    backend, or routed *through the jump host* (when the backend cannot reach
	//    the host directly but the jump host can).
	var hostClient *ssh.Client
	var hostClose func()
	var isRoot bool
	var sudoPass string
	via := "direct"
	if params.ViaJump {
		via = "via jump host"
	}
	if params.method() == "password" {
		buser := params.BootstrapUser
		if buser == "" {
			buser = "root"
		}
		isRoot = buser == "root"
		if !isRoot {
			sudoPass = params.SudoPassword
			if sudoPass == "" {
				sudoPass = params.Password // reuse SSH password for sudo by default
			}
		}
		if params.ViaJump {
			conn, derr := s.gw.DialPasswordViaJump(ctx, sessionID.String(), mgmtAddr, host.SSHPort, buser, params.Password)
			if derr != nil {
				return fail("connect_host", derr)
			}
			hostClient, hostClose = conn.Client, conn.Close
		} else {
			hostClient, err = s.gw.DialDirectPassword(ctx, mgmtAddr, host.SSHPort, buser, params.Password)
			if err != nil {
				return fail("connect_host", err)
			}
			hostClose = func() { _ = hostClient.Close() }
		}
		step("connect_host", "ok", fmt.Sprintf("ssh password auth as %s@%s (%s)", buser, mgmtAddr, via))
	} else if params.method() == "key" {
		buser := params.BootstrapUser
		if buser == "" {
			buser = "root"
		}
		isRoot = buser == "root"
		if !isRoot {
			sudoPass = params.SudoPassword // no password to reuse; passwordless sudo otherwise
		}
		signer, kerr := parsePrivateKey(params.PrivateKey, params.KeyPassphrase)
		if kerr != nil {
			return fail("connect_host", kerr)
		}
		if params.ViaJump {
			conn, derr := s.gw.DialKeyViaJump(ctx, sessionID.String(), mgmtAddr, host.SSHPort, buser, signer)
			if derr != nil {
				return fail("connect_host", derr)
			}
			hostClient, hostClose = conn.Client, conn.Close
		} else {
			hostClient, err = s.gw.DialDirectKey(ctx, mgmtAddr, host.SSHPort, buser, signer)
			if err != nil {
				return fail("connect_host", err)
			}
			hostClose = func() { _ = hostClient.Close() }
		}
		step("connect_host", "ok", fmt.Sprintf("ssh key auth as %s@%s (%s)", buser, mgmtAddr, via))
	} else if params.method() == "agent" {
		buser := params.BootstrapUser
		if buser == "" {
			buser = "root"
		}
		isRoot = buser == "root"
		if !isRoot {
			sudoPass = params.SudoPassword // no password to reuse; passwordless sudo otherwise
		}
		if params.auth == nil {
			return fail("connect_host", fmt.Errorf("no forwarded agent available"))
		}
		if params.ViaJump {
			conn, derr := s.gw.DialAuthViaJump(ctx, sessionID.String(), mgmtAddr, host.SSHPort, buser, params.auth)
			if derr != nil {
				return fail("connect_host", derr)
			}
			hostClient, hostClose = conn.Client, conn.Close
		} else {
			hostClient, err = s.gw.DialDirectAuth(ctx, mgmtAddr, host.SSHPort, buser, params.auth)
			if err != nil {
				return fail("connect_host", err)
			}
			hostClose = func() { _ = hostClient.Close() }
		}
		step("connect_host", "ok", fmt.Sprintf("ssh agent auth as %s@%s (%s)", buser, mgmtAddr, via))
	} else {
		// Certificate auth has no SSH password, but sudo may still require one. Use
		// a host-scoped system credential (not the session-level one, which carries
		// only "fleet") so this works even after the host is locked down.
		sudoPass = params.SudoPassword
		if params.ViaJump {
			conn, derr := s.gw.DialSystemForHost(ctx, host.ID, mgmtAddr, host.SSHPort, loginUser)
			if derr != nil {
				return fail("connect_host", derr)
			}
			hostClient, hostClose = conn.Client, conn.Close
		} else {
			hostClient, err = s.gw.DialDirectSystemForHost(ctx, host.ID, mgmtAddr, host.SSHPort, loginUser)
			if err != nil {
				return fail("connect_host", err)
			}
			hostClose = func() { _ = hostClient.Close() }
		}
		step("connect_host", "ok", fmt.Sprintf("ssh certificate auth to %s (%s)", mgmtAddr, via))
	}
	defer hostClose()

	// Privileged command runner: root runs directly; otherwise via sudo (with the
	// bootstrap password piped to sudo -S when one was provided).
	priv := func(script string) (string, error) {
		return privRun(hostClient, isRoot, sudoPass, script)
	}

	// 3) Collect host facts (same field order as the monitor's periodic refresh).
	if facts, ferr := run(hostClient, "uname -s; uname -r; uname -m; (. /etc/os-release 2>/dev/null; echo \"$NAME $VERSION_ID\"); ssh -V 2>&1 | head -1; nproc 2>/dev/null; awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null"); ferr == nil {
		s.recordFacts(ctx, host.ID, facts)
		step("collect_facts", "ok", oneLine(facts))
	} else {
		step("collect_facts", "skipped", ferr.Error())
	}

	// 4) For a password/key bootstrap, install the SSH CA trust, the login user,
	//    and sshd configuration so subsequent per-user certificate logins work.
	if params.bootstrapping() {
		caKeys, kerr := s.store.ListActiveCAPublicKeys(ctx, "user")
		if kerr != nil || len(caKeys) == 0 {
			return fail("install_trust", orErr(kerr, "no active user CA"))
		}
		if out, err := priv(s.caTrustScript(loginUser, strings.Join(caKeys, "\n"), host.ID)); err != nil || !strings.Contains(out, "CA_OK") {
			return fail("install_trust", orErr(err, out))
		}
		step("install_trust", "ok", "CA trust + login user '"+loginUser+"' + sshd configured")
	}

	// 5) Ensure WireGuard is installed (no-op if already present).
	if out, err := priv(wgInstallScript); err != nil || strings.Contains(out, "WG_MISSING") {
		return fail("install_wireguard", orErr(err, out+" (could not install wireguard tools)"))
	} else {
		step("install_wireguard", "ok", "wireguard tooling present")
	}

	// 6) Determine the overlay address (operator-specified or auto-assigned).
	//    Skipped for a directly-reachable host — it has no overlay address.
	var wgIP, hostPub string
	if !params.SkipWireGuard {
		wgIP = strings.TrimSpace(host.WGAddress)
		if wgIP != "" {
			if !isOverlayAddr(wgIP, s.cfg.WGJumpIP) {
				return fail("assign_overlay_address",
					fmt.Errorf("WireGuard address %q is not in the overlay subnet %s", wgIP, s.cfg.WGSubnet))
			}
			if inUse, _ := s.store.WGAddressInUse(ctx, wgIP, host.ID); inUse {
				return fail("assign_overlay_address",
					fmt.Errorf("WireGuard address %s is already assigned to another host", wgIP))
			}
		} else {
			wgIP, err = s.store.NextFreeWGAddress(ctx, s.cfg.WGJumpIP)
			if err != nil {
				return fail("assign_overlay_address", err)
			}
		}

		// 7) Bring up WireGuard on the host (kernel module preferred, userspace
		//    wireguard-go fallback). The private key is generated on the host.
		// The endpoint the managed host uses to reach the jump host (VPN server). Must
		// be routable FROM the host. Precedence: per-enroll override -> DB setting ->
		// config default (FLEET_WG_JUMP_ENDPOINT).
		jumpEndpoint := strings.TrimSpace(params.WGEndpoint)
		if jumpEndpoint == "" {
			jumpEndpoint = s.store.WireGuardEndpoint(ctx)
		}
		if jumpEndpoint == "" {
			jumpEndpoint = s.cfg.WGJumpEndpoint
		}
		out, err := priv(s.hostWGScript(wgIP, jumpPub, jumpEndpoint))
		if err != nil {
			return fail("configure_host_wireguard", orErr(err, out))
		}
		hostPub = parseKV(out, "HOSTPUB")
		if hostPub == "" {
			return fail("configure_host_wireguard", fmt.Errorf("host public key not produced: %s", oneLine(out)))
		}
		wgAddr := parseKV(out, "WGADDR")
		if wgAddr == "" {
			return fail("configure_host_wireguard",
				fmt.Errorf("wireguard interface did not come up: %s", oneLine(out)))
		}
		step("configure_host_wireguard", "ok",
			fmt.Sprintf("%s up (addr %s) pub=%s", s.cfg.WGInterface, wgAddr, short(hostPub)))

		// 8) Add the host as a peer on the jump host (the VPN server). Validate the
		// host-supplied key and the endpoint/IP before they reach the root-run
		// jump-host script, so a malicious enrollee can't inject shell commands.
		hostEndpoint := fmt.Sprintf("%s:%d", mgmtAddr, s.cfg.WGPort)
		if verr := validatePeerInputs(hostPub, hostEndpoint, wgIP); verr != nil {
			return fail("configure_jump_peer", verr)
		}
		jumpScript := s.jumpPeerScript(host.Hostname, hostPub, hostEndpoint, wgIP)
		if jout, jerr := run(jumpClient, "sudo sh -c "+shellQuote(jumpScript)); jerr != nil {
			return fail("configure_jump_peer", orErr(jerr, jout))
		}
		step("configure_jump_peer", "ok", fmt.Sprintf("peer %s allowed-ips %s/32", short(hostPub), wgIP))
	} else {
		step("configure_host_wireguard", "skipped",
			"host is directly reachable from the jump host — reached at its management address, no overlay")
	}

	// 8b) Install the KRL + RevokedKeys directive so the host enforces certificate
	//     revocation. A valid KRL is written BEFORE enabling the directive, and the
	//     change is rolled back if sshd rejects the config (never lock the host out).
	if krl.Available() {
		caKeys, _ := s.store.ListActiveCAPublicKeys(ctx, "user")
		serials, _ := s.store.RevokedSerials(ctx)
		if krlBytes, kerr := krl.Build(caKeys, serials); kerr == nil {
			b64 := base64.StdEncoding.EncodeToString(krlBytes)
			if out, err := priv(s.krlInstallScript(b64)); err != nil || !strings.Contains(out, "KRL_OK") {
				step("configure_revocation", "warning", orErr(err, out).Error())
			} else {
				step("configure_revocation", "ok", fmt.Sprintf("RevokedKeys enforced (%d revoked)", len(serials)))
			}
		} else {
			step("configure_revocation", "skipped", "could not build KRL: "+kerr.Error())
		}
	}

	// 9) Connectivity check: confirm the WireGuard tunnel actually establishes a
	//    handshake. A failure here usually means the jump endpoint is not
	//    reachable from the host (firewall / wrong address / UDP port closed).
	//    Skipped for a directly-reachable host (no tunnel to verify).
	if !params.SkipWireGuard {
		if ok, detail := s.verifyWireGuard(priv); ok {
			step("verify_connectivity", "ok", detail)
		} else {
			step("verify_connectivity", "warning", fmt.Sprintf(
				"no WireGuard handshake yet — ensure the jump endpoint %s is reachable from the host on UDP %d (firewall/port-forward) and the jump host is listening. %s",
				s.cfg.WGJumpEndpoint, s.cfg.WGPort, detail))
		}
	}

	// 10) Persist the address/enrolled state now so the validation dial can use it.
	_ = s.store.SetHostWGAddress(ctx, host.ID, wgIP)
	_ = s.store.SetHostEnrolled(ctx, host.ID, true)

	// 11) Validate end to end: connect through the jump host using a per-user
	//     certificate and run a command, proving cert auth + the tunnel path.
	if id, verr := s.validateCertLogin(ctx, host.ID, wgIP, mgmtAddr, host.SSHPort, loginUser); verr == nil {
		step("verify_certificate_login", "ok", "cert login via jump host: "+oneLine(id))
	} else {
		// Non-fatal in the local userspace-WireGuard fabric where the overlay
		// data plane is limited; configuration is applied either way.
		step("verify_certificate_login", "skipped", verr.Error())
	}

	_ = s.store.FinishEnrollmentJob(ctx, job.ID, "succeeded", "")
	_, _ = s.store.AppendAudit(ctx, models.AuditEvent{
		ActorID: actor, Action: "host.enroll", TargetKind: "host", TargetID: host.ID.String(),
		Detail: map[string]any{"wgAddress": wgIP, "hostPublicKey": hostPub, "method": params.method(), "jobId": job.ID},
	})

	final, _ := s.store.GetEnrollmentJob(ctx, job.ID)
	return &Result{Job: final, WGAddr: wgIP, HostPub: hostPub}, nil
}

// verifyWireGuard triggers and waits for a WireGuard handshake with the jump
// host, returning whether the tunnel came up and a short detail string. It runs
// on the host via the privileged runner so it works whether or not `wg` needs root.
func (s *Service) verifyWireGuard(priv func(string) (string, error)) (bool, string) {
	script := fmt.Sprintf(`IF=%s; JIP=%s
ping -c1 -W1 "$JIP" >/dev/null 2>&1 || true
i=0
while [ $i -lt 16 ]; do
  HS=$(wg show "$IF" latest-handshakes 2>/dev/null | awk '{print $2}' | sort -rn | head -1)
  if [ -n "$HS" ] && [ "$HS" != 0 ]; then
    NOW=$(date +%%s); AGO=$((NOW-HS))
    RX=$(wg show "$IF" transfer 2>/dev/null | awk '{print $2}' | paste -sd+ - | bc 2>/dev/null)
    echo "HANDSHAKE_OK age=${AGO}s rx=${RX:-0}"; exit 0
  fi
  i=$((i+1)); sleep 2
done
echo "HANDSHAKE_NONE"`, s.cfg.WGInterface, s.cfg.WGJumpIP)

	out, err := priv(script)
	if err != nil {
		return false, "check failed: " + oneLine(out)
	}
	if strings.Contains(out, "HANDSHAKE_OK") {
		return true, "wireguard handshake established (" + oneLine(parseAfter(out, "HANDSHAKE_OK")) + ")"
	}
	return false, ""
}

// parseAfter returns the text following a marker token on its line.
func parseAfter(out, marker string) string {
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, marker); i >= 0 {
			return strings.TrimSpace(line[i+len(marker):])
		}
	}
	return ""
}

// validateCertLogin connects to the host through the jump host using a system
// certificate carrying the host's accepted principals (host-scoped when locked
// down) and runs `id`, proving CA trust, the principal mapping, and the tunnel all
// work. It uses a system credential rather than the session-level one because the
// latter does not carry the host-scoped principal a locked-down host requires.
func (s *Service) validateCertLogin(ctx context.Context, hostID uuid.UUID, wgIP, mgmtAddr string, port int, user string) (string, error) {
	for _, addr := range []string{wgIP, mgmtAddr} {
		if addr == "" {
			continue
		}
		conn, err := s.gw.DialSystemForHost(ctx, hostID, addr, port, user)
		if err != nil {
			continue
		}
		out, rerr := run(conn.Client, "id")
		conn.Close()
		if rerr == nil {
			return out, nil
		}
	}
	return "", fmt.Errorf("certificate login not reachable yet")
}

// hostWGScript renders the script that configures and STARTS WireGuard on the
// managed host. It writes a wg-quick config and brings the interface up with
// wg-quick (kernel module, with a userspace wireguard-go fallback), enables it
// on boot, and reports the resulting interface state. The private key is
// generated on the host and never transmitted.
func (s *Service) hostWGScript(wgIP, jumpPub, jumpEndpoint string) string {
	iface := s.cfg.WGInterface
	return fmt.Sprintf(`set -e
IF=%s; IP=%s; SUBNET=%s; JPUB='%s'; JEP=%s; PORT=%d
mkdir -p /etc/wireguard; umask 077
[ -f /etc/wireguard/$IF.key ] || wg genkey > /etc/wireguard/$IF.key
PRIV=$(cat /etc/wireguard/$IF.key)
PUB=$(printf '%%s' "$PRIV" | wg pubkey)
cat > /etc/wireguard/$IF.conf <<EOF
[Interface]
Address = $IP/24
PrivateKey = $PRIV
ListenPort = $PORT
[Peer]
PublicKey = $JPUB
Endpoint = $JEP
AllowedIPs = $SUBNET
PersistentKeepalive = 25
EOF
chmod 600 /etc/wireguard/$IF.conf

# Bring the interface UP. Prefer wg-quick (standard; sets address + routes and
# brings it up). Use wireguard-go for the userspace fallback when there is no
# kernel module (containers / restricted kernels).
export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
UP=no
if command -v wg-quick >/dev/null 2>&1; then
  wg-quick down $IF >/dev/null 2>&1 || true
  if wg-quick up $IF >/dev/null 2>&1; then
    UP=yes
    (systemctl enable wg-quick@$IF >/dev/null 2>&1) || true
  fi
fi
if [ "$UP" != yes ]; then
  ip link del $IF >/dev/null 2>&1 || true
  if ! ip link add dev $IF type wireguard >/dev/null 2>&1; then
    command -v wireguard-go >/dev/null 2>&1 && wireguard-go $IF && sleep 1
  fi
  ip link show $IF >/dev/null 2>&1 || { echo "ERROR no wireguard interface available"; exit 1; }
  printf '%%s' "$PRIV" | wg set $IF private-key /dev/stdin listen-port $PORT
  wg set $IF peer "$JPUB" endpoint "$JEP" allowed-ips $SUBNET persistent-keepalive 25
  ip address add $IP/24 dev $IF 2>/dev/null || true
  ip link set $IF up
fi
sleep 1
# WireGuard interfaces report operational state UNKNOWN even when up.
ip link show $IF >/dev/null 2>&1 || { echo "ERROR interface not present after bring-up"; exit 1; }
ip link set $IF up 2>/dev/null || true
WGSTATE=$(ip -br link show $IF 2>/dev/null | awk '{print $2}')
WGADDR=$(ip -br addr show $IF 2>/dev/null | awk '{print $3}')
echo "WGSTATE=$WGSTATE"
echo "WGADDR=$WGADDR"
echo "HOSTPUB=$PUB"`,
		iface, wgIP, s.cfg.WGSubnet, jumpPub, jumpEndpoint, s.cfg.WGPort)
}

// krlInstallScript writes the KRL and enables the RevokedKeys directive, rolling
// back the directive if sshd rejects the resulting config.
func (s *Service) krlInstallScript(b64 string) string {
	return fmt.Sprintf(`set -e
printf '%%s' '%s' | base64 -d > /etc/ssh/fleet_krl
chmod 644 /etc/ssh/fleet_krl
DROP=/etc/ssh/sshd_config.d/00-fleet.conf
if [ -f "$DROP" ]; then
  grep -q '^RevokedKeys' "$DROP" || echo 'RevokedKeys /etc/ssh/fleet_krl' >> "$DROP"
  TARGET="$DROP"
else
  grep -q '^RevokedKeys' /etc/ssh/sshd_config || echo 'RevokedKeys /etc/ssh/fleet_krl' >> /etc/ssh/sshd_config
  TARGET=/etc/ssh/sshd_config
fi
if ! sshd -t 2>/dev/null; then
  # Roll back the directive so we never lock the host out.
  sed -i '\#^RevokedKeys /etc/ssh/fleet_krl#d' "$TARGET"
  echo "KRL_ROLLBACK sshd config rejected"; exit 1
fi
( systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service sshd reload 2>/dev/null || service ssh reload 2>/dev/null || pkill -HUP sshd 2>/dev/null ) || true
echo KRL_OK`, b64)
}

// jumpPeerScript renders the script that adds the host as a peer on the jump host.
func (s *Service) jumpPeerScript(hostname, hostPub, hostEndpoint, wgIP string) string {
	iface := s.cfg.WGInterface
	// The runtime `wg set` carries the endpoint for immediate connectivity (the
	// host is online during enrollment). The PERSISTED fragment deliberately omits
	// the endpoint: on a jump-host rebuild the hub must not have to resolve member
	// hostnames (a host may be offline, and DNS may be unavailable that early in
	// boot). The hub relearns each peer's endpoint from its keepalive handshake.
	return fmt.Sprintf(`set -e
IF=%s
wg set $IF peer '%s' endpoint '%s' allowed-ips %s/32 persistent-keepalive 25
mkdir -p /etc/wireguard/peers
cat > /etc/wireguard/peers/%s.conf <<'EOF'
[Peer]
PublicKey = %s
AllowedIPs = %s/32
EOF
echo OK`,
		iface, hostPub, hostEndpoint, wgIP, sanitize(hostname), hostPub, wgIP)
}

// caTrustScript installs the Fleet user CA, creates the login user with sudo and
// the principal mapping, configures sshd to trust certificates, and reloads sshd.
//
// The accepted principals are host-scoped: each account trusts "fleet-h-<hostID>"
// (privileged) / "fleet-login-h-<hostID>" (login-only), which only this host's
// certificates carry, so a certificate minted for another host is rejected here.
// Unless lockdown (cfg.HostScopedOnly) is set, the fleet-wide "fleet"/"fleet-login"
// principals are also trusted, keeping certs issued for not-yet-re-enrolled hosts
// working during the migration.
func (s *Service) caTrustScript(loginUser, caKeys string, hostID uuid.UUID) string {
	sudoLine := princ.Host(hostID) + `\n`
	loginLine := princ.HostLogin(hostID) + `\n`
	if !s.cfg.HostScopedOnly {
		sudoLine = princ.Global + `\n` + sudoLine
		loginLine = princ.GlobalLogin + `\n` + loginLine
	}
	return fmt.Sprintf(`set -e
LOGIN='%s'
NOSUDO="${LOGIN}-login"
# Two shared accounts that per-user certificates map to (unique cert per user):
#   $LOGIN  -> privileged, NOPASSWD sudo  (Host.Sudo / super admin)
#   $NOSUDO -> login-only, NO sudo        (users without Host.Sudo)
id "$LOGIN" >/dev/null 2>&1 || useradd -m -s /bin/bash "$LOGIN" 2>/dev/null || adduser -D "$LOGIN" 2>/dev/null || true
id "$NOSUDO" >/dev/null 2>&1 || useradd -m -s /bin/bash "$NOSUDO" 2>/dev/null || adduser -D "$NOSUDO" 2>/dev/null || true
mkdir -p /etc/sudoers.d && printf '%%s ALL=(ALL) NOPASSWD:ALL\n' "$LOGIN" > /etc/sudoers.d/fleet && chmod 0440 /etc/sudoers.d/fleet
# $NOSUDO deliberately has no sudoers entry.
# Trust the Fleet user CA.
cat > /etc/ssh/fleet_ca.pub <<'CAEOF'
%s
CAEOF
chmod 644 /etc/ssh/fleet_ca.pub
# Principal mapping: privileged cert principals -> $LOGIN account;
# login-only cert principals -> $NOSUDO account. Host-scoped ("fleet-h-<id>") so a
# certificate minted for another host is rejected here.
mkdir -p /etc/ssh/auth_principals && printf '%s' > /etc/ssh/auth_principals/"$LOGIN"
printf '%s' > /etc/ssh/auth_principals/"$NOSUDO"
# sshd: prefer a drop-in; also append directly if the main config has no Include.
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-fleet.conf <<'SSHEOF'
PubkeyAuthentication yes
TrustedUserCAKeys /etc/ssh/fleet_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%%u
SSHEOF
if ! grep -q 'sshd_config.d' /etc/ssh/sshd_config 2>/dev/null && ! grep -q 'TrustedUserCAKeys /etc/ssh/fleet_ca.pub' /etc/ssh/sshd_config 2>/dev/null; then
  { echo ''; echo '# Fleet Terminal'; echo 'PubkeyAuthentication yes'; echo 'TrustedUserCAKeys /etc/ssh/fleet_ca.pub'; echo 'AuthorizedPrincipalsFile /etc/ssh/auth_principals/%%u'; } >> /etc/ssh/sshd_config
fi
mkdir -p /run/sshd
sshd -t
( systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service sshd reload 2>/dev/null || service ssh reload 2>/dev/null || pkill -HUP sshd 2>/dev/null ) || true
echo CA_OK`,
		loginUser, caKeys, sudoLine, loginLine)
}

// wgInstallScript installs WireGuard tooling via the host's package manager if
// the `wg` command is not already present.
const wgInstallScript = `set -e
if ! command -v wg >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1 || true
    apt-get install -y -qq wireguard-tools >/dev/null 2>&1 || apt-get install -y -qq wireguard >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q wireguard-tools >/dev/null 2>&1 || { dnf install -y -q epel-release >/dev/null 2>&1; dnf install -y -q wireguard-tools >/dev/null 2>&1; } || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q wireguard-tools >/dev/null 2>&1 || true
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache wireguard-tools >/dev/null 2>&1 || true
  fi
fi
command -v wg >/dev/null 2>&1 && echo WG_INSTALLED || echo WG_MISSING`

// privRun executes a script with privilege. As root it runs directly; otherwise
// via sudo, piping the bootstrap password to `sudo -S` when one is supplied.
func privRun(client *ssh.Client, isRoot bool, password, script string) (string, error) {
	if isRoot {
		return run(client, "sh -c "+shellQuote(script))
	}
	if password != "" {
		return runWithInput(client, "sudo -S -p '' sh -c "+shellQuote(script), password+"\n")
	}
	return run(client, "sudo sh -c "+shellQuote(script))
}

// runWithInput runs a command, writing input to its stdin (used for sudo -S).
func runWithInput(client *ssh.Client, cmd, input string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	sess.Stdin = strings.NewReader(input)
	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

func (s *Service) recordFacts(ctx context.Context, hostID uuid.UUID, facts string) {
	lines := strings.Split(strings.TrimSpace(facts), "\n")
	inv := models.HostInventory{}
	if len(lines) > 0 {
		inv.OSName = strings.TrimSpace(lines[0])
	}
	if len(lines) > 1 {
		inv.KernelVersion = strings.TrimSpace(lines[1])
	}
	if len(lines) > 2 {
		inv.Architecture = strings.TrimSpace(lines[2])
	}
	if len(lines) > 3 && strings.TrimSpace(lines[3]) != "" {
		inv.OSName = strings.TrimSpace(lines[3])
	}
	if len(lines) > 4 {
		inv.SSHVersion = strings.TrimSpace(lines[4])
	}
	if len(lines) > 5 {
		if n, err := strconv.Atoi(strings.TrimSpace(lines[5])); err == nil {
			inv.CPUCount = n
		}
	}
	if len(lines) > 6 {
		if kb, err := strconv.ParseInt(strings.TrimSpace(lines[6]), 10, 64); err == nil {
			inv.MemoryMB = kb / 1024
		}
	}
	_ = s.store.UpsertInventory(ctx, hostID, inv)
}

// --- small helpers ---

func run(client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

func splitHostPort(hp string, def int) (string, int) {
	host, port, err := net.SplitHostPort(hp)
	if err != nil {
		return hp, def
	}
	p := def
	fmt.Sscanf(port, "%d", &p)
	return host, p
}

// isOverlayAddr reports whether addr is a usable overlay address in the same /24
// as the jump host (and not the jump host itself).
func isOverlayAddr(addr, jumpIP string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" || addr == jumpIP {
		return false
	}
	return ipPrefix24(addr) == ipPrefix24(jumpIP)
}

func ipPrefix24(ip string) string {
	parts := strings.Split(strings.TrimSpace(ip), ".")
	if len(parts) != 4 {
		return ""
	}
	return strings.Join(parts[:3], ".")
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

func parseKV(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimPrefix(line, key+"=")
		}
	}
	return ""
}

func short(k string) string {
	k = strings.TrimSpace(k)
	if len(k) > 12 {
		return k[:12] + "…"
	}
	return k
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
}

func orErr(err error, msg string) error {
	if err != nil {
		return fmt.Errorf("%v: %s", err, oneLine(msg))
	}
	return fmt.Errorf("%s", oneLine(msg))
}

// parsePrivateKey builds an SSH signer from a PEM-encoded private key, decrypting
// it with the passphrase when supplied. The key bytes stay in memory only.
func parsePrivateKey(pem, passphrase string) (ssh.Signer, error) {
	if strings.TrimSpace(pem) == "" {
		return nil, fmt.Errorf("no private key provided")
	}
	if passphrase != "" {
		signer, err := ssh.ParsePrivateKeyWithPassphrase([]byte(pem), []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("decrypt private key: %w", err)
		}
		return signer, nil
	}
	signer, err := ssh.ParsePrivateKey([]byte(pem))
	if err != nil {
		// A clearer hint when the key is actually passphrase-protected.
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			return nil, fmt.Errorf("private key is passphrase-protected; provide the passphrase")
		}
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return signer, nil
}
