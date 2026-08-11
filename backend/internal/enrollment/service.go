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
	"github.com/fleet-terminal/backend/internal/overlay"
	"github.com/fleet-terminal/backend/internal/overlaypki"
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
	// overlays holds the certificate-authenticated overlay provisioners by name
	// ("openvpn"). Empty when only WireGuard is available. A host is
	// provisioned onto whichever overlay its effective selection names.
	overlays map[string]overlay.Overlay
	// pki issues and revokes the certificate overlays' client certificates. Nil on a
	// WireGuard-only deployment, which never needs it.
	pki *overlaypki.PKI
}

// New constructs the enrollment Service. overlays may be nil/empty (WireGuard only);
// it carries the cert-overlay provisioners (OpenVPN) when built.
func New(st *store.Store, cfg *config.Config, log *slog.Logger, gw *sshgw.Gateway, overlays map[string]overlay.Overlay, pki *overlaypki.PKI) *Service {
	return &Service{store: st, cfg: cfg, log: log, gw: gw, overlays: overlays, pki: pki}
}

// effectiveOverlay resolves which transport to enroll a host onto: an explicit
// per-enroll choice wins, then the host's previously-recorded overlay, then the
// deployment default (FLEET_OVERLAY). Empty/"wireguard" both mean WireGuard.
func (s *Service) effectiveOverlay(params EnrollParams, host *models.Host) string {
	pick := strings.TrimSpace(params.Overlay)
	if pick == "" {
		pick = strings.TrimSpace(host.Overlay)
	}
	if pick == "" {
		pick = s.cfg.Overlay
	}
	if pick == "" {
		pick = "wireguard"
	}
	return pick
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
	// Overlay overrides the reachability transport for THIS host: "" (deployment
	// default FLEET_OVERLAY), "wireguard" or "openvpn". Lets an operator
	// pick a per-host VPN at enrollment. Ignored when SkipWireGuard is set.
	Overlay string
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

	// 1) Reach the jump host (the VPN server, which already trusts the CA). For the
	//    WireGuard overlay, read its public key (needed to configure the host peer);
	//    the OpenVPN overlay authenticates with X.509 certs and has no such key.
	jumpAddr, jumpPort := splitHostPort(s.cfg.JumpHost, 22)
	jumpClient, err := s.gw.DialDirect(ctx, sessionID.String(), jumpAddr, jumpPort, s.cfg.JumpUser)
	if err != nil {
		return fail("connect_jump_host", err)
	}
	defer jumpClient.Close()
	// Resolve which overlay transport this host uses (per-host choice > recorded > default).
	effOverlay := s.effectiveOverlay(params, host)
	var jumpPub string
	if overlay.IsCertOverlay(effOverlay) {
		step("connect_jump_host", "ok", "reached jump host ("+effOverlay+" overlay)")
	} else {
		jumpPub, err = run(jumpClient, "sudo cat /etc/wireguard/publickey 2>/dev/null || cat /etc/wireguard/publickey")
		if err != nil || strings.TrimSpace(jumpPub) == "" {
			return fail("read_jump_public_key", orErr(err, "jump host has no WireGuard public key"))
		}
		jumpPub = strings.TrimSpace(jumpPub)
		step("connect_jump_host", "ok", "jump WG pubkey "+short(jumpPub))
	}

	// 1b) A rebuilt host presents a new SSH host key, and every dial below would be
	//     refused by the pin taken before the rebuild — so re-enrolling, the obvious
	//     remedy, could not fix the one situation that most needs it. Drop the pins
	//     first; the connection re-pins whatever the host presents now. Bootstrapping
	//     methods only (see clearStalePins).
	if params.bootstrapping() {
		if n := s.clearStalePins(ctx, host); n > 0 {
			step("clear_host_key_pin", "ok",
				fmt.Sprintf("dropped %d stale SSH host-key pin(s) — the host re-pins on this connection", n))
		}
	}

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

	// 5) Ensure WireGuard is installed (no-op if already present). Skipped under a
	//    cert overlay (OpenVPN), which installs its own tooling in step 6.
	if !overlay.IsCertOverlay(effOverlay) {
		if out, err := priv(wgInstallScript); err != nil || strings.Contains(out, "WG_MISSING") {
			return fail("install_wireguard", orErr(err, out+" (could not install wireguard tools)"))
		} else {
			step("install_wireguard", "ok", "wireguard tooling present")
		}
	}

	// 6) Determine the overlay address (operator-specified or auto-assigned).
	//    Skipped for a directly-reachable host — it has no overlay address.
	var wgIP, hostPub string
	// The address a host holds before this run. Each overlay numbers hosts from its
	// own pool, so a switch renumbers it and the pin held for the old address has to
	// be released with it (see releaseOverlayAddress).
	prevIP := strings.TrimSpace(host.WGAddress)
	if overlay.IsCertOverlay(effOverlay) {
		// Cert overlay (OpenVPN): provision the tunnel via X.509 mutual auth
		// instead of WireGuard. The assigned address is stored in the same wg_address
		// column below, so the SSH gateway dials the host identically regardless of overlay.
		ov := s.overlays[effOverlay]
		if ov == nil {
			return fail("configure_overlay", fmt.Errorf("overlay %q is not available on this deployment", effOverlay))
		}
		if params.SkipWireGuard {
			step("configure_host_overlay", "skipped",
				"host is directly reachable from the jump host — no overlay")
		} else {
			var oerr error
			if wgIP, oerr = s.enrollCertOverlay(ctx, ov, host, jumpClient, priv, params, step); oerr != nil {
				return fail("configure_overlay", oerr)
			}
			// Retire whichever transport this host is leaving. Gated inside on a
			// dial to the new overlay address from the jump host: retiring a working
			// transport on the strength of a step that merely reported ok is what took
			// a host offline once already.
			s.retirePreviousOverlay(ctx, effOverlay, host, wgIP, priv, jumpClient, step)
		}
	} else if !params.SkipWireGuard {
		// A host arriving from a certificate overlay is renumbered onto WireGuard's
		// own pool here, the mirror of the cert-overlay branch above.
		wgIP, err = s.assignOverlayAddress(ctx, host, s.plan("wireguard"))
		if err != nil {
			return fail("assign_overlay_address", err)
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
		// Persist the host's overlay public key so a standby jump host can rebuild the
		// peer list from Postgres on failover (best-effort; not fatal to enrollment).
		if perr := s.store.SetHostWGPublicKey(ctx, host.ID, hostPub); perr != nil {
			s.log.Warn("persist host wg public key", "host", host.Hostname, "err", perr)
		}
		// Retire the certificate overlay this host is leaving, if any — the mirror of
		// the cert branch above, and gated on the same proof.
		s.retirePreviousOverlay(ctx, effOverlay, host, wgIP, priv, jumpClient, step)
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
	//    Skipped for a directly-reachable host (no tunnel to verify) and for a cert
	//    overlay (its tunnel-up check runs inside enrollCertOverlay).
	if !params.SkipWireGuard && !overlay.IsCertOverlay(effOverlay) {
		if ok, detail := s.verifyWireGuard(priv); ok {
			step("verify_connectivity", "ok", detail)
		} else {
			step("verify_connectivity", "warning", fmt.Sprintf(
				"no WireGuard handshake yet — ensure the jump endpoint %s is reachable from the host on UDP %d (firewall/port-forward) and the jump host is listening. %s",
				s.cfg.WGJumpEndpoint, s.cfg.WGPort, detail))
		}
	}

	// 10) Persist the address/enrolled state now so the validation dial can use it.
	//     Record the resolved overlay so re-enrollment/monitoring stays on the same one.
	if prevIP != wgIP {
		s.releaseOverlayAddress(ctx, host, prevIP)
	}
	_ = s.store.SetHostWGAddress(ctx, host.ID, wgIP)
	_ = s.store.SetHostOverlay(ctx, host.ID, effOverlay)
	_ = s.store.SetHostEnrolled(ctx, host.ID, true)

	// 11) Validate end to end: connect through the jump host using a per-user
	//     certificate and run a command, proving cert auth + the tunnel path.
	if id, verr := s.validateCertLogin(ctx, host.ID, wgIP, mgmtAddr, host.SSHPort, loginUser); verr == nil {
		step("verify_certificate_login", "ok", "cert login via jump host: "+oneLine(id))
	} else if s.cfg.IsProduction() {
		// A host nobody can log in through is not enrolled in any useful sense, and
		// recording this as "skipped" under a "succeeded" job is how an unreachable
		// host passes for a working one. Configuration has been applied and the host
		// stays marked enrolled; re-running is idempotent.
		return fail("verify_certificate_login", verr)
	} else {
		// Outside production this stays non-fatal: the local userspace-WireGuard
		// fabric has a limited data plane and legitimately can't complete this.
		step("verify_certificate_login", "failed", verr.Error()+" (non-fatal outside production)")
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

// clearStalePins drops the host's SSH host-key pins so a REBUILT host can be
// enrolled again. Without this, re-enrolling — the obvious thing to try when a
// host stops answering — cannot work: every dial the backend makes is refused by
// the pin recorded before the rebuild, and on the no-install path the failure
// surfaces only as an unverifiable certificate login at the very end.
//
// This is only done for bootstrapping methods (password/key/agent/pipe), where
// the operator supplies an out-of-band credential that proves they can already
// reach the host — the same evidence the manual clear-pin endpoint is gated on.
// A "trusted" re-provision deliberately keeps its pin: it authenticates with
// nothing but the existing trust, so silently accepting a changed key there
// would remove the MITM check with no operator act behind it.
func (s *Service) clearStalePins(ctx context.Context, host *models.Host) int {
	ids := sshgw.HostKeyIDs(host.SSHPort, host.WGAddress, host.Address, host.Hostname)
	n, err := s.store.DeleteHostKeys(ctx, ids)
	if err != nil {
		s.log.Warn("could not clear host key pins", "host", host.Hostname, "err", err)
		return 0
	}
	// The stored pin and the gateway's per-process cache have to go together.
	if s.gw != nil {
		s.gw.ForgetHostKeys(ids...)
	}
	return n
}

// validateCertLogin connects to the host through the jump host using a system
// certificate carrying the host's accepted principals (host-scoped when locked
// down) and runs `id`, proving CA trust, the principal mapping, and the tunnel all
// work. It uses a system credential rather than the session-level one because the
// latter does not carry the host-scoped principal a locked-down host requires.
// A freshly-configured tunnel and a just-reloaded sshd can both take a moment,
// so a single refusal is not proof of a broken enrollment. Retry briefly before
// calling it: an enrollment that reports failure the operator can't reproduce is
// as unhelpful as one that reports success it hasn't earned.
func (s *Service) validateCertLogin(ctx context.Context, hostID uuid.UUID, wgIP, mgmtAddr string, port int, user string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(3 * time.Second):
			}
		}
		for _, addr := range []string{wgIP, mgmtAddr} {
			if addr == "" {
				continue
			}
			conn, err := s.gw.DialSystemForHost(ctx, hostID, addr, port, user)
			if err != nil {
				// Keep the real reason. This used to be discarded and reported as
				// "certificate login not reachable yet", which named neither the
				// address that failed nor why — so a rejected host key, a refused
				// certificate and an unreachable tunnel all looked identical.
				lastErr = fmt.Errorf("%s:%d: %w", addr, port, err)
				continue
			}
			out, rerr := run(conn.Client, "id")
			conn.Close()
			if rerr == nil {
				return out, nil
			}
			lastErr = fmt.Errorf("%s:%d: connected but `id` failed: %w", addr, port, rerr)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no address to try")
	}
	return "", fmt.Errorf("certificate login failed: %w", lastErr)
}

// hostAllowedIPs is what a managed host's tunnel config carries as AllowedIPs for
// its single peer, the jump host. In WireGuard that one value does two jobs: it is
// the set of destinations the host routes INTO the tunnel, and the only set of
// source addresses it will ACCEPT back out of it.
//
// With peer isolation on it is the jump host alone (a /32), which makes the host
// end of the overlay hub-and-spoke in its own right: the host cannot address a
// sibling, and — the part that matters — it drops a decrypted packet claiming to
// come from one. The jump host's forwarding deny already stops sibling traffic,
// but that rule lives on a machine whose iptables Fleet does not always control,
// and it fails open with a warning. This end does not depend on it.
//
// With isolation off it is the whole overlay subnet, the historical value, and
// hosts can reach each other exactly as before.
//
// Already-enrolled hosts keep whatever they were given until they are re-enrolled
// (or narrowed in place — see the security guide); a fleet mid-migration is a
// mix, and the two settings interoperate fine.
func (s *Service) hostAllowedIPs() string {
	if !s.cfg.OverlayPeerIsolation {
		return s.cfg.WGSubnet
	}
	// A jump IP that isn't a plain address would produce a config that WireGuard
	// refuses to parse, taking the tunnel down entirely — much worse than the wide
	// AllowedIPs this falls back to, which the hub-side deny still covers.
	if net.ParseIP(strings.TrimSpace(s.cfg.WGJumpIP)) == nil {
		return s.cfg.WGSubnet
	}
	return strings.TrimSpace(s.cfg.WGJumpIP) + "/32"
}

// hostWGScript renders the script that configures and STARTS WireGuard on the
// managed host. It writes a wg-quick config and brings the interface up with
// wg-quick (kernel module, with a userspace wireguard-go fallback), enables it
// on boot, and reports the resulting interface state. The private key is
// generated on the host and never transmitted.
func (s *Service) hostWGScript(wgIP, jumpPub, jumpEndpoint string) string {
	iface := s.cfg.WGInterface
	core := fmt.Sprintf(`set -e
IF=%s; IP=%s; ALLOWED=%s; JPUB='%s'; JEP=%s; PORT=%d
mkdir -p /etc/wireguard; umask 077
[ -f /etc/wireguard/$IF.key ] || wg genkey > /etc/wireguard/$IF.key
PRIV=$(cat /etc/wireguard/$IF.key)
PUB=$(printf '%%s' "$PRIV" | wg pubkey)
# The interface address keeps its /24: the connected route it creates is harmless
# (WireGuard drops a packet for an address no peer claims), and narrowing it would
# change source-address selection on the host for no security gain. AllowedIPs is
# what decides reachability, in both directions.
cat > /etc/wireguard/$IF.conf <<EOF
[Interface]
Address = $IP/24
PrivateKey = $PRIV
ListenPort = $PORT
[Peer]
PublicKey = $JPUB
Endpoint = $JEP
AllowedIPs = $ALLOWED
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
  wg set $IF peer "$JPUB" endpoint "$JEP" allowed-ips $ALLOWED persistent-keepalive 25
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
		iface, wgIP, s.hostAllowedIPs(), jumpPub, jumpEndpoint, s.cfg.WGPort)
	return core + "\n" + s.wgPersistScript(iface)
}

// wgReresolveScript is installed on managed hosts and run by a timer. Because the
// jump-host Endpoint is often a DNS name on a dynamic IP, and kernel WireGuard
// resolves it only once at bring-up, a whole-node reboot can race DNS and strand
// the tunnel. This (a) brings the tunnel up if it is down (DNS wasn't ready at
// boot), and (b) refreshes the peer endpoint when the handshake goes stale.
const wgReresolveScript = `#!/bin/sh
IF="${1:-wgfleet}"
CONF="/etc/wireguard/${IF}.conf"
[ -f "$CONF" ] || exit 0

if [ ! -e "/sys/class/net/${IF}" ]; then
  systemctl start "wg-quick@${IF}" >/dev/null 2>&1 || \
    WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go wg-quick up "$IF" >/dev/null 2>&1 || true
  exit 0
fi

PUB=$(sed -n 's/^PublicKey *= *//p' "$CONF" | head -n1)
EP=$(sed -n 's/^Endpoint *= *//p' "$CONF" | head -n1)
[ -n "$PUB" ] && [ -n "$EP" ] || exit 0

HS=$(wg show "$IF" latest-handshakes 2>/dev/null | awk -v p="$PUB" '$1==p{print $2}')
NOW=$(date +%s)
if [ -z "$HS" ] || [ "$HS" = "0" ] || [ $((NOW - HS)) -gt 150 ]; then
  wg set "$IF" peer "$PUB" endpoint "$EP" >/dev/null 2>&1 || true
fi
`

// wgPersistScript makes the host's WireGuard survive reboots on every host type:
// it enables wg-quick@<iface> on boot (with a userspace drop-in so containers
// without the kernel module also come up), and installs a timer that runs
// wgReresolveScript to heal the DNS boot-race and endpoint IP changes. Best-effort
// (set +e): a persistence hiccup never fails enrollment.
func (s *Service) wgPersistScript(iface string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(wgReresolveScript))
	return fmt.Sprintf(`set +e
if command -v systemctl >/dev/null 2>&1; then
  mkdir -p /etc/systemd/system/wg-quick@%s.service.d
  cat > /etc/systemd/system/wg-quick@%s.service.d/fleet.conf <<'DROPIN'
[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
DROPIN
  printf '%%s' '%s' | base64 -d > /usr/local/sbin/fleet-wg-reresolve
  chmod 755 /usr/local/sbin/fleet-wg-reresolve
  cat > /etc/systemd/system/fleet-wg-reresolve.service <<'UNIT'
[Unit]
Description=Fleet WireGuard boot-persistence and endpoint re-resolution
After=network-online.target
UNIT
  cat >> /etc/systemd/system/fleet-wg-reresolve.service <<UNIT2
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/fleet-wg-reresolve %s
UNIT2
  cat > /etc/systemd/system/fleet-wg-reresolve.timer <<'TIMER'
[Unit]
Description=Fleet WireGuard re-resolve timer
[Timer]
OnBootSec=20
OnUnitActiveSec=30
[Install]
WantedBy=timers.target
TIMER
  systemctl daemon-reload
  systemctl enable wg-quick@%s >/dev/null 2>&1
  systemctl enable --now fleet-wg-reresolve.timer >/dev/null 2>&1
fi
echo WG_PERSIST_OK`,
		iface, iface, b64, iface, iface)
}

// wgTeardownScript retires WireGuard on a host that is moving to a certificate
// overlay. Both transports assign the host the SAME overlay address (it lives in one
// wg_address column so the gateway stays transport-agnostic), so leaving the old
// interface up means two interfaces claiming one address: which one answers is down to
// route metrics, and the jump host's stale peer keeps advertising the address on the
// hub. The result is a host that enrolls "successfully" onto OpenVPN and is reached
// intermittently, or not at all.
//
// The config is renamed rather than deleted (and the private key left in place), so a
// host that is moved back to WireGuard has its old identity to fall back on and the
// operator can see what was retired. Wholly best-effort: a host with no WireGuard to
// retire runs this as a no-op, and a failure here must not fail an enrollment whose
// real work — the new tunnel — succeeded.
func (s *Service) wgTeardownScript() string {
	iface := s.cfg.WGInterface
	return fmt.Sprintf(`set +e
IF=%s
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now wg-quick@$IF >/dev/null 2>&1
  systemctl disable --now fleet-wg-reresolve.timer >/dev/null 2>&1
fi
if command -v wg-quick >/dev/null 2>&1; then wg-quick down $IF >/dev/null 2>&1; fi
if ip link show $IF >/dev/null 2>&1; then ip link delete $IF >/dev/null 2>&1; fi
if [ -f /etc/wireguard/$IF.conf ]; then mv -f /etc/wireguard/$IF.conf /etc/wireguard/$IF.conf.fleet-disabled; fi
echo WG_RETIRED`, iface)
}

// wgPurgeScript is wgTeardownScript for a host that is leaving the fleet: it retires
// the interface AND destroys the key material and config.
//
// The retire deliberately renames the config and keeps the private key so a host that
// comes back can re-use its identity. For a decommission that leaves a working tunnel
// definition and its key on a machine nothing manages any more. The hub no longer
// lists the peer once CleanupHostOverlay has run — WireGuard is allowlist-based, so
// that alone denies it — but leaving the key behind is still a credential sitting on
// a box Fleet has walked away from.
func (s *Service) wgPurgeScript() string {
	iface := s.cfg.WGInterface
	return s.wgTeardownScript() + fmt.Sprintf(`
rm -f /etc/wireguard/%[1]s.conf /etc/wireguard/%[1]s.conf.fleet-disabled
rm -f /etc/wireguard/%[1]s.privatekey /etc/wireguard/%[1]s.publickey
rm -f /etc/systemd/system/fleet-wg-reresolve.service /etc/systemd/system/fleet-wg-reresolve.timer
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1
echo WG_PURGED`, iface)
}

// retireWireGuard tears the WireGuard overlay down on both ends when a host moves to a
// certificate overlay: the interface + boot units on the host, the peer on the jump
// host, and the stored public key (which is what a standby jump host rebuilds its peer
// list from — leaving it would restore the retired peer on the next failover). Every
// part is best-effort and reported through step().
func (s *Service) retireWireGuard(ctx context.Context, host *models.Host, priv func(string) (string, error), jumpClient *ssh.Client, step func(name, status, detail string)) {
	var notes []string
	degraded := false
	if out, err := priv(s.wgTeardownScript()); err != nil || !strings.Contains(out, "WG_RETIRED") {
		notes = append(notes, "could not retire "+s.cfg.WGInterface+" on the host: "+oneLine(orErr(err, out).Error()))
		degraded = true
	} else {
		notes = append(notes, s.cfg.WGInterface+" down and disabled on the host")
	}
	s.retireJumpPeer(ctx, host, jumpClient, &notes, &degraded)
	status := "ok"
	if degraded {
		status = "warning"
	}
	step("retire_wireguard", status, strings.Join(notes, "; "))
}

// retireJumpPeer removes the hub half of a retired WireGuard tunnel: the jump host's
// peer entry and the stored public key a standby jump host would rebuild it from.
// Split out because the no-install flow retires the two halves at different moments:
// the host side is a phase of the script the operator runs themselves, the hub side
// waits for the finish step (see FinishScriptEnroll).
func (s *Service) retireJumpPeer(ctx context.Context, host *models.Host, jumpClient *ssh.Client, notes *[]string, degraded *bool) {
	if out, err := run(jumpClient, "sudo sh -c "+shellQuote(s.jumpPeerCleanupScript(host.Hostname))); err != nil {
		*notes = append(*notes, "could not remove the jump-host peer: "+oneLine(orErr(err, out).Error()))
		*degraded = true
	} else if strings.Contains(out, "REMOVED") {
		*notes = append(*notes, "jump-host peer removed")
	}
	// The peer list a standby jump host restores on failover is built from this
	// column; leaving the key would bring the retired peer back on the next failover.
	if err := s.store.SetHostWGPublicKey(ctx, host.ID, ""); err != nil {
		*notes = append(*notes, "could not clear the stored public key: "+err.Error())
		*degraded = true
	}
}

// hasOverlayState reports whether a host has been on the overlay before — a completed
// enrollment or an assigned address. It says nothing about which transport: retiring
// WireGuard is a no-op on a host that never had it, so this is the safe question to ask
// when the recorded overlay can't be trusted (see certOverlayScript).
func hasOverlayState(host *models.Host) bool {
	return host.Enrolled || strings.TrimSpace(host.WGAddress) != ""
}

// retireCertOverlay is retireWireGuard's mirror: it takes a certificate overlay down
// on both ends when a host moves back to WireGuard. Without it the host keeps an
// openvpn client reconnecting to an overlay it has left, and the server keeps a pinned
// address for a host that is no longer on it — two interfaces racing for the same
// traffic, which is the failure the separate subnets exist to prevent.
func (s *Service) retireCertOverlay(ctx context.Context, name string, host *models.Host, priv func(string) (string, error), jumpClient *ssh.Client, step func(name, status, detail string)) {
	ov := s.overlays[name]
	if ov == nil {
		// The transport is recorded but not built into this deployment, so Fleet cannot
		// speak for it. Say so rather than reporting a clean retirement.
		step("retire_"+name, "warning",
			fmt.Sprintf("this host is recorded on the %s overlay, which is not available on this deployment — "+
				"its client may still be running; stop it on the host by hand", name))
		return
	}
	var notes []string
	degraded := false

	hb := ov.RetireHostScript()
	if out, err := priv(hb.Script); err != nil || !strings.Contains(out, hb.Marker) {
		notes = append(notes, "could not stop the "+name+" client on the host: "+oneLine(orErr(err, out).Error()))
		degraded = true
	} else {
		notes = append(notes, name+" client stopped and disabled on the host")
	}

	jumpRun := func(script string) (string, error) {
		return run(jumpClient, "sudo sh -c "+shellQuote(script))
	}
	if detail, err := ov.RetireJump(ctx, host.ID, jumpRun); err != nil {
		notes = append(notes, err.Error())
		degraded = true
	} else if detail != "" {
		notes = append(notes, detail)
	}

	status := "ok"
	if degraded {
		status = "warning"
	}
	step("retire_"+name, status, strings.Join(notes, "; "))
}

// retirePreviousOverlay takes down whichever transport a host is LEAVING, in either
// direction, once the one it is joining has been proven to carry traffic.
//
// One entry point for both directions on purpose: a switch is only complete when the
// old transport is gone from both ends, and the two directions used to be neither
// symmetric nor gated the same way. The proof is a dial to the host's new overlay
// address from the jump host — the path every session takes — because every other
// check in enrollment can fall back to the management address and pass over the LAN
// with no tunnel at all.
func (s *Service) retirePreviousOverlay(
	ctx context.Context, joining string, host *models.Host, overlayIP string,
	priv func(string) (string, error), jumpClient *ssh.Client, step func(name, status, detail string),
) {
	leaving := previousOverlay(host, joining)
	if leaving == "" {
		return
	}
	if err := s.verifyOverlayReachable(ctx, jumpClient, overlayIP, host.SSHPort); err != nil {
		// Never trade a transport that might be working for one that demonstrably is
		// not. The host keeps both until an operator can look at it; the duplicate is
		// recoverable, an unreachable host is not.
		step("retire_"+leaving, "warning", fmt.Sprintf(
			"left the %s overlay in place: the new %s tunnel did not answer at %s (%v). "+
				"Re-enroll once it does, or retire %s on the host by hand",
			leaving, joining, overlayIP, err, leaving))
		return
	}
	if overlay.IsCertOverlay(leaving) {
		s.retireCertOverlay(ctx, leaving, host, priv, jumpClient, step)
		return
	}
	s.retireWireGuard(ctx, host, priv, jumpClient, step)
}

// previousOverlay names the transport a host is leaving, or "" when it is not moving.
// A host with no overlay state has nothing to leave; an empty recorded overlay means
// WireGuard, which is what a host enrolled before per-host overlays looks like.
func previousOverlay(host *models.Host, joining string) string {
	if !hasOverlayState(host) {
		return ""
	}
	was := strings.TrimSpace(host.Overlay)
	if was == "" {
		was = "wireguard"
	}
	if was == strings.TrimSpace(joining) {
		return ""
	}
	return was
}

// hadWireGuard reports whether a host is carrying WireGuard state worth retiring
// before it moves to a certificate overlay. An empty Overlay counts as WireGuard —
// that is what a host enrolled before per-host overlays existed looks like.
func hadWireGuard(host *models.Host) bool {
	if overlay.IsCertOverlay(strings.TrimSpace(host.Overlay)) {
		return false
	}
	return hasOverlayState(host)
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
	// The persisted fragment carries the SAME endpoint + keepalive as the runtime
	// `wg set`, so a jump-host rebuild restores the hub's ability to initiate to
	// the host rather than only waiting to be called.
	//
	// This fragment used to omit the endpoint, on the reasoning that a hub rebuild
	// must not depend on resolving member hostnames (a host may be offline, and DNS
	// may be unavailable that early in boot) — `wg addconf` drops the whole peer if
	// the endpoint will not resolve. That concern is real but the cure was too
	// broad: it silently removed hub-initiated connectivity for EVERY peer on every
	// restart. A host whose own configured Endpoint is unreachable was being carried
	// entirely by the hub calling it, and went permanently dark after the first
	// `make up-single` — with nothing to indicate why. The restore side now handles
	// the resolve risk precisely, dropping the endpoint only when it actually fails
	// to resolve (see deploy/testfabric/jumphost/entrypoint.sh).
	//
	// Before adding the peer, retire every stale persisted claim on this overlay
	// IP — this host's own previous key (re-enrollment rotates it) or a removed
	// host's leftover fragment after the IP was reused. In WireGuard the LAST peer
	// assigned an allowed-ip silently steals it, so a stale fragment restored
	// after this host's own would take the IP back on the next hub rebuild and
	// dead-end the tunnel.
	return fmt.Sprintf(`set -e
IF=%s
NEW='%s'
WGIP=%s
NAME=%s
mkdir -p /etc/wireguard/peers
for f in /etc/wireguard/peers/*.conf; do
  [ -f "$f" ] || continue
  if grep -qF "AllowedIPs = ${WGIP}/32" "$f" || [ "$f" = "/etc/wireguard/peers/${NAME}.conf" ]; then
    OLD=$(awk '/^PublicKey/{print $3; exit}' "$f")
    if [ -n "$OLD" ] && [ "$OLD" != "$NEW" ]; then
      wg set $IF peer "$OLD" remove 2>/dev/null || true
      echo "retired stale peer $(basename "$f") ($OLD)"
    fi
    if [ "$f" != "/etc/wireguard/peers/${NAME}.conf" ]; then rm -f "$f"; fi
  fi
done
wg set $IF peer "$NEW" endpoint '%s' allowed-ips ${WGIP}/32 persistent-keepalive 25
cat > /etc/wireguard/peers/${NAME}.conf <<'EOF'
[Peer]
PublicKey = %s
AllowedIPs = %s/32
Endpoint = %s
PersistentKeepalive = 25
EOF
echo OK`,
		iface, hostPub, wgIP, sanitize(hostname), hostEndpoint, hostPub, wgIP, hostEndpoint)
}

// jumpPeerCleanupScript renders the script that removes a host's WireGuard peer
// from the jump host — both the live kernel peer (key read from the persisted
// fragment) and the fragment itself — so a deleted host can't linger as a peer
// or, worse, steal its reassigned overlay IP back on a later hub rebuild.
func (s *Service) jumpPeerCleanupScript(hostname string) string {
	return fmt.Sprintf(`IF=%s
F=/etc/wireguard/peers/%s.conf
if [ -f "$F" ]; then
  KEY=$(awk '/^PublicKey/{print $3; exit}' "$F")
  if [ -n "$KEY" ]; then wg set $IF peer "$KEY" remove 2>/dev/null || true; fi
  rm -f "$F"
  echo REMOVED
else
  echo ABSENT
fi`, s.cfg.WGInterface, sanitize(hostname))
}

// hostTeardownScript removes everything enrollment installed on a managed host:
// the sudoers grant, both shared accounts, the CA trust, the principal files, the
// sshd drop-in (and the appended block on hosts with no Include), the KRL, and the
// overlay client.
//
// overlayRetire is the privileged script that takes this host's transport down —
// wgTeardownScript for WireGuard, the overlay's RetireHostScript for a certificate
// overlay. It is embedded rather than run separately because it must happen on the
// detached side: the tunnel is how Fleet reached the host, so bringing it down in
// the foreground would kill the session before it could finish. It runs LAST, after
// the accounts are gone, so the privileged account is removed even if the transport
// teardown stalls.
//
// It runs DETACHED, and that is not incidental. The script deletes the very account
// the SSH session is running as, and `userdel` refuses while a process of that user
// is alive — a foreground run would remove the config, fail on both accounts, and
// leave the host half-torn-down with no login. So the outer command writes a script,
// launches it with setsid, and returns; the script waits for the session to end,
// then does the work and removes itself. Output goes to /var/log/fleet-unenroll.log
// so an operator can see what happened on a host Fleet can no longer reach.
//
// Only paths Fleet created are touched. authorized_keys, other sudoers files, and
// any sshd configuration Fleet did not write are left exactly as they are, and sshd
// is reloaded only if `sshd -t` still passes after the removal — a host whose
// remaining config is broken keeps the running sshd it has rather than being cut off
// by the cleanup.
func (s *Service) hostTeardownScript(loginUser, overlayRetire string) string {
	return fmt.Sprintf(`set +e
LOGIN='%s'
NOSUDO="${LOGIN}-login"
cat > /usr/local/sbin/fleet-unenroll.sh <<'FLEETEOF'
#!/bin/sh
# Written by Fleet Terminal when the host was removed from its inventory.
# Removes Fleet's accounts and SSH trust, then deletes itself.
set +e
LOGIN="$1"
NOSUDO="${LOGIN}-login"
echo "[fleet] unenroll started $(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)"
# Let the SSH session that launched this close, so userdel can take the account.
sleep 8
rm -f /etc/sudoers.d/fleet
rm -f /etc/ssh/fleet_ca.pub /etc/ssh/fleet_krl
rm -f /etc/ssh/auth_principals/"$LOGIN" /etc/ssh/auth_principals/"$NOSUDO"
rmdir /etc/ssh/auth_principals 2>/dev/null
rm -f /etc/ssh/sshd_config.d/00-fleet.conf
# Hosts whose sshd_config has no Include got the directives appended under a
# "# Fleet Terminal" marker. Drop exactly that block, nothing else.
if grep -q '^# Fleet Terminal$' /etc/ssh/sshd_config 2>/dev/null; then
  cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.fleet-backup
  awk '
    /^# Fleet Terminal$/ { skip=1; next }
    skip && /^(PubkeyAuthentication|TrustedUserCAKeys|AuthorizedPrincipalsFile) / { next }
    skip { skip=0 }
    { print }
  ' /etc/ssh/sshd_config.fleet-backup > /etc/ssh/sshd_config.fleet-new &&
    mv -f /etc/ssh/sshd_config.fleet-new /etc/ssh/sshd_config
fi
# Reload only if the remaining config is valid; a broken one keeps the running sshd.
if sshd -t 2>/dev/null; then
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || \
    service sshd reload 2>/dev/null || service ssh reload 2>/dev/null || pkill -HUP sshd 2>/dev/null
  echo "[fleet] sshd reloaded"
else
  echo "[fleet] WARNING: sshd -t failed after cleanup; sshd NOT reloaded, config left in place"
  [ -f /etc/ssh/sshd_config.fleet-backup ] && mv -f /etc/ssh/sshd_config.fleet-backup /etc/ssh/sshd_config
fi
for U in "$LOGIN" "$NOSUDO"; do
  id "$U" >/dev/null 2>&1 || continue
  pkill -KILL -u "$U" 2>/dev/null
  sleep 1
  userdel -r "$U" 2>/dev/null || deluser --remove-home "$U" 2>/dev/null || userdel "$U" 2>/dev/null
  if id "$U" >/dev/null 2>&1; then echo "[fleet] WARNING: could not remove account $U"; else echo "[fleet] removed account $U"; fi
done
rm -f /etc/ssh/sshd_config.fleet-backup
# The overlay LAST: it is the transport Fleet arrived over, and a host that keeps a
# live tunnel to the jump host after being deleted is still on the fleet's network
# with nothing left that manages or audits it.
echo "[fleet] retiring the overlay transport"
%s
echo "[fleet] unenroll finished"
rm -f /usr/local/sbin/fleet-unenroll.sh
FLEETEOF
chmod 0700 /usr/local/sbin/fleet-unenroll.sh
setsid nohup /usr/local/sbin/fleet-unenroll.sh "$LOGIN" >/var/log/fleet-unenroll.log 2>&1 < /dev/null &
echo TEARDOWN_STARTED`, loginUser, overlayRetire)
}

// hostOverlayRetireScript returns the privileged script that takes host's transport
// down on the host itself AND destroys the material it could reconnect with.
//
// This is the PURGE variant, not the retire one. Retiring is for a transport switch
// and keeps the key material on purpose; a teardown means the host is leaving, and
// what retiring leaves behind — a renamed but complete config next to its ca/cert/key
// — reconnects the moment anyone points openvpn at it. A cert overlay whose
// provisioner this deployment does not have leaves a loud note in the teardown log
// rather than being silently skipped.
func (s *Service) hostOverlayRetireScript(host *models.Host) string {
	name := strings.TrimSpace(host.Overlay)
	if !overlay.IsCertOverlay(name) {
		return s.wgPurgeScript()
	}
	ov := s.overlays[name]
	if ov == nil {
		return "echo '[fleet] WARNING: overlay " + name + " is not available on this deployment; " +
			"its client is STILL RUNNING and its key material is STILL PRESENT — " +
			"stop it and remove /etc/openvpn/fleet on the host by hand'"
	}
	return ov.PurgeHostScript().Script
}

// TeardownHost removes Fleet's footprint from a managed host: the NOPASSWD sudoers
// grant, the two shared accounts, the CA trust, the principal files, the sshd
// drop-in, and the overlay client. Without it, deleting a host from Fleet leaves a
// standing root account, a trusted CA, and a live tunnel onto the fleet's network on
// a machine Fleet no longer manages or audits.
//
// It must run BEFORE the overlay membership is retired — that cleanup removes the
// jump host's route to the host, and the teardown has to reach the host to run.
//
// The work itself is detached on the host (see hostTeardownScript), so a nil return
// means the teardown was successfully STARTED, not that it finished; the host is
// about to drop its Fleet accounts and will be unreachable from Fleet thereafter.
// A host that is already unreachable returns an error and is left untouched — the
// operator's recourse is scripts/fleet-unenroll.sh, run locally on the machine.
func (s *Service) TeardownHost(ctx context.Context, host *models.Host) error {
	if host == nil {
		return nil
	}
	loginUser := strings.TrimSpace(host.SSHUser)
	if loginUser == "" {
		loginUser = "fleet"
	}
	var lastErr error
	for _, addr := range dedupeAddrs(host.WGAddress, host.Address, host.Hostname) {
		conn, err := s.gw.DialSystemForHost(ctx, host.ID, addr, host.SSHPort, loginUser)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", addr, err)
			continue
		}
		script := s.hostTeardownScript(loginUser, s.hostOverlayRetireScript(host))
		out, rerr := run(conn.Client, "sudo sh -c "+shellQuote(script))
		conn.Close()
		if rerr != nil || !strings.Contains(out, "TEARDOWN_STARTED") {
			return fmt.Errorf("start teardown on %s: %w (%s)", addr, orErr(rerr, out), oneLine(strings.TrimSpace(out)))
		}
		s.log.Info("host teardown started", "host", host.Hostname, "addr", addr, "account", loginUser)
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reachable address")
	}
	return fmt.Errorf("connect to host: %w", lastErr)
}

// dedupeAddrs returns the non-empty addresses in order, without duplicates.
func dedupeAddrs(addrs ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// RevokeHostOverlayCerts revokes the client certificates issued to a host on a
// certificate overlay, so the certificate itself stops being accepted rather than
// merely losing its pinned address.
//
// It MUST run before the host row is deleted. overlay_clients.host_id cascades on
// host delete, so once the host is gone there is nothing left to say which serial
// was its — the revocation would have nothing to revoke. The record it writes lives
// in overlay_revocations, which has no host reference and outlives the host.
//
// A WireGuard host needs none of this: the hub's peer list is an allowlist, so
// removing the peer is itself the revocation.
func (s *Service) RevokeHostOverlayCerts(ctx context.Context, host *models.Host) (int, error) {
	if host == nil {
		return 0, nil
	}
	name := strings.TrimSpace(host.Overlay)
	if !overlay.IsCertOverlay(name) {
		return 0, nil
	}
	if s.pki == nil {
		return 0, fmt.Errorf("overlay PKI unavailable")
	}
	n, err := s.pki.RevokeHostClients(ctx, host.ID, "host deleted from Fleet")
	if err != nil {
		return 0, err
	}
	if n > 0 {
		s.log.Info("revoked overlay client certificates", "host", host.Hostname, "count", n)
	}
	return n, nil
}

// CleanupHostOverlay retires a deleted host's membership of whichever overlay it was
// on, from the jump host: a WireGuard peer (kernel entry + persisted fragment) or a
// certificate overlay's pinned address.
//
// It has to branch on the host's overlay because the two leave different things
// behind, and a leftover from the wrong one is not harmless: both pin the host's
// address, so whichever is left keeps answering for an address the next host may be
// given. Best-effort — enrollment also retires stale claims inline (see
// jumpPeerScript), so a failure here (jump unreachable) self-heals on the next
// enrollment that reuses the address.
func (s *Service) CleanupHostOverlay(ctx context.Context, host *models.Host) error {
	if host == nil {
		return nil
	}
	// A SYSTEM certificate, not a session one. This ran with uuid.New().String() as
	// the session id — an id that by construction has no credential in the vault — so
	// the dial failed with "no live credential for session" every single time and the
	// jump-host half of the cleanup never ran. It is called from a goroutine that only
	// logs, so nothing surfaced: deleted hosts kept a live peer on the hub, and their
	// tunnels kept handshaking.
	jumpClient, err := s.gw.DialJumpSystem(ctx)
	if err != nil {
		return fmt.Errorf("connect jump host: %w", err)
	}
	defer jumpClient.Close()

	if name := strings.TrimSpace(host.Overlay); overlay.IsCertOverlay(name) {
		ov := s.overlays[name]
		if ov == nil {
			return fmt.Errorf("overlay %q is not available on this deployment", name)
		}
		detail, rerr := ov.RetireJump(ctx, host.ID, func(script string) (string, error) {
			return run(jumpClient, "sudo sh -c "+shellQuote(script))
		})
		if rerr != nil {
			return rerr
		}
		s.log.Info("retired overlay membership on the jump host",
			"host", host.Hostname, "overlay", name, "result", detail)
		return nil
	}

	out, err := run(jumpClient, "sudo sh -c "+shellQuote(s.jumpPeerCleanupScript(host.Hostname)))
	if err != nil {
		return fmt.Errorf("remove jump peer: %w (%s)", err, strings.TrimSpace(out))
	}
	s.log.Info("removed jump-host wireguard peer", "host", host.Hostname, "result", strings.TrimSpace(out))
	return nil
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
# Minimal hosts (Alpine, trimmed images) have no bash; an account pointed at a
# missing shell can't take a session even once its certificate is accepted.
FLEETSHELL=/bin/bash
[ -x "$FLEETSHELL" ] || FLEETSHELL=/bin/sh
for U in "$LOGIN" "$NOSUDO"; do
  id "$U" >/dev/null 2>&1 && continue
  # useradd on glibc distros, adduser on busybox. Keep whichever error came out:
  # both failing must be fatal, not swallowed — a host that trusts the CA but has
  # no account to map principals onto accepts no one, and the failure would
  # otherwise surface much later as an unexplained login rejection.
  useradd -m -s "$FLEETSHELL" "$U" 2>&1 || adduser -D -s "$FLEETSHELL" "$U" 2>&1 || true
  id "$U" >/dev/null 2>&1 || { echo "[fleet] FAILED to create account $U"; exit 1; }
done
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
