package enrollment

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/overlay"
	"github.com/fleet-terminal/backend/internal/sshgw"
)

// enrollCertOverlay provisions a certificate-authenticated overlay (OpenVPN)
// for a host in place of WireGuard: it assigns the host a stable overlay
// address, brings up the VPN server on the jump host, and provisions the host onto the
// tunnel. The assigned address is returned and stored in the same wg_address column
// WireGuard uses, so the SSH gateway dials the host identically regardless of overlay.
// The specific overlay's mechanics live behind the overlay.Overlay interface; this
// method owns only the shared address assignment, endpoint resolution, and step log.
func (s *Service) enrollCertOverlay(
	ctx context.Context,
	ov overlay.Overlay,
	host *models.Host,
	jumpClient *ssh.Client,
	priv func(string) (string, error),
	params EnrollParams,
	step func(name, status, detail string),
) (overlayIP string, err error) {
	// Assign this host's address on the cert overlay's own pool. A host arriving from
	// WireGuard is renumbered here — the plans are deliberately different subnets.
	p := s.plan(ov.Name())
	overlayIP, err = s.assignOverlayAddress(ctx, host, p)
	if err != nil {
		return "", err
	}

	// jumpRun runs a privileged script on the jump host; hostRun (priv) runs one on the
	// managed host. The overlay provisioner supplies the scripts; we run them.
	jumpRun := func(script string) (string, error) {
		return run(jumpClient, "sudo sh -c "+shellQuote(script))
	}

	// 1) Bring up the VPN server on the jump host (idempotent).
	serverDetail, err := ov.EnsureServer(ctx, jumpRun)
	if err != nil {
		return "", fmt.Errorf("provision %s server: %w", ov.Name(), err)
	}
	step("configure_jump_server", "ok", serverDetail)

	// 2) Provision the host onto the tunnel (issue cert, pin address, bring up). The
	//    endpoint host follows the same precedence as WireGuard; the overlay applies its
	//    own port.
	endpoint := strings.TrimSpace(params.WGEndpoint)
	if endpoint == "" {
		endpoint = s.store.WireGuardEndpoint(ctx)
	}
	if endpoint == "" {
		endpoint = s.cfg.WGJumpEndpoint
	}
	detail, err := ov.ProvisionHost(ctx, host.ID, overlayIP, endpoint, priv, jumpRun)
	if err != nil {
		return "", err
	}
	step("configure_host_overlay", "ok", detail)

	// 3) Prove the tunnel end to end, from the jump host to the overlay address. Both
	//    ends reporting healthy is not the same as a data plane: the host can hold a
	//    tun device while the jump host has no route to it. This is also the check the
	//    WireGuard teardown is gated on, and the reason it has to be specific to the
	//    overlay address — every other verification in enrollment falls back to the
	//    host's management address, so all of them pass over the LAN with no tunnel at
	//    all, which is exactly how a never-started overlay collected a row of green
	//    steps and then took its host offline.
	if err := s.verifyOverlayReachable(ctx, jumpClient, overlayIP, host.SSHPort); err != nil {
		return "", fmt.Errorf("%s tunnel is not carrying traffic: %w", ov.Name(), err)
	}
	step("verify_overlay_tunnel", "ok",
		fmt.Sprintf("jump host reached %s:%d over the %s tunnel", overlayIP, host.SSHPort, ov.Name()))

	return overlayIP, nil
}

// verifyOverlayReachable dials the host's overlay address FROM the jump host, which is
// the path every Fleet session takes. It is deliberately narrow: no management-address
// fallback, no hostname, nothing that can succeed while the overlay is dead.
func (s *Service) verifyOverlayReachable(ctx context.Context, jumpClient *ssh.Client, overlayIP string, port int) error {
	if port <= 0 {
		port = 22
	}
	// Bounded: a black-holed overlay address does not refuse the connection, it hangs,
	// and DialContext through the jump host would otherwise wait minutes.
	dctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	conn, err := jumpClient.DialContext(dctx, "tcp", net.JoinHostPort(overlayIP, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("no route from the jump host to %s:%d (%v)", overlayIP, port, err)
	}
	_ = conn.Close()
	return nil
}

// overlayPlan is one transport's address plan: the subnet its hosts are numbered
// from and the jump host's own address on it.
//
// The two overlays MUST have different plans on a deployment that runs both. They
// terminate on the same jump host and each puts its jump address on its own
// interface, so one shared subnet gives that host two connected routes for the same
// prefix — the kernel resolves that once, for the whole subnet, not per host, and
// every host behind the losing interface becomes unreachable. Separate plans are
// what make a per-host transport choice (and switching a host between transports)
// work at all.
type overlayPlan struct {
	Name   string
	Subnet string
	JumpIP string
}

// plan resolves the address plan for an overlay name. Anything that is not a
// certificate overlay is WireGuard, matching effectiveOverlay's normalization.
func (s *Service) plan(name string) overlayPlan {
	if overlay.IsCertOverlay(name) {
		return overlayPlan{Name: name, Subnet: s.cfg.OVPNSubnet, JumpIP: s.cfg.OVPNJumpIP}
	}
	return overlayPlan{Name: "wireguard", Subnet: s.cfg.WGSubnet, JumpIP: s.cfg.WGJumpIP}
}

// assignOverlayAddress resolves the address a host should hold on the overlay it is
// enrolling onto: the one it already has when that address belongs to this plan,
// otherwise the next free address in the plan's pool.
//
// The "belongs to this plan" test is what makes switching transports work. Each
// overlay numbers hosts from its own subnet, so a host moving between them cannot
// keep its address — and silently keeping it would hand the host an address that
// routes into the transport it just left. Reassignment is therefore the normal case
// on a switch, and callers must treat the returned address as possibly new.
func (s *Service) assignOverlayAddress(ctx context.Context, host *models.Host, p overlayPlan) (string, error) {
	cur := strings.TrimSpace(host.WGAddress)
	if cur != "" && isOverlayAddr(cur, p.JumpIP) {
		if inUse, _ := s.store.WGAddressInUse(ctx, cur, host.ID); inUse {
			return "", fmt.Errorf("overlay address %s is already assigned to another host", cur)
		}
		return cur, nil
	}
	next, err := s.store.NextFreeWGAddress(ctx, p.JumpIP)
	if err != nil {
		return "", fmt.Errorf("assign an address on the %s overlay (%s): %w", p.Name, p.Subnet, err)
	}
	return next, nil
}

// releaseOverlayAddress drops the SSH host-key pin held for an overlay address a host
// has just been renumbered off.
//
// The pin is keyed by address, so the stale one is inert while nothing dials it — but
// overlay addresses are recycled, and the next host to be assigned this one would
// inherit a pin for the previous host's key and be refused every connection. Only the
// released address is cleared; the host's management-address and hostname pins are
// still valid and re-opening trust-on-first-use for them would be a needless window.
// Callers pass the address the host is moving OFF and have already established that
// it differs from the new one — host.WGAddress still holds the old value at that
// point, so this must not second-guess them by comparing against it.
func (s *Service) releaseOverlayAddress(ctx context.Context, host *models.Host, oldIP string) {
	oldIP = strings.TrimSpace(oldIP)
	if oldIP == "" {
		return
	}
	ids := sshgw.HostKeyIDs(host.SSHPort, oldIP)
	if _, err := s.store.DeleteHostKeys(ctx, ids); err != nil {
		s.log.Warn("could not release host key pin for a renumbered overlay address",
			"host", host.Hostname, "address", oldIP, "err", err)
		return
	}
	if s.gw != nil {
		s.gw.ForgetHostKeys(ids...)
	}
}
