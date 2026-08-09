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
	// Assign the overlay address: honor an operator-specified one, else auto-assign the
	// next free address in the overlay subnet (same logic as WireGuard, uniform across
	// overlays).
	overlayIP = strings.TrimSpace(host.WGAddress)
	if overlayIP != "" {
		if !isOverlayAddr(overlayIP, s.cfg.WGJumpIP) {
			return "", fmt.Errorf("overlay address %q is not in the overlay subnet %s", overlayIP, s.cfg.WGSubnet)
		}
		if inUse, _ := s.store.WGAddressInUse(ctx, overlayIP, host.ID); inUse {
			return "", fmt.Errorf("overlay address %s is already assigned to another host", overlayIP)
		}
	} else {
		overlayIP, err = s.store.NextFreeWGAddress(ctx, s.cfg.WGJumpIP)
		if err != nil {
			return "", err
		}
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
