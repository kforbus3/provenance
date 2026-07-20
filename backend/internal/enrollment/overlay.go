package enrollment

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/overlay"
)

// enrollCertOverlay provisions a certificate-authenticated overlay (OpenVPN or
// strongSwan) for a host in place of WireGuard: it assigns the host a stable overlay
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
	if err := ov.EnsureServer(ctx, jumpRun); err != nil {
		return "", fmt.Errorf("provision %s server: %w", ov.Name(), err)
	}
	step("configure_jump_server", "ok", ov.Name()+" server ready on jump host")

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

	return overlayIP, nil
}
