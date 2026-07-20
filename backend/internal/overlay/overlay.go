// Package overlay provisions Fleet's host-reachability transports. WireGuard is
// handled inline by the enrollment package; the certificate-authenticated overlays
// (OpenVPN, strongSwan/IPsec) implement the Overlay interface here so enrollment can
// treat them uniformly and select one per host. All cert overlays share the X.509
// overlay PKI and the wg_address-based addressing, so the SSH gateway stays
// overlay-agnostic.
package overlay

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// RunFunc runs a shell script with privilege on a target and returns its combined
// output. The enrollment layer supplies two of these per host: one that runs on the
// managed host (privileged) and one that runs on the jump host (sudo).
type RunFunc func(script string) (string, error)

// Overlay is a certificate-authenticated VPN transport a host can be enrolled onto.
// Implementations are stateless request builders: they generate config + provisioning
// scripts and issue certs from the shared overlay PKI; the enrollment layer runs the
// scripts over SSH and owns address assignment.
type Overlay interface {
	// Name is the FLEET_OVERLAY value this overlay answers to ("openvpn", "strongswan").
	Name() string

	// EnsureServer idempotently provisions and starts the VPN server on the jump host
	// (installing packages, writing CA/server material + config, starting the daemon
	// only if not already running). Safe to call on every enrollment.
	EnsureServer(ctx context.Context, jumpRun RunFunc) error

	// ProvisionHost issues the host's client certificate, pins its overlay address on
	// the jump server (spoof-proof, keyed by the cert identity), and brings up the
	// tunnel on the host. endpoint is the jump address the host dials. It returns a
	// short human detail for the enrollment step log.
	ProvisionHost(ctx context.Context, hostID uuid.UUID, overlayIP, endpoint string, hostRun, jumpRun RunFunc) (detail string, err error)
}

// IsCertOverlay reports whether name selects a certificate-authenticated overlay
// (OpenVPN / strongSwan) rather than WireGuard. Empty and "wireguard" are WireGuard.
func IsCertOverlay(name string) bool {
	return name == "openvpn" || name == "strongswan"
}

// oneLine collapses a script's multi-line output to a single trimmed line for error
// messages (shared by the cert-overlay provisioners).
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
