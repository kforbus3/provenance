// Package overlay provisions Fleet's host-reachability transports. WireGuard is
// handled inline by the enrollment package; the certificate-authenticated overlays
// (OpenVPN) implement the Overlay interface here so enrollment can treat them
// uniformly and select one per host. All cert overlays share the X.509 overlay PKI.
//
// A host's assigned address lives in the one wg_address column whichever transport
// assigned it, so the SSH gateway and every other consumer stay overlay-agnostic —
// but the POOL it is drawn from is per-overlay (FLEET_OVPN_SUBNET vs
// FLEET_WG_SUBNET). Both transports terminate on the same jump host and each claims
// its own address on its own interface, so a shared subnet would give that host two
// connected routes for one prefix and strand every host behind the losing one.
// Switching a host between transports therefore renumbers it.
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
	// Name is the FLEET_OVERLAY value this overlay answers to ("openvpn").
	Name() string

	// EnsureServer idempotently provisions and starts the VPN server on the jump host
	// (installing packages, writing CA/server material + config, starting the daemon
	// only if not already running). Safe to call on every enrollment. Like
	// ProvisionHost it returns a short human detail for the enrollment step log —
	// which is how a peer-isolation rule that could not be applied reaches the
	// operator instead of failing silently.
	EnsureServer(ctx context.Context, jumpRun RunFunc) (detail string, err error)

	// ProvisionHost issues the host's client certificate, pins its overlay address on
	// the jump server (spoof-proof, keyed by the cert identity), and brings up the
	// tunnel on the host. endpoint is the jump address the host dials. It returns a
	// short human detail for the enrollment step log.
	ProvisionHost(ctx context.Context, hostID uuid.UUID, overlayIP, endpoint string, hostRun, jumpRun RunFunc) (detail string, err error)

	// PrepareHost is ProvisionHost without the host half: it issues the client
	// certificate and pins the address on the jump server, then RETURNS the privileged
	// script that brings the tunnel up on the host instead of running it. The
	// no-install enrollment flow needs this, because there Fleet never connects to the
	// host at all — the operator pipes the script over their own ssh and runs it.
	// ProvisionHost is PrepareHost plus hostRun.
	PrepareHost(ctx context.Context, hostID uuid.UUID, overlayIP, endpoint string, jumpRun RunFunc) (HostBringup, error)

	// RetireJump removes the hub half of this host's membership — its pinned address,
	// so the overlay stops answering for a host that has moved to another transport
	// and the address can be reissued. Idempotent: a host that was never on this
	// overlay is not an error.
	RetireJump(ctx context.Context, hostID uuid.UUID, jumpRun RunFunc) (detail string, err error)

	// RetireHostScript is the privileged script that takes this overlay down on the
	// managed host: stop the client, keep it from coming back on boot, and set its
	// config aside. Returned rather than run so the no-install flow can carry it in
	// the bootstrap script, exactly as PrepareHost's is.
	//
	// Switching transports is only complete when the old one is gone from BOTH ends.
	// Leaving a client running means two interfaces racing for the host's traffic and
	// a tunnel that quietly reconnects to an overlay the host has left.
	//
	// It deliberately KEEPS the client's key material, because a host switched to
	// another transport and back re-uses the certificate Fleet already issued it. Use
	// PurgeHostScript when the host is leaving the fleet.
	RetireHostScript() HostBringup

	// PurgeHostScript is RetireHostScript for a host that is being decommissioned: it
	// retires the client AND destroys the material it could reconnect with.
	//
	// The distinction is the whole point. Retiring renames the config and leaves
	// ca/cert/key in place, so the config left behind is complete and still works —
	// moving it back, or pointing openvpn straight at it, rejoins the overlay. That is
	// correct for a transport switch and wrong for a host that is leaving, where what
	// is left behind is a working credential on a machine nothing manages any more.
	//
	// Deleting the host's copy is necessary but not sufficient on its own: a key
	// copied off the host earlier still authenticates. Revocation (the CRL) is what
	// makes it final; this makes the common case clean.
	PurgeHostScript() HostBringup
}

// HostBringup is the host-side half of overlay provisioning: a privileged script and
// the marker its successful run prints. Callers that run the script themselves check
// Marker to tell a real bring-up from a script that merely exited 0.
type HostBringup struct {
	Script string
	Marker string
}

// IsCertOverlay reports whether name selects a certificate-authenticated overlay
// (OpenVPN) rather than WireGuard. Empty and "wireguard" are WireGuard.
func IsCertOverlay(name string) bool {
	return name == "openvpn"
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
