import { Chip, Tooltip } from "@mui/material";
import GppMaybeIcon from "@mui/icons-material/GppMaybe";
import VpnLockIcon from "@mui/icons-material/VpnLock";
import type { Host } from "../api/hosts";

// A host's VPN transport, for display. An empty/absent overlay means WireGuard —
// that is what a host enrolled before per-host overlays existed records.
export function overlayLabel(overlay?: string): string {
  return overlay === "openvpn" ? "OpenVPN" : "WireGuard";
}

// Where an operator should look when this host's tunnel is down. The two transports
// have nothing in common at either end, so a generic "check the overlay" sends
// people to the wrong daemon on half the fleet.
function whereToLook(overlay?: string): string {
  return overlay === "openvpn"
    ? "Check the openvpn client on the host and the openvpn server on the jump host."
    : "Check the WireGuard tunnel on the host and the peer entry on the jump host.";
}

// A host is "overlay-degraded" when a VPN overlay is configured for it (wgAddress
// set — the column holds the assigned address whichever transport assigned it) and
// it is reachable, but the monitor could not confirm a healthy tunnel. In that state
// connections still succeed by falling back to the host's direct address — they just
// aren't riding the encrypted overlay. Hosts with no address don't use an overlay at
// all, so they are not flagged; offline hosts have a bigger problem than the overlay,
// so they aren't either.
export function wgDegraded(host: Pick<Host, "wgAddress" | "status">): boolean {
  return (
    !!host.wgAddress &&
    host.status?.status === "online" &&
    host.status?.wgOk === false
  );
}

// WgDownChip is the at-a-glance badge shown wherever hosts are listed. It is
// deliberately warning-colored (not error) because access is not lost — the
// connection has silently fallen back off the overlay.
export function WgDownChip({ overlay, size = "small" }: { overlay?: string; size?: "small" | "medium" }) {
  const name = overlayLabel(overlay);
  return (
    <Tooltip
      title={`The ${name} overlay is down for this host. Connections still work by falling back to the direct address (unless strict overlay mode is on, in which case they are refused). ${whereToLook(overlay)}`}
    >
      <Chip
        size={size}
        color="warning"
        variant="outlined"
        icon={<GppMaybeIcon />}
        label="VPN down"
      />
    </Tooltip>
  );
}

// A host is confirmed "on the overlay" when it has an overlay address and the
// monitor reached it over that address with a healthy tunnel (wgOk). This is the
// affirmative counterpart to WgDownChip: it lets you confirm at a glance that a
// host's sessions ride the encrypted overlay rather than inferring it from latency.
export function wgHealthy(host: Pick<Host, "wgAddress" | "status">): boolean {
  return (
    !!host.wgAddress &&
    host.status?.status === "online" &&
    host.status?.wgOk === true
  );
}

// WgOnChip is the affirmative badge, and it names the transport: which VPN a host is
// on is now a per-host choice, so a chip that always said "WireGuard" was wrong for
// every OpenVPN host — and wrong in the one place an operator would check it.
export function WgOnChip({ overlay, size = "small" }: { overlay?: string; size?: "small" | "medium" }) {
  const name = overlayLabel(overlay);
  return (
    <Tooltip
      title={`Reachable over the encrypted ${name} overlay (tunnel healthy at the last check). Terminal, file-transfer, and RDP sessions ride the overlay.`}
    >
      <Chip
        size={size}
        color="success"
        variant="outlined"
        icon={<VpnLockIcon />}
        label={name}
      />
    </Tooltip>
  );
}
