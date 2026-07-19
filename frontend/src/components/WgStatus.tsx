import { Chip, Tooltip } from "@mui/material";
import GppMaybeIcon from "@mui/icons-material/GppMaybe";
import VpnLockIcon from "@mui/icons-material/VpnLock";
import type { Host } from "../api/hosts";

// A host is "WireGuard-degraded" when the overlay is configured for it
// (wgAddress set) and it is reachable, but the monitor could not confirm a
// healthy WireGuard tunnel. In that state connections still succeed by falling
// back to the host's direct address — they just aren't riding the encrypted
// overlay. Hosts with no wgAddress don't use WireGuard at all, so they are not
// flagged; offline hosts have a bigger problem than the overlay, so they aren't
// either.
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
export function WgDownChip({ size = "small" }: { size?: "small" | "medium" }) {
  return (
    <Tooltip title="WireGuard overlay is down for this host. Connections still work by falling back to the direct address (unless strict overlay mode is on, in which case they are refused). Check the host's WireGuard tunnel.">
      <Chip
        size={size}
        color="warning"
        variant="outlined"
        icon={<GppMaybeIcon />}
        label="WG down"
      />
    </Tooltip>
  );
}

// A host is confirmed "on WireGuard" when it has an overlay address and the
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

// WgOnChip is the affirmative badge: this host is reachable over the encrypted
// WireGuard overlay (tunnel confirmed healthy by the last probe).
export function WgOnChip({ size = "small" }: { size?: "small" | "medium" }) {
  return (
    <Tooltip title="Reachable over the encrypted WireGuard overlay (tunnel healthy at the last check). Terminal, file-transfer, and RDP sessions ride the overlay.">
      <Chip
        size={size}
        color="success"
        variant="outlined"
        icon={<VpnLockIcon />}
        label="WireGuard"
      />
    </Tooltip>
  );
}
