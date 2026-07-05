import { Chip, Tooltip } from "@mui/material";
import GppMaybeIcon from "@mui/icons-material/GppMaybe";
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
    <Tooltip title="WireGuard overlay is down for this host. Connections still work by falling back to the direct address, but they are not on the encrypted overlay. Check the host's WireGuard tunnel.">
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
