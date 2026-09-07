import {
  Alert, Box, Button, Chip, Paper, Stack, Table, TableBody, TableCell,
  TableHead, TableRow, Tooltip, Typography,
} from "@mui/material";
import RefreshIcon from "@mui/icons-material/Refresh";
import AddTaskIcon from "@mui/icons-material/AddTask";
import { useQuery } from "@tanstack/react-query";
import { listProvisioningClients, type ProvisioningClient } from "../../api/imaging";

// Machines currently on the provisioning network.
//
// This is the answer to "I booted the machine, now what is its MAC?". PXE-boot
// it on the provisioning segment and it appears here announcing its own
// address, which you hand straight to a per-machine image assignment. The
// alternative is reading a MAC off a sticker in a rack, or out of a
// hypervisor's settings page, once per machine, before you can do anything.
//
// Derived from the PXE stack's own logs over a short window, so it answers "who
// is waiting right now" rather than "who has ever booted". A machine that has
// finished and rebooted into its image drops off deliberately: it is no longer
// waiting for an assignment, and a list that only grows stops being a worklist.
// What happened historically is the machines table and the audit log.

// The stack reports its own vocabulary; this puts each state on a scale the
// reader can act on. "waiting" is the one that wants a click.
const EVENT_STYLE: Record<string, { color: "default" | "info" | "success" | "warning"; help: string }> = {
  "got boot info": {
    color: "warning",
    help: "It has a lease and boot instructions and is asking what to do. Assign it an image.",
  },
  "downloading bootloader": {
    color: "info",
    help: "Fetching the network bootloader over TFTP. It will ask for its image next.",
  },
  "PXE booting": {
    color: "info",
    help: "Firmware is talking to the provisioning server.",
  },
  "booting imager": {
    color: "info",
    help: "Running the imager. It is about to ask which image to write.",
  },
};

export function DiscoveredMachines({ onAssign, assignedMacs, canProvision }: {
  onAssign: (mac: string) => void;
  assignedMacs: Set<string>;
  canProvision: boolean;
}) {
  // Polled, because a machine you have just powered on should appear without
  // the reader wondering whether to reload the page. Short, because the whole
  // window this reads is only fifteen minutes wide.
  const { data: clients = [], isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["provisioning-clients"],
    queryFn: listProvisioningClients,
    refetchInterval: 5000,
    // Keep polling while the tab is in the background. The whole workflow is
    // "power the machine on, watch it boot, come back here", so the tab is
    // hidden for exactly the period this list needs to be updating -- and
    // without this, React Query pauses the interval and you return to a stale
    // list that a page reload was the only way to clear.
    refetchIntervalInBackground: true,
    // And refetch the moment the tab is focused, overriding the app-wide
    // default of false. Coming back to this page IS the request to see what is
    // on the network now.
    refetchOnWindowFocus: true,
    // Never serve this from cache: a list of who is booting right now is stale
    // the moment it is stored.
    staleTime: 0,
    gcTime: 0,
  });

  return (
    <Box sx={{ mb: 3 }}>
      <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="subtitle2">On the provisioning network now</Typography>
          <Typography variant="body2" color="text.secondary">
            Machines that have PXE-booted in the last few minutes. Assign one an image
            here rather than looking its MAC address up first.
          </Typography>
        </Box>
        <Tooltip title="Refresh">
          <span>
            <Button size="small" startIcon={<RefreshIcon />} disabled={isFetching}
                    onClick={() => void refetch()}>
              Refresh
            </Button>
          </span>
        </Tooltip>
      </Stack>

      {isError && (
        <Alert severity="error" sx={{ mb: 1 }}>
          Could not read the provisioning network. The stack has to be running for
          this to show anything — check its status above.
        </Alert>
      )}

      <Paper variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>MAC address</TableCell>
              <TableCell>Address</TableCell>
              <TableCell>Doing</TableCell>
              <TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {clients.map((c: ProvisioningClient) => {
              const style = EVENT_STYLE[c.event];
              // A MAC dnsmasq never saw — the LAN's own DHCP answered and only
              // the HTTP fetch reached us. Real, and not assignable by MAC.
              const macUnknown = !c.mac || c.mac === "—";
              const already = !macUnknown && assignedMacs.has(c.mac.toLowerCase());
              return (
                <TableRow key={c.mac === "—" ? c.ip : c.mac} hover>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: 13 }}>
                    {macUnknown ? <em>not seen</em> : c.mac}
                  </TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: 13 }}>{c.ip || "—"}</TableCell>
                  <TableCell>
                    <Tooltip title={style?.help ?? ""}>
                      <Chip size="small" variant="outlined"
                            color={style?.color ?? "default"}
                            label={c.event || "seen"} />
                    </Tooltip>
                  </TableCell>
                  <TableCell align="right">
                    {already ? (
                      <Chip size="small" color="success" variant="outlined" label="assigned" />
                    ) : (
                      <Tooltip title={macUnknown
                        ? "This machine's DHCP request was answered by another server, so the "
                          + "provisioning stack never saw its MAC. Assign it by hand, or run the "
                          + "stack in standalone DHCP mode on this segment."
                        : "Add a per-machine image assignment for this MAC"}>
                        <span>
                          <Button size="small" startIcon={<AddTaskIcon />}
                                  disabled={!canProvision || macUnknown}
                                  onClick={() => onAssign(c.mac)}>
                            Assign image
                          </Button>
                        </span>
                      </Tooltip>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
            {clients.length === 0 && (
              <TableRow>
                <TableCell colSpan={4}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                    {isLoading
                      ? "Looking…"
                      : "Nothing has PXE-booted in the last few minutes. Power on a machine "
                        + "on the provisioning network and it will appear here. If one is "
                        + "booting and does not show up, its DHCP request is being answered "
                        + "by another server on that segment."}
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>
    </Box>
  );
}
