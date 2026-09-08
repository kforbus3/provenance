import { useEffect, useMemo, useState } from "react";
import {
  Alert, CircularProgress, Box, Button, Chip, Divider, Grid, IconButton, MenuItem, Paper,
  Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip,
  Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import StopIcon from "@mui/icons-material/Stop";
import RefreshIcon from "@mui/icons-material/Refresh";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { DiscoveredMachines } from "./DiscoveredMachines";
import {
  getProvisioning, setProvisioningEnv, steerProvisioning, listAssignments, saveAssignments,
  type Assignment, type NetInterface,
} from "../../api/imaging";
import { rangeWithin } from "./net";

// ProvisioningTab drives the PXE stack: pick the network the machines are on,
// pick the image to write, start the server.
//
// The interface choice is the whole point of the page. DHCP and TFTP are bound to
// that NIC alone, so they cannot reach — or disturb — any other network the host
// is attached to, and getting it wrong is the failure that matters here: a
// standalone DHCP server on the office LAN competes with the one already there.

export function ProvisioningTab({ images, canProvision, setMsg }: {
  images: string[];
  canProvision: boolean;
  setMsg: (text: string, kind?: "success" | "error") => void;
}) {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["imaging-provisioning"],
    queryFn: getProvisioning,
    // The stack is started and stopped from here; reflect that without a reload.
    refetchInterval: 10000,
  });
  const { data: assignments = [] } = useQuery({
    queryKey: ["imaging-assignments"], queryFn: listAssignments,
  });

  const [cfg, setCfg] = useState<Record<string, string>>({});
  const [advanced, setAdvanced] = useState(false);
  const [rows, setRows] = useState<Assignment[] | null>(null);

  // Server state is the source of truth until the operator edits something; once
  // they have, refetches must not overwrite what they are typing.
  const [dirty, setDirty] = useState(false);
  useEffect(() => {
    if (data?.env && !dirty) setCfg(data.env);
  }, [data?.env, dirty]);

  // Memoised because the `?? []` fallback is a fresh array on every render, which
  // would make the selected-interface memo below recompute every time.
  const ifaces = useMemo(() => data?.interfaces?.interfaces ?? [], [data?.interfaces?.interfaces]);
  const suggestion = data?.interfaces?.suggestion ?? {};
  const running = data?.status?.running ?? false;
  const problems = data?.problems ?? [];
  const rowsShown = rows ?? assignments;

  const selected = useMemo(
    () => ifaces.find((i) => i.name === cfg.INTERFACE),
    [ifaces, cfg.INTERFACE],
  );

  const set = (k: string, v: string) => { setDirty(true); setCfg((c) => ({ ...c, [k]: v })); };

  // Choosing an interface fills in everything derivable from it. A NIC with no
  // IPv4 is the normal case for a dedicated provisioning port, and gets the
  // proposed free subnet; one that already has an address keeps it and gets a
  // lease range inside its own network.
  function selectInterface(name: string) {
    setDirty(true);
    const i = ifaces.find((f) => f.name === name);
    if (!i) { setCfg((c) => ({ ...c, INTERFACE: name })); return; }
    if (!i.ip) {
      setCfg((c) => ({
        ...c,
        INTERFACE: i.name,
        SERVER_IP: suggestion.SERVER_IP ?? "",
        SERVER_PREFIXLEN: String(suggestion.prefixlen ?? 24),
        DHCP_NETMASK: suggestion.DHCP_NETMASK ?? "",
        PROXY_SUBNET: suggestion.PROXY_SUBNET ?? "",
        DHCP_RANGE_START: suggestion.DHCP_RANGE_START ?? "",
        DHCP_RANGE_END: suggestion.DHCP_RANGE_END ?? "",
      }));
      return;
    }
    const r = rangeWithin(i.network, i.prefixlen);
    setCfg((c) => ({
      ...c,
      INTERFACE: i.name,
      SERVER_IP: i.ip,
      SERVER_PREFIXLEN: String(i.prefixlen),
      DHCP_NETMASK: i.netmask,
      PROXY_SUBNET: i.network,
      DHCP_RANGE_START: r?.start ?? "",
      DHCP_RANGE_END: r?.end ?? "",
    }));
  }

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["imaging-provisioning"] });
    void qc.invalidateQueries({ queryKey: ["imaging-assignments"] });
  };

  const save = useMutation({
    mutationFn: () => setProvisioningEnv(cfg),
    onSuccess: () => { setDirty(false); setMsg("Provisioning settings saved."); refresh(); },
    onError: (e) => setMsg(errText(e, "Could not save the provisioning settings."), "error"),
  });

  const steer = useMutation({
    mutationFn: (verb: "up" | "down") => steerProvisioning(verb),
    onSuccess: (_out, verb) => {
      setMsg(verb === "up" ? "Provisioning server started." : "Provisioning server stopped.");
      refresh();
    },
    onError: (e) => setMsg(errText(e, "Could not change the provisioning server's state."), "error"),
  });

  const saveRows = useMutation({
    mutationFn: (items: Assignment[]) => saveAssignments(items),
    onSuccess: (out) => { setRows(null); qc.setQueryData(["imaging-assignments"], out); setMsg("Per-machine images saved."); },
    onError: (e) => setMsg(errText(e, "Could not save the per-machine images."), "error"),
  });

  const noBuilder = problems.some((p) => /builder|runner|501/i.test(p));

  // Nothing is rendered until the saved settings are in hand.
  //
  // cfg starts empty and is filled by the effect above once the query resolves,
  // so rendering before then showed the form's own defaults and then replaced
  // them a moment later with what was actually saved. That reads as the page
  // losing your settings, and it invites someone to "fix" a value that was
  // never wrong -- and then save the defaults over the real configuration.
  if (isLoading && !data) {
    return (
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, py: 4 }}>
        <CircularProgress size={24} />
        <Typography variant="body2" color="text.secondary">
          Loading the provisioning settings…
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }} spacing={1}>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
            Provisioning server{" "}
            <Chip
              size="small"
              color={running ? "success" : "default"}
              variant={running ? "filled" : "outlined"}
              label={running ? "running" : "stopped"}
            />
          </Typography>
          <Typography variant="body2" color="text.secondary">
            PXE/iPXE network imaging. DHCP and TFTP are bound to the one interface you
            pick, so no other network the host is on can see them.
          </Typography>
        </Box>
        <Tooltip title="Refresh"><IconButton onClick={refresh}><RefreshIcon /></IconButton></Tooltip>
        {running ? (
          <Button
            variant="outlined" color="error" startIcon={<StopIcon />}
            disabled={!canProvision || steer.isPending}
            onClick={() => steer.mutate("down")}
          >
            Stop
          </Button>
        ) : (
          <Button
            variant="contained" startIcon={<PlayArrowIcon />}
            disabled={!canProvision || steer.isPending}
            onClick={() => steer.mutate("up")}
          >
            Start
          </Button>
        )}
      </Stack>

      {!canProvision && (
        <Alert severity="info" sx={{ mb: 2 }}>
          You can see this configuration but not change it — that needs the
          <code> Imaging.Provision</code> permission. It is separate from the rest of
          imaging because this is the part that puts a DHCP server on a network.
        </Alert>
      )}

      {noBuilder && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          The builder-runner sidecar is not reachable, so nothing here can be started.
          Bring the stack up with the <code>imaging</code> profile and set
          <code> FLEET_BUILDER_RUNNER_URL</code>.
        </Alert>
      )}

      {problems.length > 0 && !noBuilder && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.5 }}>
            Not ready to provision yet
          </Typography>
          <ul style={{ margin: 0, paddingLeft: "1.2em" }}>
            {problems.map((p) => <li key={p}><Typography variant="body2">{p}</Typography></li>)}
          </ul>
        </Alert>
      )}

      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Server configuration</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Pick the network the machines are on and the image to write.
        </Typography>

        <Grid container spacing={2}>
          <Grid item xs={12}>
            <TextField
              select fullWidth size="small" label="Provisioning network"
              value={ifaces.some((i) => i.name === cfg.INTERFACE) ? cfg.INTERFACE : ""}
              onChange={(e) => selectInterface(e.target.value)}
              disabled={!canProvision}
              helperText={
                ifaces.length === 0
                  ? "No interfaces detected — the sidecar reads them from the host network namespace."
                  : "DHCP and TFTP are confined to this interface alone."
              }
            >
              {ifaces.map((i) => (
                <MenuItem key={i.name} value={i.name}>
                  {ifaceLabel(i)}
                </MenuItem>
              ))}
            </TextField>
            {selected?.default && (
              <Alert severity="warning" sx={{ mt: 1 }}>
                This is the host's main LAN — it carries the default route. A standalone
                DHCP server here will compete with the network's existing one. Use a
                dedicated NIC, or switch to proxy mode under advanced settings.
              </Alert>
            )}
          </Grid>

          <Grid item xs={12} sm={6}>
            <TextField
              select fullWidth size="small" label="Image to deploy"
              value={images.includes(cfg.IMAGE_FILE) ? cfg.IMAGE_FILE : ""}
              onChange={(e) => set("IMAGE_FILE", e.target.value)}
              disabled={!canProvision}
              helperText={images.length === 0
                ? "No images built yet — build one first."
                : cfg.IMAGE_FILE
                  ? "Anything without its own assignment gets this."
                  : "No default: every machine must be assigned an image individually."}
            >
              {/* Blank is a real choice, not an empty state. With no default,
                  a machine that PXE-boots without an assignment is held and
                  told so, and its disk is not touched — which is what you want
                  on a segment carrying machines you have not decided about. */}
              <MenuItem value="">
                <em>None — hold every machine until it is assigned</em>
              </MenuItem>
              {images.map((n) => <MenuItem key={n} value={n}>{n}</MenuItem>)}
            </TextField>
          </Grid>

          <Grid item xs={12} sm={6}>
            <TextField
              select fullWidth size="small" label="After imaging"
              value={cfg.ACTION || "reboot"}
              onChange={(e) => set("ACTION", e.target.value)}
              disabled={!canProvision}
            >
              <MenuItem value="reboot">reboot</MenuItem>
              <MenuItem value="poweroff">poweroff</MenuItem>
              <MenuItem value="shell">shell</MenuItem>
            </TextField>
          </Grid>
        </Grid>

        {selected && (
          <Paper variant="outlined" sx={{ mt: 2, p: 1.5, bgcolor: "action.hover" }}>
            <Typography variant="caption" sx={{ fontWeight: 700, display: "block", mb: 0.5 }}>
              Starting this server will:
            </Typography>
            {!selected.ip && cfg.SERVER_IP && (
              <Typography variant="caption" display="block">
                • give <code>{selected.name}</code> the address{" "}
                <code>{cfg.SERVER_IP}/{cfg.SERVER_PREFIXLEN || 24}</code> — the NIC has
                none, and this is applied at runtime only (a reboot reverts it; starting
                again re-applies it, so the host's permanent network config is untouched)
              </Typography>
            )}
            <Typography variant="caption" display="block">
              • serve DHCP and TFTP on <code>{selected.name}</code> only, as{" "}
              <code>{cfg.SERVER_IP || "(unset)"}</code>
            </Typography>
            {cfg.MODE !== "proxy" && cfg.DHCP_RANGE_START && (
              <Typography variant="caption" display="block">
                • lease <code>{cfg.DHCP_RANGE_START} – {cfg.DHCP_RANGE_END}</code> to
                machines that PXE-boot
              </Typography>
            )}
            {cfg.MODE === "proxy" && (
              <Typography variant="caption" display="block">
                • answer only PXE requests on <code>{cfg.PROXY_SUBNET}</code>, leaving IP
                leases to the network's existing DHCP server
              </Typography>
            )}
            <Typography variant="caption" display="block">
              • write <code>{cfg.IMAGE_FILE || "nothing — no default image is set"}</code> to each
              machine, then {cfg.ACTION || "reboot"}
            </Typography>
          </Paper>
        )}

        <Button size="small" sx={{ mt: 2 }} onClick={() => setAdvanced((a) => !a)}>
          {advanced ? "Hide" : "Show"} advanced network settings
        </Button>

        {advanced && (
          <Grid container spacing={2} sx={{ mt: 0 }}>
            <Grid item xs={12} sm={6}>
              <TextField
                select fullWidth size="small" label="DHCP mode" value={cfg.MODE || "dhcp"}
                onChange={(e) => set("MODE", e.target.value)} disabled={!canProvision}
                helperText={
                  cfg.MODE === "proxy"
                    ? "Answers only PXE questions; the existing DHCP server keeps handing out IPs."
                    : "This server owns the provisioning network and hands out its own leases."
                }
              >
                <MenuItem value="dhcp">standalone</MenuItem>
                <MenuItem value="proxy">proxy (existing DHCP server)</MenuItem>
              </TextField>
            </Grid>
            {[
              ["SERVER_IP", "Server IP"],
              ["SERVER_PREFIXLEN", "Prefix length"],
              ["DHCP_RANGE_START", "DHCP range start"],
              ["DHCP_RANGE_END", "DHCP range end"],
              ["DHCP_NETMASK", "Netmask"],
              ["PROXY_SUBNET", "Proxy subnet"],
              ["LEASE_TIME", "Lease time"],
              ["DHCP_ROUTER", "Router (optional)"],
              ["DHCP_DNS", "DNS (optional)"],
              ["UPDATE_IP", "Also publish bundles on"],
              ["UPDATE_PORT", "Bundle port"],
              ["WEBUI_ADDR", "Web UI address"],
            ].map(([k, label]) => (
              <Grid item xs={12} sm={6} key={k}>
                <TextField
                  fullWidth size="small" label={label} value={cfg[k] ?? ""}
                  onChange={(e) => set(k, e.target.value)} disabled={!canProvision}
                />
              </Grid>
            ))}
            <Grid item xs={12}>
              <TextField
                fullWidth size="small" label="Control URL (where the fleet reaches this server)"
                value={cfg.CONTROL_URL ?? ""} onChange={(e) => set("CONTROL_URL", e.target.value)}
                disabled={!canProvision}
                placeholder="https://blackfriars.example.com"
                helperText={
                  "Written onto each machine while imaging and re-advertised on every check-in. " +
                  "Every other address here is on the provisioning segment — a network the machine " +
                  "is on for twenty minutes and never again. Leave it empty and machines fall back " +
                  "to the address they were imaged from, which they stop being able to reach the " +
                  "moment they are unracked."
                }
              />
            </Grid>
          </Grid>
        )}

        <Stack direction="row" spacing={1} sx={{ mt: 2 }} alignItems="center">
          <Button
            variant="contained" disabled={!canProvision || save.isPending || !dirty}
            onClick={() => save.mutate()}
          >
            Save configuration
          </Button>
          {dirty && <Typography variant="caption" color="text.secondary">Unsaved changes</Typography>}
        </Stack>
      </Paper>

      <Divider sx={{ my: 2 }} />

      {/* Above the assignment table on purpose: the usual order of work is
          "boot the machine, see it appear, give it an image", and the thing you
          do first should be the thing you read first. */}
      <DiscoveredMachines
        canProvision={canProvision}
        assignedMacs={new Set(rowsShown.map((a) => (a.mac || "").toLowerCase()))}
        onAssign={(mac) => {
          const current = rowsShown;
          // Reuse an empty row if the reader already added one, rather than
          // leaving a blank line above the machine they just clicked.
          const blank = current.findIndex((a) => !a.mac);
          const next = blank >= 0
            ? current.map((a, i) => (i === blank ? { ...a, mac } : a))
            : [...current, { mac, image: "", hostname: "", name: "" }];
          setRows(next);
          setMsg(`Added ${mac}. Choose an image for it below, then Save.`);
        }}
      />

      <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="subtitle2">Per-machine images</Typography>
          <Typography variant="body2" color="text.secondary">
            A MAC listed here gets its own image instead of the default above.
            {cfg.IMAGE_FILE
              ? <> Anything not listed gets <code>{cfg.IMAGE_FILE}</code>.</>
              : <> With no default set, anything not listed is <strong>held</strong>: it
                  reports its MAC, its disk is untouched, and it picks up an image
                  within {cfg.RETRY_SECONDS || "30"}s of one being assigned — no second
                  power cycle.</>}
          </Typography>
        </Box>
        <Button
          size="small" startIcon={<AddIcon />} disabled={!canProvision}
          onClick={() => setRows([...(rowsShown), { mac: "", image: "", hostname: "", name: "" }])}
        >
          Add machine
        </Button>
        <Button
          size="small" variant="contained" sx={{ ml: 1 }}
          disabled={!canProvision || rows === null || saveRows.isPending}
          onClick={() => rows && saveRows.mutate(rows)}
        >
          Save
        </Button>
      </Stack>

      <Paper variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>MAC address</TableCell>
              <TableCell>Image</TableCell>
              <TableCell>Hostname</TableCell>
              <TableCell>Label</TableCell>
              <TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {rowsShown.map((a, i) => (
              <TableRow key={i}>
                <TableCell>
                  <TextField
                    size="small" variant="standard" placeholder="00:11:22:33:44:55"
                    value={a.mac ?? ""} disabled={!canProvision}
                    onChange={(e) => setRows(rowsShown.map((r, j) => j === i ? { ...r, mac: e.target.value } : r))}
                    inputProps={{ style: { fontFamily: "monospace" } }}
                  />
                </TableCell>
                <TableCell>
                  <TextField
                    select size="small" variant="standard" sx={{ minWidth: 160 }}
                    value={images.includes(String(a.image)) ? a.image : ""}
                    disabled={!canProvision}
                    onChange={(e) => setRows(rowsShown.map((r, j) => j === i ? { ...r, image: e.target.value } : r))}
                  >
                    {images.map((n) => <MenuItem key={n} value={n}>{n}</MenuItem>)}
                  </TextField>
                </TableCell>
                <TableCell>
                  <TextField
                    size="small" variant="standard" placeholder="web01"
                    value={a.hostname ?? ""} disabled={!canProvision}
                    onChange={(e) => setRows(rowsShown.map((r, j) => j === i ? { ...r, hostname: e.target.value } : r))}
                  />
                </TableCell>
                <TableCell>
                  <TextField
                    size="small" variant="standard" placeholder="optional"
                    value={a.name ?? ""} disabled={!canProvision}
                    onChange={(e) => setRows(rowsShown.map((r, j) => j === i ? { ...r, name: e.target.value } : r))}
                  />
                </TableCell>
                <TableCell align="right">
                  <IconButton
                    size="small" disabled={!canProvision}
                    onClick={() => setRows(rowsShown.filter((_, j) => j !== i))}
                  >
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
            {rowsShown.length === 0 && (
              <TableRow>
                <TableCell colSpan={5}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                    {isLoading ? "Loading…" : "No per-machine images — every machine gets the default."}
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

// A NIC's description carries the two facts that decide whether it is the right
// one: whether it already has an address, and whether it is the main LAN.
function ifaceLabel(i: NetInterface): string {
  const addr = i.ip ? `${i.ip}/${i.prefixlen}` : "no IP address";
  const marks = [
    i.default ? "main LAN — carries the default route" : "",
    !i.up ? "link down" : "",
    i.up && !i.carrier ? "no carrier" : "",
  ].filter(Boolean);
  return `${i.name} · ${addr}${marks.length ? ` (${marks.join("; ")})` : ""}`;
}

function errText(e: unknown, fallback: string): string {
  const d = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
  return d ? `${fallback} ${d}` : fallback;
}
