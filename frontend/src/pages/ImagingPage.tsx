import { useMemo, useState } from "react";
import {
  Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent,
  DialogTitle, Divider, LinearProgress, MenuItem, Paper, Stack, Tab, Table, TableBody,
  TableCell, TableHead, TableRow, Tabs, TextField, Tooltip, Typography,
} from "@mui/material";
import BoltIcon from "@mui/icons-material/Bolt";
import DownloadingIcon from "@mui/icons-material/Downloading";
import LinkIcon from "@mui/icons-material/Link";
import PauseIcon from "@mui/icons-material/Pause";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import StopIcon from "@mui/icons-material/Stop";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { formatDateTime } from "../lib/datetime";
import { useAuthStore } from "../store/auth";
import {
  createRollout, imagingFleet, imagingStatus, installOnHost, linkHost, listBundles,
  listFleetGroups, listImages, listRollouts, nudgeHost, steerRollout,
  type FleetRow, type Rollout,
} from "../api/imaging";

const PRESENCE: Record<string, { label: string; color: "success" | "warning" | "error" | "default" }> = {
  online: { label: "Online", color: "success" },
  stale: { label: "Stale", color: "warning" },
  offline: { label: "Offline", color: "error" },
  unknown: { label: "No agent", color: "default" },
};

const ROLLOUT_COLOR: Record<string, "success" | "warning" | "error" | "info" | "default"> = {
  running: "success", paused: "warning", halted: "error",
  completed: "info", cancelled: "default",
};

function bytes(n?: number) {
  if (!n) return "—";
  if (n >= 1e9) return (n / 1e9).toFixed(2) + " GB";
  if (n >= 1e6) return (n / 1e6).toFixed(1) + " MB";
  return (n / 1e3).toFixed(0) + " KB";
}

/**
 * ImagingPage: the OS half of a machine's life — what image it was built from,
 * what version it runs now, and rolling a new one out.
 *
 * Flipside decides what a rollout does; this page shows it and, for hosts
 * Moorgate can reach, removes the waiting. See docs/imaging.md.
 */
export function ImagingPage() {
  const qc = useQueryClient();
  const canManage = useAuthStore((s) => s.has("Imaging.Manage"));
  const [tab, setTab] = useState(0);
  const [msg, setMsg] = useState<{ kind: "success" | "error" | "info"; text: string } | null>(null);

  const { data: status, isLoading: statusLoading } = useQuery({
    queryKey: ["imaging-status"], queryFn: imagingStatus, refetchInterval: 60_000,
  });
  const on = !!status?.configured && !!status?.reachable;

  const { data: fleet } = useQuery({
    queryKey: ["imaging-fleet"], queryFn: imagingFleet, enabled: on, refetchInterval: 15_000,
  });
  const { data: rollouts = [] } = useQuery({
    queryKey: ["imaging-rollouts"], queryFn: listRollouts, enabled: on, refetchInterval: 10_000,
  });
  const { data: images = [] } = useQuery({
    queryKey: ["imaging-images"], queryFn: listImages, enabled: on,
  });
  const { data: bundleData } = useQuery({
    queryKey: ["imaging-bundles"], queryFn: listBundles, enabled: on,
  });

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["imaging-fleet"] });
    qc.invalidateQueries({ queryKey: ["imaging-rollouts"] });
  };

  const nudge = useMutation({
    mutationFn: (hostId: string) => nudgeHost(hostId),
    onSuccess: (r) => {
      // A failed nudge is not a failed update — the agent still polls — so it
      // is reported as information rather than as an error someone must act on.
      setMsg(r.ok
        ? { kind: "success", text: "Checked in. Flipside decides from here." }
        : { kind: "info", text: `${r.error ?? "The nudge did not land"}. ${r.note ?? ""}` });
      refresh();
    },
    onError: (e: any) => setMsg({ kind: "error", text: e?.response?.data?.error ?? String(e) }),
  });

  const steer = useMutation({
    mutationFn: ({ id, verb }: { id: string; verb: "pause" | "resume" | "cancel" }) =>
      steerRollout(id, verb),
    onSuccess: refresh,
    onError: (e: any) => setMsg({ kind: "error", text: e?.response?.data?.error ?? String(e) }),
  });

  if (statusLoading) return <CircularProgress />;

  if (!status?.configured) {
    return (
      <Box>
        <Typography variant="h5" gutterBottom>Imaging</Typography>
        <Alert severity="info">
          <Typography variant="subtitle2">No Flipside server is configured.</Typography>
          Flipside builds the operating system images this fleet runs and rolls updates
          out to them. Set <code>FLEET_FLIPSIDE_URL</code> and <code>FLEET_FLIPSIDE_TOKEN</code>
          {" "}to manage it from here. See <code>docs/imaging.md</code>.
        </Alert>
      </Box>
    );
  }

  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }}>
        <Typography variant="h5">Imaging</Typography>
        {status.reachable
          ? <Chip size="small" color="success" label={`Flipside ${status.version ?? ""}`} />
          : <Chip size="small" color="error" label="Flipside unreachable" />}
        {status.configured && status.nudge === false && (
          <Tooltip title="Rollouts still work; machines pick them up on their own timer instead of being asked to check in.">
            <Chip size="small" variant="outlined" label="push disabled" />
          </Tooltip>
        )}
      </Stack>

      {!status.reachable && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {/* The reason, not a red dot: a rejected token and a dead server need
              different people to do different things. */}
          {status.error ?? `Cannot reach Flipside at ${status.url}.`}
        </Alert>
      )}
      {msg && <Alert severity={msg.kind} sx={{ mb: 2 }} onClose={() => setMsg(null)}>{msg.text}</Alert>}

      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        <Tab label={`Fleet${fleet ? ` (${fleet.rows.length})` : ""}`} />
        <Tab label={`Rollouts${rollouts.length ? ` (${rollouts.length})` : ""}`} />
        <Tab label={`Images${images.length ? ` (${images.length})` : ""}`} />
        <Tab label={`Bundles${bundleData ? ` (${bundleData.bundles.length})` : ""}`} />
      </Tabs>

      {tab === 0 && <FleetTab fleet={fleet} canManage={canManage} onNudge={(id) => nudge.mutate(id)}
                              busy={nudge.isPending} onDone={refresh} setMsg={setMsg} />}
      {tab === 1 && <RolloutsTab rollouts={rollouts} canManage={canManage}
                                 onSteer={(id, verb) => steer.mutate({ id, verb })}
                                 onCreated={refresh} setMsg={setMsg} />}
      {tab === 2 && <ImagesTab images={images} />}
      {tab === 3 && <BundlesTab data={bundleData} />}
    </Box>
  );
}

// --- fleet -------------------------------------------------------------------

function FleetTab({ fleet, canManage, onNudge, busy, onDone, setMsg }: {
  fleet?: { rows: FleetRow[]; counts: Record<string, number>; versions: Record<string, number>;
            controlUrl: string };
  canManage: boolean;
  onNudge: (hostId: string) => void;
  busy: boolean;
  onDone: () => void;
  setMsg: (m: { kind: "success" | "error" | "info"; text: string } | null) => void;
}) {
  const [linking, setLinking] = useState<FleetRow | null>(null);
  const [installing, setInstalling] = useState<FleetRow | null>(null);
  if (!fleet) return <CircularProgress />;

  const versions = Object.entries(fleet.versions).sort((a, b) => b[1] - a[1]);

  return (
    <>
      <Stack direction="row" spacing={1} sx={{ mb: 2 }} flexWrap="wrap" useFlexGap>
        {(["online", "stale", "offline", "unknown"] as const).map((k) => (
          <Chip key={k} size="small" color={PRESENCE[k].color}
                variant={fleet.counts[k] ? "filled" : "outlined"}
                label={`${PRESENCE[k].label}: ${fleet.counts[k] ?? 0}`} />
        ))}
        <Divider orientation="vertical" flexItem />
        {versions.map(([v, n]) => <Chip key={v} size="small" variant="outlined" label={`${v} · ${n}`} />)}
      </Stack>

      <Paper variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Host</TableCell>
              <TableCell>OS version</TableCell>
              <TableCell>Presence</TableCell>
              <TableCell>Groups</TableCell>
              <TableCell>Paired</TableCell>
              <TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {fleet.rows.map((row) => {
              const m = row.machine;
              const p = PRESENCE[m?.presence ?? "unknown"];
              return (
                <TableRow key={row.hostId ?? row.machineId} hover>
                  <TableCell>
                    <Typography variant="body2">{row.hostname}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {row.hostId ? row.environment : "not enrolled in Moorgate"}
                      {row.machineId ? ` · ${row.machineId}` : ""}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {m?.version ?? "—"}
                    {m?.update_state && m.update_state !== "idle" && (
                      <Chip size="small" sx={{ ml: 1 }} label={m.update_state} />
                    )}
                    {m?.update_error && (
                      <Typography variant="caption" color="error" display="block">
                        {m.update_error}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Chip size="small" color={p.color} label={p.label} />
                    {m?.health === "degraded" && <Chip size="small" color="error" sx={{ ml: 0.5 }} label="degraded" />}
                  </TableCell>
                  <TableCell>
                    {(m?.groups ?? []).map((g) => <Chip key={g} size="small" label={g} sx={{ mr: 0.5 }} />)}
                  </TableCell>
                  <TableCell>
                    {/* A hostname match is a guess that stops being true the
                        moment a machine is renamed. Shown as one, with the
                        offer to make it permanent. */}
                    {row.linkedBy === "linked" && <Chip size="small" color="success" label="linked" />}
                    {row.linkedBy === "hostname" && (
                      <Tooltip title="Matched by hostname. Pin it so a rename cannot re-point it.">
                        <Chip size="small" variant="outlined" label="by name" />
                      </Tooltip>
                    )}
                    {row.linkedBy === "none" && <Typography variant="caption" color="text.secondary">—</Typography>}
                  </TableCell>
                  <TableCell align="right">
                    <Stack direction="row" spacing={1} justifyContent="flex-end">
                      {canManage && row.hostId && (
                        <Tooltip title="Pin this host to a Flipside machine">
                          <span><Button size="small" startIcon={<LinkIcon />}
                                        onClick={() => setLinking(row)}>Pair</Button></span>
                        </Tooltip>
                      )}
                      {canManage && row.hostId && row.reachable && (
                        <Tooltip title="Make this machine check in with Flipside now instead of waiting for its timer">
                          <span><Button size="small" startIcon={<BoltIcon />} disabled={busy}
                                        onClick={() => onNudge(row.hostId!)}>Check in now</Button></span>
                        </Tooltip>
                      )}
                      {/* The escape hatch for a machine Moorgate can reach and
                          Flipside cannot: it will never be nudged into checking
                          in, because it has nowhere to check in to. Offered only
                          for those, so it does not become the habitual button --
                          a rollout applies canary, soak and failure budget, and
                          this bypasses all three. */}
                      {canManage && row.hostId && row.reachable &&
                        (m?.presence === "unknown" || m?.presence === "offline" || !m) && (
                        <Tooltip title="Install a bundle over SSH. For machines that cannot reach Flipside at all — this bypasses the rollout's canary, soak and failure budget.">
                          <span><Button size="small" color="warning" startIcon={<DownloadingIcon />}
                                        onClick={() => setInstalling(row)}>Install directly</Button></span>
                        </Tooltip>
                      )}
                    </Stack>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </Paper>

      <LinkDialog row={linking} onClose={() => setLinking(null)}
                  onDone={(text) => { setMsg({ kind: "success", text }); onDone(); }} />
      <InstallDialog row={installing} controlUrl={fleet.controlUrl}
                     onClose={() => setInstalling(null)} setMsg={setMsg} onDone={onDone} />
    </>
  );
}

function LinkDialog({ row, onClose, onDone }: {
  row: FleetRow | null; onClose: () => void; onDone: (text: string) => void;
}) {
  const [id, setId] = useState("");
  const save = useMutation({
    mutationFn: () => linkHost(row!.hostId!, id.trim()),
    onSuccess: () => { onDone(id.trim() ? "Paired." : "Pairing cleared."); onClose(); },
  });
  return (
    <Dialog open={!!row} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Pair {row?.hostname} with a Flipside machine</DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          A pairing recorded here is the only one that survives a rename or a re-image.
          Matching on hostname works until somebody changes one.
        </Typography>
        <TextField autoFocus fullWidth label="Flipside machine id"
                   placeholder={row?.machineId || "aa:bb:cc:dd:ee:ff"}
                   value={id} onChange={(e) => setId(e.target.value)}
                   helperText="Leave empty to clear the pairing and fall back to matching by name." />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={() => save.mutate()} disabled={save.isPending}>Save</Button>
      </DialogActions>
    </Dialog>
  );
}

/**
 * InstallDialog: write a bundle to one host over SSH.
 *
 * This is the path for a machine Moorgate reaches and Flipside does not — a
 * site with no route back, or a host imaged before the agent existed. It is
 * deliberately not the ordinary way to update a machine: a rollout decides who
 * goes first, waits to see whether it worked, and stops if enough of them fail,
 * and none of that applies here.
 */
function InstallDialog({ row, controlUrl, onClose, onDone, setMsg }: {
  row: FleetRow | null; controlUrl: string; onClose: () => void; onDone: () => void;
  setMsg: (m: { kind: "success" | "error" | "info"; text: string } | null) => void;
}) {
  const { data: bundleData } = useQuery({
    queryKey: ["imaging-bundles"], queryFn: listBundles, enabled: !!row,
  });
  const [bundle, setBundle] = useState("");
  const [override, setOverride] = useState("");

  // The URL the *host* will fetch from, which is built from Flipside's
  // CONTROL_URL -- the address that works from where the fleet lives. That is
  // routinely not the address this browser or the Moorgate backend uses to
  // reach Flipside's API, which is exactly the mistake that makes a bundle
  // download fail with "server not responding" on the machine and nowhere else.
  const url = override.trim() || (bundle && controlUrl ? `${controlUrl.replace(/\/$/, "")}/bundles/${bundle}` : "");

  const install = useMutation({
    mutationFn: () => installOnHost(row!.hostId!, url),
    onSuccess: (r) => {
      setMsg(r.ok
        ? { kind: "success", text: r.note ?? "Installed to the inactive slot." }
        : { kind: "error", text: r.error ?? "The install failed." });
      onDone();
      onClose();
    },
    onError: (e: any) => setMsg({ kind: "error", text: e?.response?.data?.error ?? String(e) }),
  });

  return (
    <Dialog open={!!row} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Install a bundle on {row?.hostname}</DialogTitle>
      <DialogContent>
        <Alert severity="warning" sx={{ mb: 2 }}>
          This writes the inactive slot directly and bypasses the rollout machinery —
          no canary, no soak, no failure budget. Use it for machines that cannot reach
          Flipside at all; everything else should go through a rollout.
        </Alert>
        <TextField select fullWidth label="Bundle" value={bundle}
                   onChange={(e) => setBundle(e.target.value)}
                   helperText="The host fetches this itself, over the overlay it already trusts.">
          {(bundleData?.bundles ?? []).map((b) => (
            <MenuItem key={b.name} value={b.name}>{b.name}{b.version ? ` — ${b.version}` : ""}</MenuItem>
          ))}
        </TextField>
        {!controlUrl && (
          <Alert severity="warning" sx={{ mt: 2 }}>
            Flipside has no control URL set, so there is no address to tell the machine to
            fetch from. Set <code>CONTROL_URL</code> in Flipside, or give a full URL below.
          </Alert>
        )}
        <TextField fullWidth sx={{ mt: 2 }} label="Or a full bundle URL" value={override}
                   onChange={(e) => setOverride(e.target.value)}
                   placeholder={url || "http://flipside.example.com/bundles/name.raucb"}
                   helperText={url ? `The host will fetch: ${url}` : undefined} />
        <Typography variant="caption" color="text.secondary">
          The machine boots what is installed on its next reboot; until then it is still
          running the old version, and RAUC verifies the signature against the certificate
          inside its own image exactly as on any other path.
        </Typography>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" color="warning" disabled={!url || install.isPending}
                onClick={() => install.mutate()}>Install</Button>
      </DialogActions>
    </Dialog>
  );
}

// --- rollouts ----------------------------------------------------------------

function RolloutsTab({ rollouts, canManage, onSteer, onCreated, setMsg }: {
  rollouts: Rollout[];
  canManage: boolean;
  onSteer: (id: string, verb: "pause" | "resume" | "cancel") => void;
  onCreated: () => void;
  setMsg: (m: { kind: "success" | "error" | "info"; text: string } | null) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      {canManage && (
        <Button variant="contained" startIcon={<RocketLaunchIcon />} sx={{ mb: 2 }}
                onClick={() => setOpen(true)}>New rollout</Button>
      )}
      {rollouts.length === 0 && (
        <Alert severity="info">
          No rollouts. A rollout puts a bundle on a group of machines a few at a time —
          one first, then the rest once it has proven itself — and stops on its own if
          too many fail.
        </Alert>
      )}
      <Stack spacing={2}>
        {rollouts.map((r) => {
          const pct = r.total ? Math.round((r.done / r.total) * 100) : 0;
          return (
            <Paper key={r.id} variant="outlined" sx={{ p: 2 }}>
              <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }} flexWrap="wrap" useFlexGap>
                <Typography variant="subtitle1">{r.version}</Typography>
                <Chip size="small" color={ROLLOUT_COLOR[r.state]} label={r.state} />
                <Typography variant="caption" color="text.secondary">
                  {r.bundle} → {r.target.all ? "the whole fleet" : [...r.target.groups, ...r.target.hosts].join(", ")}
                  {" · "}{r.done} of {r.total}
                </Typography>
                <Box flexGrow={1} />
                {canManage && r.state === "running" && (
                  <Button size="small" startIcon={<PauseIcon />} onClick={() => onSteer(r.id, "pause")}>Pause</Button>
                )}
                {canManage && (r.state === "paused" || r.state === "halted") && (
                  <Button size="small" startIcon={<PlayArrowIcon />} onClick={() => onSteer(r.id, "resume")}>Resume</Button>
                )}
                {canManage && ["running", "paused", "halted"].includes(r.state) && (
                  <Button size="small" color="error" startIcon={<StopIcon />}
                          onClick={() => onSteer(r.id, "cancel")}>Cancel</Button>
                )}
              </Stack>
              {r.state === "halted" && (
                <Alert severity="error" sx={{ mb: 1 }}>
                  {r.halt_reason} Resuming continues with the machines that have not been
                  tried; the ones that failed stay failed.
                </Alert>
              )}
              <LinearProgress variant="determinate" value={pct}
                              color={r.state === "halted" ? "error" : "primary"} />
              <Stack direction="row" spacing={1} sx={{ mt: 1 }} flexWrap="wrap" useFlexGap>
                {Object.entries(r.counts).map(([k, n]) => (
                  <Chip key={k} size="small" variant="outlined" label={`${k}: ${n}`} />
                ))}
                <Box flexGrow={1} />
                <Typography variant="caption" color="text.secondary">
                  canary {r.strategy.canary} · batches of {r.strategy.batch_size} ·
                  soak {Math.round(r.strategy.soak_seconds / 60)}m ·
                  stop after {r.strategy.max_failures}
                </Typography>
              </Stack>
            </Paper>
          );
        })}
      </Stack>
      <NewRolloutDialog open={open} onClose={() => setOpen(false)}
                        onCreated={() => { setOpen(false); onCreated(); }} setMsg={setMsg} />
    </>
  );
}

function NewRolloutDialog({ open, onClose, onCreated, setMsg }: {
  open: boolean; onClose: () => void; onCreated: () => void;
  setMsg: (m: { kind: "success" | "error" | "info"; text: string } | null) => void;
}) {
  const { data: bundleData } = useQuery({ queryKey: ["imaging-bundles"], queryFn: listBundles, enabled: open });
  const { data: groups = [] } = useQuery({ queryKey: ["imaging-groups"], queryFn: listFleetGroups, enabled: open });
  const [bundle, setBundle] = useState("");
  const [group, setGroup] = useState("");
  const [canary, setCanary] = useState(1);
  const [batch, setBatch] = useState(10);
  const [soak, setSoak] = useState(15);
  const [maxFail, setMaxFail] = useState(2);

  const create = useMutation({
    mutationFn: () => createRollout({
      bundle, groups: group ? [group] : [], all: !group,
      strategy: { canary, batch_size: batch, soak_seconds: soak * 60, max_failures: maxFail },
    }),
    onSuccess: () => { setMsg({ kind: "success", text: "Rollout started." }); onCreated(); },
    // Flipside validates a rollout and says exactly what is wrong with one.
    // Its wording is passed through rather than replaced.
    onError: (e: any) => setMsg({ kind: "error", text: e?.response?.data?.error ?? String(e) }),
  });

  const bundles = bundleData?.bundles ?? [];
  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>New rollout</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <TextField select fullWidth label="Bundle" value={bundle} onChange={(e) => setBundle(e.target.value)}>
            {bundles.map((b) => (
              <MenuItem key={b.name} value={b.name}>
                {b.name}{b.version ? ` — ${b.version}` : " — no version recorded"}
              </MenuItem>
            ))}
          </TextField>
          <TextField select fullWidth label="Target" value={group} onChange={(e) => setGroup(e.target.value)}>
            <MenuItem value="">The whole fleet</MenuItem>
            {groups.map((g) => (
              <MenuItem key={g.name} value={g.name}>{g.name} ({g.hosts} machines)</MenuItem>
            ))}
          </TextField>
          <Stack direction="row" spacing={2}>
            <TextField type="number" label="Canary" value={canary}
                       onChange={(e) => setCanary(+e.target.value)} />
            <TextField type="number" label="Batches of" value={batch}
                       onChange={(e) => setBatch(+e.target.value)} />
            <TextField type="number" label="Soak (min)" value={soak}
                       onChange={(e) => setSoak(+e.target.value)} />
            <TextField type="number" label="Stop after" value={maxFail}
                       onChange={(e) => setMaxFail(+e.target.value)} />
          </Stack>
          <Typography variant="caption" color="text.secondary">
            A machine counts as done only when it comes back on the new version and passes
            its health check — not when the install returns. An update that installs cleanly
            and then fails to boot is what the canary and the soak are there to catch, before
            the rest of the fleet gets it.
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={!bundle || create.isPending}
                onClick={() => create.mutate()}>Create</Button>
      </DialogActions>
    </Dialog>
  );
}

// --- artefacts ---------------------------------------------------------------

function ImagesTab({ images }: { images: Awaited<ReturnType<typeof listImages>> }) {
  return (
    <Paper variant="outlined">
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Image</TableCell><TableCell>System</TableCell>
            <TableCell>Version</TableCell><TableCell>Contents</TableCell>
            <TableCell>Size</TableCell><TableCell>Built</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {images.map((i) => (
            <TableRow key={i.name} hover>
              <TableCell>
                {i.name}
                <Stack direction="row" spacing={0.5} sx={{ mt: 0.5 }}>
                  {i.meta?.encrypted && <Chip size="small" label="LUKS" />}
                  {i.meta?.secure_boot && <Chip size="small" color="success" label="Secure Boot" />}
                  {i.meta?.profile && i.meta.profile !== "minimal" && <Chip size="small" label={i.meta.profile} />}
                </Stack>
              </TableCell>
              <TableCell>{[i.meta?.distro, i.meta?.suite, i.meta?.arch].filter(Boolean).join(" ")}</TableCell>
              <TableCell>{i.meta?.version ?? "—"}</TableCell>
              <TableCell>{i.meta?.packages ? `${i.meta.packages} packages` : "no SBOM"}</TableCell>
              <TableCell>{bytes(i.size)}</TableCell>
              <TableCell>{formatDateTime(i.meta?.created ?? i.created)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Paper>
  );
}

function BundlesTab({ data }: { data?: Awaited<ReturnType<typeof listBundles>> }) {
  const running = data?.running_versions ?? {};
  const rows = useMemo(() => data?.bundles ?? [], [data]);
  return (
    <Paper variant="outlined">
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Bundle</TableCell><TableCell>Version</TableCell>
            <TableCell>Built from</TableCell><TableCell>In the field</TableCell>
            <TableCell>Size</TableCell><TableCell>Built</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.map((b) => (
            <TableRow key={b.name} hover>
              <TableCell>
                {b.name}{b.is_latest && <Chip size="small" color="primary" sx={{ ml: 1 }} label="latest" />}
              </TableCell>
              <TableCell>{b.version ?? "—"}</TableCell>
              <TableCell>{b.source ?? "—"}</TableCell>
              <TableCell>
                {/* What is actually deployed, not what has been built. The two
                    differ, and only one of them is the fleet's real state. */}
                {b.version && running[b.version] ? `${running[b.version]} machines` : "—"}
              </TableCell>
              <TableCell>{bytes(b.size)}</TableCell>
              <TableCell>{formatDateTime(b.created)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Paper>
  );
}

export default ImagingPage;
