import { useMemo, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, Divider, FormControlLabel, LinearProgress, MenuItem,
  Paper, Stack, Switch, Tab, Table, TableBody, TableCell, TableHead, TableRow, Tabs,
  TextField, Tooltip, Typography,
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
import { listGroups } from "../api/admin";
import { listHosts } from "../api/hosts";
import {
  createRollout, installOnMachine, listBundles, listImages, listMachines, listRollouts,
  nudgeMachine, steerRollout, updateMachine,
  type Machine, type Rollout,
} from "../api/imaging";

type Note = { kind: "success" | "error" | "info"; text: string } | null;

const PRESENCE: Record<string, { label: string; color: "success" | "warning" | "error" | "default" }> = {
  online: { label: "Online", color: "success" },
  stale: { label: "Stale", color: "warning" },
  offline: { label: "Offline", color: "error" },
  unknown: { label: "Never seen", color: "default" },
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

// The backend says exactly what is wrong with a rollout — an unversioned bundle,
// a target matching nothing, a missing control URL. Its wording is surfaced
// rather than replaced with something vaguer.
function apiError(e: unknown): string {
  const detail = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
  return detail ?? String(e);
}

/**
 * ImagingPage: the OS half of a machine's life — what image it was built from,
 * what version it runs now, and rolling a new one out.
 *
 * A machine here is not a host. It is imaged on the provisioning switch and
 * exists from that moment; it becomes a host later, when it is enrolled. Keeping
 * the two separate is what makes "imaged perfectly and never came back" a thing
 * this page can show, rather than a gap between two systems. Pairing a machine
 * with its host is what unlocks reaching it — see docs/imaging.md.
 */
export function ImagingPage() {
  const qc = useQueryClient();
  const canManage = useAuthStore((s) => s.has("Imaging.Manage"));
  const [tab, setTab] = useState(0);
  const [msg, setMsg] = useState<Note>(null);

  const { data: fleet, isLoading } = useQuery({
    queryKey: ["imaging-machines"], queryFn: listMachines, refetchInterval: 15_000,
  });
  const { data: rollouts = [] } = useQuery({
    queryKey: ["imaging-rollouts"], queryFn: listRollouts, refetchInterval: 10_000,
  });
  const { data: imageData } = useQuery({ queryKey: ["imaging-images"], queryFn: listImages });
  const { data: bundleData } = useQuery({ queryKey: ["imaging-bundles"], queryFn: listBundles });

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["imaging-machines"] });
    qc.invalidateQueries({ queryKey: ["imaging-rollouts"] });
  };

  const nudge = useMutation({
    mutationFn: (id: string) => nudgeMachine(id),
    onSuccess: (r) => {
      // A failed nudge is not a failed update — the agent still polls — so it is
      // reported as information rather than as an error someone must act on.
      setMsg(r.ok
        ? { kind: "success", text: "Checked in. The rollout decides from here." }
        : { kind: "info", text: `${r.error ?? "The check-in did not land"}. ${r.note ?? ""}` });
      refresh();
    },
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  const steer = useMutation({
    mutationFn: ({ id, verb }: { id: string; verb: "pause" | "resume" | "cancel" }) =>
      steerRollout(id, verb),
    onSuccess: refresh,
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  if (isLoading) return <CircularProgress />;

  const images = imageData?.images ?? [];

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 2 }}>Imaging</Typography>
      {msg && <Alert severity={msg.kind} sx={{ mb: 2 }} onClose={() => setMsg(null)}>{msg.text}</Alert>}

      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        <Tab label={`Machines${fleet ? ` (${fleet.machines.length})` : ""}`} />
        <Tab label={`Rollouts${rollouts.length ? ` (${rollouts.length})` : ""}`} />
        <Tab label={`Images${images.length ? ` (${images.length})` : ""}`} />
        <Tab label={`Bundles${bundleData ? ` (${bundleData.bundles.length})` : ""}`} />
      </Tabs>

      {tab === 0 && <MachinesTab fleet={fleet} canManage={canManage}
                                 onNudge={(id) => nudge.mutate(id)} busy={nudge.isPending}
                                 onDone={refresh} setMsg={setMsg} />}
      {tab === 1 && <RolloutsTab rollouts={rollouts} canManage={canManage}
                                 onSteer={(id, verb) => steer.mutate({ id, verb })}
                                 onCreated={refresh} setMsg={setMsg} />}
      {tab === 2 && <ImagesTab images={images} dir={imageData?.dir ?? ""} />}
      {tab === 3 && <BundlesTab data={bundleData} />}
    </Box>
  );
}

// --- machines ----------------------------------------------------------------

function MachinesTab({ fleet, canManage, onNudge, busy, onDone, setMsg }: {
  fleet?: Awaited<ReturnType<typeof listMachines>>;
  canManage: boolean;
  onNudge: (machineId: string) => void;
  busy: boolean;
  onDone: () => void;
  setMsg: (m: Note) => void;
}) {
  const [pairing, setPairing] = useState<Machine | null>(null);
  const [installing, setInstalling] = useState<Machine | null>(null);
  const { data: bundleData } = useQuery({ queryKey: ["imaging-bundles"], queryFn: listBundles });

  const hold = useMutation({
    mutationFn: ({ id, held }: { id: string; held: boolean }) => updateMachine(id, { held }),
    onSuccess: (m) => {
      setMsg({
        kind: "info",
        text: m.held
          ? `${m.hostname || m.id} is held back. It keeps reporting, and rollouts carry on without waiting for it.`
          : `${m.hostname || m.id} is back in rollouts.`,
      });
      onDone();
    },
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  if (!fleet) return <CircularProgress />;
  const versions = Object.entries(fleet.versions).sort((a, b) => b[1] - a[1]);

  if (fleet.machines.length === 0) {
    return (
      <Alert severity="info">
        No machines have checked in yet. A machine appears here the first time its agent
        reports, which is on its first boot after imaging — before it is enrolled as a host.
      </Alert>
    );
  }

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
              <TableCell>Machine</TableCell>
              <TableCell>OS version</TableCell>
              <TableCell>Presence</TableCell>
              <TableCell>Host</TableCell>
              <TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {fleet.machines.map((m) => {
              const p = PRESENCE[m.presence] ?? PRESENCE.unknown;
              return (
                <TableRow key={m.id} hover sx={{ opacity: m.held ? 0.6 : 1 }}>
                  <TableCell>
                    <Typography variant="body2">
                      {m.label || m.hostname || m.id}
                      {m.held && <Chip size="small" sx={{ ml: 1 }} label="held" />}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {m.id}{m.slot ? ` · slot ${m.slot}` : ""}{m.arch ? ` · ${m.arch}` : ""}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {m.version || "—"}
                    {m.updateState && m.updateState !== "idle" && (
                      <Chip size="small" sx={{ ml: 1 }} label={m.updateState} />
                    )}
                    {m.updateError && (
                      <Typography variant="caption" color="error" display="block">
                        {m.updateError}
                      </Typography>
                    )}
                    {/* Whose word this is. A machine's own check-in and something
                        having read the version off it over SSH are different
                        evidence, and when one turns out to be wrong it matters
                        which kind it was. */}
                    {m.reportSource === "observed" && (
                      <Tooltip title={`Read off the host by ${m.reportedBy || "this server"}, not reported by the machine.`}>
                        <Typography variant="caption" color="text.secondary" display="block">
                          observed
                        </Typography>
                      </Tooltip>
                    )}
                  </TableCell>
                  <TableCell>
                    <Chip size="small" color={p.color} label={p.label} />
                    {m.health === "degraded" && (
                      <Chip size="small" color="error" sx={{ ml: 0.5 }} label="degraded" />
                    )}
                    {m.lastSeen && (
                      <Typography variant="caption" color="text.secondary" display="block">
                        {formatDateTime(m.lastSeen)}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    {m.hostId ? (
                      <>
                        <Typography variant="body2">{m.hostName}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {m.environment}
                          {/* Reachability is the difference between an update
                              that lands in minutes and one that lands whenever
                              the machine next asks. */}
                          {m.reachable ? " · reachable" : " · not reachable from here"}
                        </Typography>
                      </>
                    ) : (
                      <Tooltip title="Imaged but not paired with an enrolled host. It still takes rollouts on its own timer; it just cannot be reached.">
                        <Typography variant="caption" color="text.secondary">not paired</Typography>
                      </Tooltip>
                    )}
                  </TableCell>
                  <TableCell align="right">
                    <Stack direction="row" spacing={1} justifyContent="flex-end">
                      {canManage && (
                        <Tooltip title="Pair this machine with the host it is">
                          <span><Button size="small" startIcon={<LinkIcon />}
                                        onClick={() => setPairing(m)}>Pair</Button></span>
                        </Tooltip>
                      )}
                      {canManage && (
                        <Tooltip title={m.held
                          ? "Put this machine back into rollouts"
                          : "Hold it back: it keeps reporting, and rollouts carry on without waiting for it"}>
                          <span><Button size="small" disabled={hold.isPending}
                                        onClick={() => hold.mutate({ id: m.id, held: !m.held })}>
                            {m.held ? "Release" : "Hold"}
                          </Button></span>
                        </Tooltip>
                      )}
                      {canManage && m.hostId && m.reachable && (
                        <Tooltip title="Make this machine check in now instead of waiting for its timer">
                          <span><Button size="small" startIcon={<BoltIcon />} disabled={busy}
                                        onClick={() => onNudge(m.id)}>Check in now</Button></span>
                        </Tooltip>
                      )}
                      {/* The escape hatch for a machine this server can reach and
                          that cannot reach it back: it will never be nudged into
                          checking in, because it has nowhere to check in to.
                          Offered only for those, so it does not become the
                          habitual button — a rollout applies canary, soak and a
                          failure budget, and this bypasses all three. */}
                      {canManage && m.hostId && m.reachable &&
                        (m.presence === "unknown" || m.presence === "offline") && (
                        <Tooltip title="Install a bundle over SSH. For machines that cannot reach this server at all — it bypasses the rollout's canary, soak and failure budget.">
                          <span><Button size="small" color="warning" startIcon={<DownloadingIcon />}
                                        onClick={() => setInstalling(m)}>Install directly</Button></span>
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

      <PairDialog machine={pairing} onClose={() => setPairing(null)} setMsg={setMsg} onDone={onDone} />
      <InstallDialog machine={installing} controlUrl={bundleData?.controlUrl ?? ""}
                     onClose={() => setInstalling(null)} setMsg={setMsg} onDone={onDone} />
    </>
  );
}

/**
 * PairDialog: say which enrolled host a machine is.
 *
 * Recorded rather than guessed. Matching on hostname works right up until
 * somebody renames one, and then it silently re-points at a different machine —
 * which for a rollout means updating something nobody targeted.
 */
function PairDialog({ machine, onClose, onDone, setMsg }: {
  machine: Machine | null; onClose: () => void; onDone: () => void; setMsg: (m: Note) => void;
}) {
  const { data: hostData } = useQuery({
    queryKey: ["hosts"], queryFn: listHosts, enabled: !!machine,
  });
  const [hostId, setHostId] = useState<string | null>(null);
  const hosts = hostData?.hosts ?? [];

  const save = useMutation({
    mutationFn: () => updateMachine(machine!.id, { hostId: hostId ?? "" }),
    onSuccess: () => {
      setMsg({ kind: "success", text: hostId ? "Paired." : "Pairing cleared." });
      onDone();
      onClose();
    },
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  return (
    <Dialog open={!!machine} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Pair {machine?.hostname || machine?.id} with a host</DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Pairing is what lets this server reach the machine: check-ins on demand,
          direct installs, and reading a version off it when it cannot report for
          itself. Unpaired machines still take rollouts — just on their own timer.
        </Typography>
        <Autocomplete
          options={hosts}
          getOptionLabel={(h) => `${h.hostname}${h.environment ? ` (${h.environment})` : ""}`}
          value={hosts.find((h) => h.id === hostId) ?? null}
          onChange={(_, h) => setHostId(h?.id ?? null)}
          renderInput={(params) => (
            <TextField {...params} autoFocus label="Host"
                       helperText="Leave empty and save to clear the pairing." />
          )}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={() => save.mutate()} disabled={save.isPending}>Save</Button>
      </DialogActions>
    </Dialog>
  );
}

/**
 * InstallDialog: write a bundle to one machine over SSH.
 *
 * The path for a machine this server reaches and that cannot reach it back — a
 * site with no route home, or a host imaged before the agent existed. It is
 * deliberately not the ordinary way to update a machine: a rollout decides who
 * goes first, waits to see whether it worked, and stops if enough of them fail,
 * and none of that applies here.
 */
function InstallDialog({ machine, controlUrl, onClose, onDone, setMsg }: {
  machine: Machine | null; controlUrl: string; onClose: () => void; onDone: () => void;
  setMsg: (m: Note) => void;
}) {
  const { data: bundleData } = useQuery({
    queryKey: ["imaging-bundles"], queryFn: listBundles, enabled: !!machine,
  });
  const [bundle, setBundle] = useState("");
  const [override, setOverride] = useState("");

  // The URL the *machine* will fetch from, built from CONTROL_URL — the address
  // that works from where the fleet lives. That is routinely not the address
  // this browser uses to reach the server, which is exactly the mistake that
  // makes a download fail on the machine and nowhere else.
  const url = override.trim() ||
    (bundle && controlUrl ? `${controlUrl.replace(/\/$/, "")}/bundles/${bundle}` : "");

  const install = useMutation({
    mutationFn: () => installOnMachine(machine!.id, url),
    onSuccess: (r) => {
      setMsg(r.ok
        ? { kind: "success", text: r.note ?? "Installed to the inactive slot." }
        : { kind: "error", text: r.error ?? "The install failed." });
      onDone();
      onClose();
    },
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  return (
    <Dialog open={!!machine} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Install a bundle on {machine?.hostName || machine?.hostname}</DialogTitle>
      <DialogContent>
        <Alert severity="warning" sx={{ mb: 2 }}>
          This writes the inactive slot directly and bypasses the rollout machinery —
          no canary, no soak, no failure budget. Use it for machines that cannot reach
          this server at all; everything else should go through a rollout.
        </Alert>
        <TextField select fullWidth label="Bundle" value={bundle}
                   onChange={(e) => setBundle(e.target.value)}
                   helperText="The machine fetches this itself, over the overlay it already trusts.">
          {(bundleData?.bundles ?? []).map((b) => (
            <MenuItem key={b.name} value={b.name}>{b.name}{b.version ? ` — ${b.version}` : ""}</MenuItem>
          ))}
        </TextField>
        {!controlUrl && (
          <Alert severity="warning" sx={{ mt: 2 }}>
            No control URL is set, so there is no address to tell the machine to fetch
            from. Set <code>CONTROL_URL</code>, or give a full URL below.
          </Alert>
        )}
        <TextField fullWidth sx={{ mt: 2 }} label="Or a full bundle URL" value={override}
                   onChange={(e) => setOverride(e.target.value)}
                   placeholder={url || "http://provisioning.example.com/bundles/name.raucb"}
                   helperText={url ? `The machine will fetch: ${url}` : undefined} />
        <Typography variant="caption" color="text.secondary">
          The machine boots what is installed on its next reboot; until then it is still
          running the old version, and RAUC verifies the signature against the certificate
          inside its own image exactly as on every other path.
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
  setMsg: (m: Note) => void;
}) {
  const [open, setOpen] = useState(false);
  const { data: groups = [] } = useQuery({ queryKey: ["groups"], queryFn: listGroups });
  const groupName = useMemo(() => {
    const by = new Map(groups.map((g) => [g.id, g.name]));
    return (id: string) => by.get(id) ?? id;
  }, [groups]);

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
          const target = r.targetAll
            ? "the whole fleet"
            : [...r.targetGroups.map(groupName), ...r.targetHosts].join(", ");
          return (
            <Paper key={r.id} variant="outlined" sx={{ p: 2 }}>
              <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }} flexWrap="wrap" useFlexGap>
                <Typography variant="subtitle1">{r.version}</Typography>
                <Chip size="small" color={ROLLOUT_COLOR[r.state]} label={r.state} />
                <Typography variant="caption" color="text.secondary">
                  {r.bundle} → {target} · {r.done} of {r.total}
                  {r.createdBy ? ` · by ${r.createdBy}` : ""}
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
                  {r.haltReason} Resuming continues with the machines that have not been
                  tried; the ones that failed stay failed, and the budget counts from there.
                </Alert>
              )}
              <LinearProgress variant="determinate" value={pct}
                              color={r.state === "halted" ? "error" : "primary"} />
              <Stack direction="row" spacing={1} sx={{ mt: 1 }} flexWrap="wrap" useFlexGap>
                {Object.entries(r.counts ?? {}).map(([k, n]) => (
                  <Chip key={k} size="small" variant="outlined" label={`${k}: ${n}`} />
                ))}
                <Box flexGrow={1} />
                <Typography variant="caption" color="text.secondary">
                  canary {r.canary} · batches of {r.batchSize} ·
                  {" "}soak {Math.round(r.soakSeconds / 60)}m · stop after {r.maxFailures}
                  {r.windowStart ? ` · ${r.windowStart}–${r.windowEnd}` : ""}
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
  open: boolean; onClose: () => void; onCreated: () => void; setMsg: (m: Note) => void;
}) {
  const { data: bundleData } = useQuery({
    queryKey: ["imaging-bundles"], queryFn: listBundles, enabled: open,
  });
  // The product's own host groups, not a second set naming the same machines.
  // Keeping two in step is work nobody would have done.
  const { data: groups = [] } = useQuery({ queryKey: ["groups"], queryFn: listGroups, enabled: open });

  const [bundle, setBundle] = useState("");
  const [group, setGroup] = useState("");
  const [canary, setCanary] = useState(1);
  const [batch, setBatch] = useState(10);
  const [soak, setSoak] = useState(15);
  const [maxFail, setMaxFail] = useState(2);
  const [windowed, setWindowed] = useState(false);
  const [start, setStart] = useState("22:00");
  const [end, setEnd] = useState("04:00");

  const create = useMutation({
    mutationFn: () => createRollout({
      bundle,
      groups: group ? [group] : [],
      all: !group,
      canary, batchSize: batch, soakSeconds: soak * 60, maxFailures: maxFail,
      ...(windowed ? { windowStart: start, windowEnd: end } : {}),
    }),
    onSuccess: () => { setMsg({ kind: "success", text: "Rollout started." }); onCreated(); },
    // The backend validates a rollout and says exactly what is wrong with one —
    // an unversioned bundle, a target matching nothing, a missing control URL.
    // Its wording is passed through rather than replaced with something vaguer.
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  const bundles = bundleData?.bundles ?? [];
  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>New rollout</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <TextField select fullWidth label="Bundle" value={bundle}
                     onChange={(e) => setBundle(e.target.value)}>
            {bundles.map((b) => (
              <MenuItem key={b.name} value={b.name}>
                {b.name}{b.version ? ` — ${b.version}` : " — no version recorded"}
              </MenuItem>
            ))}
          </TextField>
          <TextField select fullWidth label="Target" value={group}
                     onChange={(e) => setGroup(e.target.value)}
                     helperText="Host groups, the same ones access and policy use.">
            <MenuItem value="">The whole fleet</MenuItem>
            {groups.map((g) => (
              <MenuItem key={g.id} value={g.id}>
                {g.name}{g.hostCount != null ? ` (${g.hostCount} hosts)` : ""}
              </MenuItem>
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
          <FormControlLabel
            control={<Switch checked={windowed} onChange={(e) => setWindowed(e.target.checked)} />}
            label="Only start machines inside a maintenance window" />
          {windowed && (
            <>
              <Stack direction="row" spacing={2}>
                <TextField label="From" value={start} onChange={(e) => setStart(e.target.value)}
                           placeholder="22:00" />
                <TextField label="Until" value={end} onChange={(e) => setEnd(e.target.value)}
                           placeholder="04:00" />
              </Stack>
              <Typography variant="caption" color="text.secondary">
                Server time, deliberately: a window read against each machine's own clock
                means different things on different machines, and the one whose timezone is
                wrong is exactly the one nobody notices until it reboots mid-shift. The
                window gates when a machine is <em>started</em>; one already installing is
                left to finish.
              </Typography>
            </>
          )}
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

function ImagesTab({ images, dir }: {
  images: Awaited<ReturnType<typeof listImages>>["images"]; dir: string;
}) {
  if (images.length === 0) {
    return (
      <Alert severity="info">
        No images have been built yet{dir ? <> — nothing in <code>{dir}</code></> : null}.
      </Alert>
    );
  }
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
                  {i.encrypted && <Chip size="small" label="LUKS" />}
                  {i.secureBoot && <Chip size="small" color="success" label="Secure Boot" />}
                  {i.profile && i.profile !== "minimal" && <Chip size="small" label={i.profile} />}
                </Stack>
              </TableCell>
              <TableCell>{[i.distro, i.suite, i.arch].filter(Boolean).join(" ")}</TableCell>
              <TableCell>{i.version ?? "—"}</TableCell>
              <TableCell>
                {i.hasSbom
                  ? `${i.packages ?? 0} packages`
                  /* Worth naming rather than blanking: an image with no SBOM is
                     one nothing can answer a CVE question about later. */
                  : <Typography variant="caption" color="text.secondary">no SBOM</Typography>}
              </TableCell>
              <TableCell>{bytes(i.size)}</TableCell>
              <TableCell>{formatDateTime(i.created)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Paper>
  );
}

function BundlesTab({ data }: { data?: Awaited<ReturnType<typeof listBundles>> }) {
  const running = data?.runningVersions ?? {};
  const rows = data?.bundles ?? [];
  if (rows.length === 0) {
    return <Alert severity="info">No update bundles have been built yet.</Alert>;
  }
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
                {b.name}
                {b.isLatest && (
                  <Tooltip title="What a machine running bare ab-update fetches. Deleting it changes what the whole fleet gets.">
                    <Chip size="small" color="primary" sx={{ ml: 1 }} label="latest" />
                  </Tooltip>
                )}
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
