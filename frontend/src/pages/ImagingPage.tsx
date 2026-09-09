import { useEffect, useMemo, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, Divider, FormControlLabel, LinearProgress, MenuItem,
  Paper, Stack, Switch, Tab, Table, TableBody, TableCell, TableHead, TableRow, Tabs,
  TextField, Tooltip, Typography,
} from "@mui/material";
import BoltIcon from "@mui/icons-material/Bolt";
import DeleteIcon from "@mui/icons-material/Delete";
import DownloadingIcon from "@mui/icons-material/Downloading";
import LinkIcon from "@mui/icons-material/Link";
import PauseIcon from "@mui/icons-material/Pause";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import StopIcon from "@mui/icons-material/Stop";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import BuildIcon from "@mui/icons-material/Build";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { formatDateTime } from "../lib/datetime";
import { useAuthStore } from "../store/auth";
import { listGroups } from "../api/admin";
import { listHosts, createHost } from "../api/hosts";
import { ProvisioningTab } from "./imaging/ProvisioningTab";
import { OverlayTab } from "./imaging/OverlayTab";
import { KeysTab } from "./imaging/KeysTab";
import { distroFamily, DEFAULT_SUITE, RPM_SUITES } from "./imaging/distro";
import { WritableState } from "./imaging/WritableState";
import {
  WRITABLE_STATE_DEFAULT, invalidPaths, type WritableStateValue,
} from "./imaging/writable-state";
import {
  buildLog, cancelBuild, createRollout, deleteBundle, deleteImage, diskUsage,
  forgetImaging, imageDownloadUrl, imageSbomUrl, imagingNow, installOnMachine,
  listBuilds, listBundles, listImages,
  deleteMachine, forgetBuild, forgetFinishedBuilds, listMachines, listRollouts, nudgeMachine, startBuild, steerRollout, updateMachine,
  type BuildJob, type Bundle, type Image, type ImagingNow, type Machine, type Rollout,
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
  const canBuild = useAuthStore((s) => s.has("Imaging.Build"));
  // Its own permission: this is the part that puts a DHCP server on a network.
  const canProvision = useAuthStore((s) => s.has("Imaging.Provision"));
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
  // A running build is polled; an idle list is not. There is nothing to watch
  // between builds, and this page is left open all day.
  // Polled quickly while anything is being written, and not at all otherwise.
  // An imaging run is twenty minutes of a machine that cannot be reached any
  // other way, so this is the one view where a stale number is actively unhelpful.
  const { data: now } = useQuery({
    queryKey: ["imaging-now"], queryFn: imagingNow,
    refetchInterval: (q) => ((q.state.data as { active: number } | undefined)?.active ? 3_000 : 20_000),
  });
  const { data: builds = [] } = useQuery({
    queryKey: ["imaging-builds"], queryFn: listBuilds, retry: false,
    refetchInterval: (q) =>
      (q.state.data as BuildJob[] | undefined)?.some((b) => b.status === "running") ? 3_000 : false,
  });

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["imaging-machines"] });
    qc.invalidateQueries({ queryKey: ["imaging-rollouts"] });
  };
  const refreshArtifacts = () => {
    qc.invalidateQueries({ queryKey: ["imaging-images"] });
    qc.invalidateQueries({ queryKey: ["imaging-bundles"] });
    qc.invalidateQueries({ queryKey: ["imaging-builds"] });
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

      {/* Above the tabs, not inside one. A machine being written is the most
          perishable thing on this page -- it exists for twenty minutes and
          cannot be reached any other way -- and it should not be somewhere an
          operator has to already know to look. */}
      <ImagingNowPanel rows={now?.imaging ?? []} canManage={canManage}
                       onDone={() => qc.invalidateQueries({ queryKey: ["imaging-now"] })} />

      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        <Tab label={`Machines${fleet ? ` (${fleet.machines.length})` : ""}`} />
        <Tab label={`Rollouts${rollouts.length ? ` (${rollouts.length})` : ""}`} />
        <Tab label={`Images${images.length ? ` (${images.length})` : ""}`} />
        <Tab label={`Bundles${bundleData ? ` (${bundleData.bundles.length})` : ""}`} />
        <Tab label={`Builds${builds.length ? ` (${builds.length})` : ""}`} />
        <Tab label="Provisioning" />
        <Tab label="Overlay" />
        <Tab label="Keys" />
      </Tabs>

      {tab === 0 && <MachinesTab fleet={fleet} canManage={canManage}
                                 onNudge={(id) => nudge.mutate(id)} busy={nudge.isPending}
                                 onDone={refresh} setMsg={setMsg} />}
      {tab === 1 && <RolloutsTab rollouts={rollouts} canManage={canManage}
                                 onSteer={(id, verb) => steer.mutate({ id, verb })}
                                 onCreated={refresh} setMsg={setMsg} />}
      {tab === 2 && <ImagesTab images={images} dir={imageData?.dir ?? ""}
                               imagerArches={imageData?.imagerArches ?? {}} canBuild={canBuild}
                               onChanged={refreshArtifacts} setMsg={setMsg} />}
      {tab === 3 && <BundlesTab data={bundleData} images={images} canBuild={canBuild}
                                onChanged={refreshArtifacts} setMsg={setMsg} />}
      {tab === 4 && <BuildsTab builds={builds} canBuild={canBuild}
                               onChanged={refreshArtifacts} setMsg={setMsg} />}
      {/* IMAGE_FILE is a filename in the output directory, which is exactly what
          Image.name is — the tab needs nothing else about an image. */}
      {tab === 5 && <ProvisioningTab images={images.map((i) => i.name)} canProvision={canProvision}
                                     setMsg={(text, kind) => setMsg({ kind: kind ?? "success", text })} />}
      {tab === 6 && <OverlayTab canBuild={canBuild}
                                setMsg={(text, kind) => setMsg({ kind: kind ?? "success", text })} />}
      {tab === 7 && <KeysTab canProvision={canProvision}
                             setMsg={(text, kind) => setMsg({ kind: kind ?? "success", text })} />}
    </Box>
  );
}

// --- machines being imaged right now -----------------------------------------

const IMAGING_STATE: Record<string, { color: "info" | "warning" | "success" | "error"; label: string }> = {
  active: { color: "info", label: "imaging" },
  stalled: { color: "warning", label: "stalled" },
  done: { color: "success", label: "done" },
  failed: { color: "error", label: "failed" },
};

function mmss(seconds: number) {
  const s = Math.max(0, Math.round(seconds));
  return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}

/**
 * ImagingNowPanel: what is being written to a disk at this moment.
 *
 * Absent entirely when nothing is imaging, rather than an empty box. This is a
 * progress bar, not an inventory — the inventory is the Machines tab, and a
 * machine appears there for good once its run finishes.
 */
function ImagingNowPanel({ rows, canManage, onDone }: {
  rows: ImagingNow[]; canManage: boolean; onDone: () => void;
}) {
  const forget = useMutation({
    mutationFn: (id: string) => forgetImaging(id),
    onSuccess: onDone,
  });
  if (rows.length === 0) return null;

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
      <Typography variant="subtitle2" sx={{ mb: 1.5 }}>
        Being imaged now ({rows.length})
      </Typography>
      <Stack spacing={1.5}>
        {rows.map((r) => {
          const st = IMAGING_STATE[r.state] ?? IMAGING_STATE.active;
          return (
            <Box key={r.id}>
              <Stack direction="row" alignItems="center" spacing={1} flexWrap="wrap" useFlexGap>
                <Typography variant="body2">{r.id}</Typography>
                <Chip size="small" color={st.color} label={st.label} />
                <Typography variant="caption" color="text.secondary">
                  {r.phase}{r.detail ? ` — ${r.detail}` : ""}
                  {r.disk ? ` · ${r.disk}` : ""} · {mmss(r.ageSeconds)}
                </Typography>
                <Box flexGrow={1} />
                {r.state === "stalled" && (
                  <Tooltip title="No report for a while. The imager reports on phase changes rather than on a timer, and writing a large image to a slow disk is a long silence — this is not yet a failure.">
                    <Typography variant="caption" color="warning.main">
                      quiet for {mmss(r.staleSeconds)}
                    </Typography>
                  </Tooltip>
                )}
                {canManage && (r.state === "stalled" || r.state === "failed") && (
                  <Tooltip title="Drop this row. It expires on its own; this is for a machine you know will never report again.">
                    <span><Button size="small" disabled={forget.isPending}
                                  onClick={() => forget.mutate(r.id)}>Dismiss</Button></span>
                  </Tooltip>
                )}
              </Stack>
              <LinearProgress variant="determinate" value={r.percent}
                              color={r.state === "failed" ? "error" : r.state === "done" ? "success" : "primary"} />
            </Box>
          );
        })}
      </Stack>
    </Paper>
  );
}

// --- machines ----------------------------------------------------------------

export function MachinesTab({ fleet, canManage, onNudge, busy, onDone, setMsg }: {
  fleet?: Awaited<ReturnType<typeof listMachines>>;
  canManage: boolean;
  onNudge: (machineId: string) => void;
  busy: boolean;
  onDone: () => void;
  setMsg: (m: Note) => void;
}) {
  const [pairing, setPairing] = useState<Machine | null>(null);
  const [installing, setInstalling] = useState<Machine | null>(null);
  const [forgetting, setForgetting] = useState<Machine | null>(null);
  const [adopting, setAdopting] = useState<Machine | null>(null);
  // "Needs a host" rather than hiding managed machines by default. A row that
  // vanishes when you act on it teaches you to distrust the list; a filter you
  // chose is a different thing.
  const [onlyUnpaired, setOnlyUnpaired] = useState(false);
  const { data: bundleData } = useQuery({ queryKey: ["imaging-bundles"], queryFn: listBundles });

  const forget = useMutation({
    mutationFn: (id: string) => deleteMachine(id),
    onSuccess: () => {
      setMsg({ kind: "info", text: `Removed ${forgetting?.hostname || forgetting?.id}. If that machine still exists it will reappear on its next check-in.` });
      setForgetting(null);
      onDone();
    },
    onError: (e) => { setMsg({ kind: "error", text: apiError(e) }); setForgetting(null); },
  });

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
  const unpaired = fleet.machines.filter((m) => !m.hostId).length;
  const shown = onlyUnpaired ? fleet.machines.filter((m) => !m.hostId) : fleet.machines;

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

      {/* A machine does not leave this list when it becomes a host, and should
          not: this row is its A/B update record — slot, image, running version,
          rollout progress — none of which the host record holds, and rollout
          progress is keyed on it with ON DELETE CASCADE. Removing it on pairing
          would silently drop the machine out of every future rollout, and its
          agent would recreate the row on the next check-in anyway.
          What the list needed was not fewer rows but a way to see which ones
          still want something doing. */}
      <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="body2" color="text.secondary" sx={{ flexGrow: 1 }}>
          {unpaired === 0
            ? `All ${fleet.machines.length} machines are paired with a host.`
            : `${unpaired} of ${fleet.machines.length} not yet added as a host.`}
        </Typography>
        {unpaired > 0 && (
          <Tooltip title="Machines stay listed after they become hosts — this row is their update record. Filter to the ones still waiting.">
            <FormControlLabel
              control={<Switch size="small" checked={onlyUnpaired}
                               onChange={(e) => setOnlyUnpaired(e.target.checked)} />}
              label={<Typography variant="body2">Only ones needing a host</Typography>}
            />
          </Tooltip>
        )}
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
            {shown.map((m) => {
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
                      {/* Forgetting a machine. Last in the row and only for
                          operators who can manage, because it is the one action
                          here that removes a record rather than changing one --
                          and the confirmation says the thing that makes it safe:
                          a machine that still exists comes back by itself. */}
                      {/* An imaged machine is not yet a managed host: it has to
                          exist in Hosts and be paired before this server can
                          reach it. Everything that takes is already known here —
                          the hostname it was given at imaging and the address it
                          reported — so offer it rather than making somebody
                          retype it in another page and come back to pair. */}
                      {canManage && !m.hostId && (
                        <Tooltip title="Create a managed host from this machine and pair them, in one step">
                          <span><Button size="small" variant="outlined" startIcon={<LinkIcon />}
                                        onClick={() => setAdopting(m)}>Add as host</Button></span>
                        </Tooltip>
                      )}
                      {canManage && (
                        <Tooltip title="Remove this machine from the list. If it still exists it reappears on its next check-in.">
                          <span><Button size="small" color="error" disabled={forget.isPending}
                                        onClick={() => setForgetting(m)}>Forget</Button></span>
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

      <AddAsHostDialog machine={adopting} onClose={() => setAdopting(null)}
                       setMsg={setMsg} onDone={onDone} />
      <PairDialog machine={pairing} onClose={() => setPairing(null)} setMsg={setMsg} onDone={onDone} />
      <InstallDialog machine={installing} controlUrl={bundleData?.controlUrl ?? ""}
                     onClose={() => setInstalling(null)} setMsg={setMsg} onDone={onDone} />

      {/* A confirmation, because this removes a record rather than changing one.
          It leads with what makes the action safe rather than with a warning: if
          the machine still exists it comes back by itself, so the mistake costs
          a heartbeat interval and not a record. */}
      <Dialog open={!!forgetting} onClose={() => setForgetting(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Forget {forgetting?.hostname || forgetting?.id}?</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 2 }}>
            This removes the machine and its imaging history from this list.
          </Typography>
          <Alert severity="info">
            If the machine still exists it reappears on its next check-in. This is
            for hardware that is gone, was reimaged under a different MAC, or only
            ever appeared because of a test boot. Any host it is paired to is left
            alone.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setForgetting(null)}>Cancel</Button>
          <Button color="error" variant="contained" disabled={forget.isPending}
                  onClick={() => forgetting && forget.mutate(forgetting.id)}>
            {forget.isPending ? "Removing…" : "Forget it"}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

/**
 * AddAsHostDialog: turn an imaged machine into a managed host, and pair them.
 *
 * An imaged machine and a managed host are two different records, and until now
 * getting from one to the other meant leaving this page, creating a host by
 * hand, retyping the hostname and address that imaging already knew, and coming
 * back to pair. Three of those four steps are the machine telling us what it
 * already told us.
 *
 * What it cannot know is the login user — that was chosen when the image was
 * built and is not carried on the machine record — and which environment and
 * owner this machine belongs to, which are the operator's to decide. So those
 * are asked for and everything else is filled in.
 *
 * Creating and pairing are one action here but two writes. If the pairing fails
 * the host still exists, and the message says so: a half-done step that reports
 * failure and leaves a stray host is worse than one that says what it managed.
 */
function AddAsHostDialog({ machine, onClose, onDone, setMsg }: {
  machine: Machine | null; onClose: () => void; onDone: () => void; setMsg: (m: Note) => void;
}) {
  const [sshUser, setSshUser] = useState("fleet");
  const [environment, setEnvironment] = useState("");
  const [owner, setOwner] = useState("");
  const [address, setAddress] = useState("");
  const [hostname, setHostname] = useState("");

  // Re-seed each time a different machine is chosen, not on every render.
  useEffect(() => {
    if (!machine) return;
    setHostname(machine.hostname || machine.id);
    setAddress(machine.address || "");
    setSshUser("fleet");
    setEnvironment("");
    setOwner("");
  }, [machine]);

  const adopt = useMutation({
    mutationFn: async () => {
      const host = await createHost({
        hostname: hostname.trim(),
        description: `Imaged by Blackfriars${machine?.image ? ` from ${machine.image}` : ""}`,
        environment: environment.trim(),
        owner: owner.trim(),
        address: address.trim(),
        wgAddress: "",
        sshPort: 22,
        sshUser: sshUser.trim(),
        tags: [],
      });
      try {
        await updateMachine(machine!.id, { hostId: host.id });
      } catch (e) {
        // The host is real even though the pairing failed. Say which half
        // happened rather than leaving a stray host nobody knows about.
        throw new Error(
          `Created the host ${host.hostname}, but could not pair it with this machine: ` +
          `${apiError(e)}. Pair them from this page.`);
      }
      return host;
    },
    onSuccess: (host) => {
      setMsg({
        kind: "success",
        text: `${host.hostname} added and paired. It is not enrolled yet — enrol it from Hosts to let this server reach it.`,
      });
      onDone();
      onClose();
    },
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  const ready = hostname.trim() && sshUser.trim() && address.trim();

  return (
    <Dialog open={!!machine} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Add {machine?.hostname || machine?.id} as a managed host</DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Creates the host record and pairs it with this machine. The hostname and
          address come from imaging; the rest is yours to set.
        </Typography>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <TextField size="small" label="Hostname" value={hostname}
                     onChange={(e) => setHostname(e.target.value)} fullWidth
                     helperText="The name it was given when it was imaged." />
          <TextField size="small" label="Address" value={address}
                     onChange={(e) => setAddress(e.target.value)} fullWidth
                     helperText={machine?.address
                       ? "The address this machine reported while it was being imaged — on the provisioning network. If it has been moved, this is not where it is now."
                       : "This machine never reported an address — enter the one it has now."} />
          <TextField size="small" label="SSH user" value={sshUser}
                     onChange={(e) => setSshUser(e.target.value)} fullWidth
                     helperText="The account this server connects as. Enrolment creates it — it is not the login user the image was built with." />
          <Stack direction="row" spacing={2}>
            <TextField size="small" label="Environment" value={environment}
                       onChange={(e) => setEnvironment(e.target.value)} fullWidth />
            <TextField size="small" label="Owner" value={owner}
                       onChange={(e) => setOwner(e.target.value)} fullWidth />
          </Stack>
          <Alert severity="info">
            This does not enrol the machine. Enrolment is what establishes the SSH
            trust and the overlay address, and it runs from the Hosts page — an
            image carries only the authorized key it was built with.
          </Alert>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={!ready || adopt.isPending}
                onClick={() => adopt.mutate()}>
          {adopt.isPending ? "Adding…" : "Add and pair"}
        </Button>
      </DialogActions>
    </Dialog>
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

// Which architectures can actually be imaged. The imager is a kernel the target
// machine executes, so an amd64 imager cannot boot an arm64 machine however it is
// served — "built" is per architecture, not a single yes.
function ImagerChips({ arches }: { arches: Record<string, boolean> }) {
  const built = Object.keys(arches).filter((a) => arches[a]);
  if (built.length === 0) return null;
  return (
    <Tooltip title="Architectures with a netboot imager built. A machine picks its own at boot from iPXE's ${buildarch}.">
      <Stack direction="row" spacing={0.5}>
        {built.map((a) => (
          <Chip key={a} size="small" color="success" variant="outlined" label={`imager: ${a}`} />
        ))}
      </Stack>
    </Tooltip>
  );
}

// BuildImagerDialog builds the netboot imager: the kernel and initramfs a machine
// downloads and executes in order to be imaged. Separate from an OS image build
// because it takes no distribution, profile or credentials — only an architecture.
function BuildImagerDialog({ open, arches, onClose, onStarted, setMsg }: {
  open: boolean;
  arches: Record<string, boolean>;
  onClose: () => void;
  onStarted: () => void;
  setMsg: (m: Note) => void;
}) {
  const [arch, setArch] = useState("amd64");

  const start = useMutation({
    mutationFn: () => startBuild("imager", { arch }),
    onSuccess: (job) => {
      setMsg({ kind: "success", text: `Started: ${job.label}. Watch it on the Builds tab.` });
      onStarted();
      onClose();
    },
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="xs">
      <DialogTitle>Build the netboot imager</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Typography variant="body2" color="text.secondary">
            The kernel and initramfs a machine downloads over TFTP and executes to be
            imaged. Without one, PXE boots into nothing and the provisioning server
            refuses to start.
          </Typography>
          <TextField
            select size="small" label="Architecture" value={arch}
            onChange={(e) => setArch(e.target.value)}
            helperText={
              arches[arch]
                ? "Already built for this architecture — rebuilding replaces it."
                : "The imager is a kernel, so it must match the machines it boots."
            }
          >
            <MenuItem value="amd64">amd64</MenuItem>
            <MenuItem value="arm64">arm64</MenuItem>
          </TextField>
          {arch === "arm64" && (
            <Alert severity="info">
              Built under emulation on an amd64 host, which is slow but works. amd64
              lives at the top of the imager directory and arm64 in a subdirectory, so
              both can be present and neither interferes.
            </Alert>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={start.isPending} onClick={() => start.mutate()}>
          {start.isPending ? "Starting…" : "Build"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function DiskChip() {
  const { data } = useQuery({ queryKey: ["imaging-disk"], queryFn: diskUsage, retry: false });
  if (!data) return null;
  // The way a build fails on a full volume is not a clean error: debootstrap
  // gets part way, the loop device stays attached, and the reason is two
  // hundred lines up the log. Cheaper to see the number beforehand.
  const low = data.free > 0 && data.free < 10e9;
  return (
    <Tooltip title={`Artefacts occupy ${bytes(data.artifacts)} of ${bytes(data.total)}`}>
      <Chip size="small" color={low ? "warning" : "default"} variant="outlined"
            label={`${bytes(data.free)} free`} />
    </Tooltip>
  );
}

function ImagesTab({ images, dir, imagerArches, canBuild, onChanged, setMsg }: {
  images: Image[]; dir: string; imagerArches: Record<string, boolean>; canBuild: boolean;
  onChanged: () => void; setMsg: (m: Note) => void;
}) {
  const [building, setBuilding] = useState(false);
  const [buildingImager, setBuildingImager] = useState(false);
  const remove = useMutation({
    mutationFn: (name: string) => deleteImage(name),
    onSuccess: () => { setMsg({ kind: "success", text: "Image deleted." }); onChanged(); },
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  return (
    <>
      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
        {canBuild && (
          <Button variant="contained" startIcon={<BuildIcon />} onClick={() => setBuilding(true)}>
            Build image
          </Button>
        )}
        {canBuild && (
          <Button variant="outlined" startIcon={<BuildIcon />} onClick={() => setBuildingImager(true)}>
            Build netboot imager
          </Button>
        )}
        <ImagerChips arches={imagerArches} />
        <Box flexGrow={1} />
        <DiskChip />
      </Stack>

      {/* Without an imager there is nothing for a machine to PXE-boot, so an
          image library on its own cannot deploy anything. Said here rather than
          only in the provisioning preflight, which is read after a network has
          been chosen and Start pressed. */}
      {!imagerArches.amd64 && !imagerArches.arm64 && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          <strong>No netboot imager has been built.</strong> It is the kernel and
          initramfs a machine downloads and executes in order to be imaged at all —
          without one, PXE boots into nothing and the provisioning server will refuse
          to start. {canBuild
            ? "Build it with the button above; it takes a few minutes."
            : "Building it needs the Imaging.Build permission."}
        </Alert>
      )}

      {images.length === 0 ? (
        <Alert severity="info">
          No images have been built yet{dir ? <> — nothing in <code>{dir}</code></> : null}.
        </Alert>
      ) : (
        <Paper variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Image</TableCell><TableCell>System</TableCell>
                <TableCell>Version</TableCell><TableCell>Contents</TableCell>
                <TableCell>Size</TableCell><TableCell>Built</TableCell>
                <TableCell align="right" />
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
                      ? (
                        <Button size="small" href={imageSbomUrl(i.name)}
                                sx={{ textTransform: "none", p: 0, minWidth: 0 }}>
                          {i.packages ?? 0} packages
                        </Button>
                      )
                      /* Worth naming rather than blanking: an image with no SBOM
                         is one nothing can answer a CVE question about later. */
                      : <Typography variant="caption" color="text.secondary">no SBOM</Typography>}
                  </TableCell>
                  <TableCell>{bytes(i.size)}</TableCell>
                  <TableCell>{formatDateTime(i.created)}</TableCell>
                  <TableCell align="right">
                    {/* Imaging.View, not Build: taking a copy of an image is not
                        producing one, and the person who has to hand it to
                        somebody is not necessarily allowed to start a build. */}
                    <Button size="small" href={imageDownloadUrl(i.name)}
                            sx={{ textTransform: "none" }}>Download</Button>
                    {canBuild && (
                      <Button size="small" color="error" disabled={remove.isPending}
                              onClick={() => remove.mutate(i.name)}>Delete</Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}
      <BuildImageDialog open={building} onClose={() => setBuilding(false)}
                        onStarted={onChanged} setMsg={setMsg} />
      <BuildImagerDialog open={buildingImager} arches={imagerArches}
                         onClose={() => setBuildingImager(false)}
                         onStarted={onChanged} setMsg={setMsg} />
    </>
  );
}

function BundlesTab({ data, images, canBuild, onChanged, setMsg }: {
  data?: Awaited<ReturnType<typeof listBundles>>; images: Image[]; canBuild: boolean;
  onChanged: () => void; setMsg: (m: Note) => void;
}) {
  const [building, setBuilding] = useState(false);
  const running = data?.runningVersions ?? {};
  const rows: Bundle[] = data?.bundles ?? [];
  const remove = useMutation({
    mutationFn: (name: string) => deleteBundle(name),
    onSuccess: () => { setMsg({ kind: "success", text: "Bundle deleted." }); onChanged(); },
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  return (
    <>
      {canBuild && (
        <Button variant="contained" startIcon={<BuildIcon />} sx={{ mb: 2 }}
                onClick={() => setBuilding(true)}>Build bundle</Button>
      )}
      {rows.length === 0 ? (
        <Alert severity="info">
          No update bundles have been built yet. A bundle is a signed image packaged so
          a running machine can install it into its inactive slot.
        </Alert>
      ) : (
        <Paper variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Bundle</TableCell><TableCell>Version</TableCell>
                <TableCell>Built from</TableCell><TableCell>In the field</TableCell>
                <TableCell>Size</TableCell><TableCell>Built</TableCell>
                <TableCell align="right" />
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
                  <TableCell align="right">
                    {canBuild && (
                      <Button size="small" color="error" disabled={remove.isPending}
                              onClick={() => remove.mutate(b.name)}>Delete</Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}
      <BuildBundleDialog open={building} images={images} onClose={() => setBuilding(false)}
                         onStarted={onChanged} setMsg={setMsg} />
    </>
  );
}

// --- builds ------------------------------------------------------------------

const JOB_COLOR: Record<string, "success" | "error" | "warning" | "info"> = {
  running: "info", success: "success", failed: "error", canceled: "warning",
};

function BuildsTab({ builds, canBuild, onChanged, setMsg }: {
  builds: BuildJob[]; canBuild: boolean; onChanged: () => void; setMsg: (m: Note) => void;
}) {
  const [open, setOpen] = useState<string | null>(null);

  // Clearing history. The list is append-only otherwise, and a page showing
  // every build ever run is one nobody reads — which matters, because the
  // failure worth noticing ends up below thirty successes.
  const forget = useMutation({
    mutationFn: (id: string) => forgetBuild(id),
    onSuccess: () => { setMsg({ kind: "info", text: "Build removed from the list." }); onChanged(); },
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });
  const clearAll = useMutation({
    mutationFn: () => forgetFinishedBuilds(),
    onSuccess: (n) => {
      setMsg({ kind: "info", text: `Cleared ${n} finished build${n === 1 ? "" : "s"}. Anything still running was left alone.` });
      onChanged();
    },
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  const cancel = useMutation({
    mutationFn: (id: string) => cancelBuild(id),
    onSuccess: () => {
      // Cancelling removes the container the build runs in, not just the label
      // on it — a non-interactive shell defers signals until its foreground
      // command returns, so signalling the shell alone would leave the builder
      // running while this page claimed the job was cancelled.
      setMsg({ kind: "info", text: "Cancelled. The build container was removed." });
      onChanged();
    },
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  if (builds.length === 0) {
    return (
      <Alert severity="info">
        Nothing has been built here. Builds run in the builder-runner sidecar, which is
        opt-in — if the Build buttons return "no image builder is configured", the
        deployment is not running one. See <code>docs/imaging.md</code>.
      </Alert>
    );
  }

  const finished = builds.filter((b) => b.status !== "running").length;

  return (
    <>
      <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="body2" color="text.secondary" sx={{ flexGrow: 1 }}>
          {builds.length} build{builds.length === 1 ? "" : "s"}
          {finished > 0 ? `, ${finished} finished` : ""}.
        </Typography>
        {canBuild && finished > 0 && (
          <Tooltip title="Remove every build that is not running, and its log. Anything still running is left alone.">
            <span>
              <Button size="small" startIcon={<DeleteIcon />} disabled={clearAll.isPending}
                      onClick={() => clearAll.mutate()}>
                {clearAll.isPending ? "Clearing…" : `Clear ${finished} finished`}
              </Button>
            </span>
          </Tooltip>
        )}
      </Stack>
      <Paper variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Build</TableCell><TableCell>Status</TableCell>
              <TableCell>Started</TableCell><TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {builds.map((b) => (
              <TableRow key={b.id} hover>
                <TableCell>
                  <Typography variant="body2">{b.label}</Typography>
                  <Typography variant="caption" color="text.secondary">{b.id}</Typography>
                  {b.status === "running" && b.progress && (
                    <>
                      <LinearProgress variant="determinate" sx={{ mt: 0.5 }}
                        value={Math.round((b.progress.step / Math.max(b.progress.total, 1)) * 100)} />
                      <Typography variant="caption" color="text.secondary">
                        {b.progress.step}/{b.progress.total} {b.progress.label}
                      </Typography>
                    </>
                  )}
                </TableCell>
                <TableCell>
                  <Chip size="small" color={JOB_COLOR[b.status] ?? "default"} label={b.status} />
                </TableCell>
                <TableCell>{b.started ? formatDateTime(b.started) : "—"}</TableCell>
                <TableCell align="right">
                  <Stack direction="row" spacing={1} justifyContent="flex-end">
                    <Button size="small" onClick={() => setOpen(b.id)}>Log</Button>
                    {canBuild && b.status === "running" && (
                      <Button size="small" color="error" disabled={cancel.isPending}
                              onClick={() => cancel.mutate(b.id)}>Cancel</Button>
                    )}
                    {canBuild && b.status !== "running" && (
                      <Tooltip title="Remove this build and its log from the list">
                        <span>
                          <Button size="small" color="error" disabled={forget.isPending}
                                  onClick={() => forget.mutate(b.id)}>Remove</Button>
                        </span>
                      </Tooltip>
                    )}
                  </Stack>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Paper>
      <BuildLogDialog id={open} onClose={() => setOpen(null)} />
    </>
  );
}

/** BuildLogDialog: the build's output, followed while it is still running. */
function BuildLogDialog({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { data } = useQuery({
    queryKey: ["imaging-build-log", id], queryFn: () => buildLog(id!), enabled: !!id,
    refetchInterval: (q) =>
      (q.state.data as BuildJob | undefined)?.status === "running" ? 2_000 : false,
  });
  return (
    <Dialog open={!!id} onClose={onClose} fullWidth maxWidth="lg">
      <DialogTitle>{data?.label ?? id}</DialogTitle>
      <DialogContent>
        <Box component="pre" sx={{
          m: 0, p: 1.5, maxHeight: "60vh", overflow: "auto", fontSize: 12,
          bgcolor: "action.hover", borderRadius: 1, whiteSpace: "pre-wrap",
        }}>
          {(data?.log ?? []).join("\n") || "…"}
        </Box>
      </DialogContent>
      <DialogActions><Button onClick={onClose}>Close</Button></DialogActions>
    </Dialog>
  );
}

/**
 * BuildImageDialog: the common options, not all of them.
 *
 * The builder takes about thirty; most exist for one deployment's layout and
 * putting all of them in a dialog would bury the six that are always answered.
 * What is left out is reachable by editing the overlay and rebuilding, and the
 * builder validates everything either way — it refuses a build rather than
 * shipping an image whose state manifest is wrong, which is otherwise a thing
 * discovered at a boot prompt.
 */
// Why you would pick each. The trade-off is always the same one: what has to be
// present at boot for the machine to come up on its own.
const UNLOCK_HELP: Record<string, string> = {
  keyfile: "Boots unattended anywhere. The key is in the initramfs, which is not encrypted.",
  tpm2: "Boots unattended, and only on this machine — the key is sealed to its TPM. Enrolled on first boot.",
  tang: "Boots unattended while it can reach the Tang server. Off that network, it needs the passphrase.",
  passphrase: "Someone types it at every boot. No unattended reboots.",
};

function BuildImageDialog({ open, onClose, onStarted, setMsg }: {
  open: boolean; onClose: () => void; onStarted: () => void; setMsg: (m: Note) => void;
}) {
  const [distro, setDistro] = useState("debian");
  const [suite, setSuite] = useState("trixie");
  const [arch, setArch] = useState("amd64");
  const [hostname, setHostname] = useState("");
  const [username, setUsername] = useState("debian");
  const [password, setPassword] = useState("");
  const [profile, setProfile] = useState("minimal");
  const [secureBoot, setSecureBoot] = useState("auto");
  const [packages, setPackages] = useState("");
  const [sshKey, setSshKey] = useState("");
  const [encrypt, setEncrypt] = useState(false);
  const [luks, setLuks] = useState("");
  // keyfile is the builder's own default: it is the only method that both boots
  // unattended and needs nothing else present (no TPM, no Tang server).
  const [unlock, setUnlock] = useState<"passphrase" | "keyfile" | "tpm2" | "tang">("keyfile");
  const [tangUrl, setTangUrl] = useState("");
  // Generating beats typing: it is 256 bits of random rather than something
  // memorable, and it is filed automatically instead of ending up in a note.
  const [genPass, setGenPass] = useState(true);
  const [name, setName] = useState("");
  const [imageSize, setImageSize] = useState("");
  const [rootSize, setRootSize] = useState("");
  const [compress, setCompress] = useState("zstd");
  const [desktop, setDesktop] = useState("gnome");
  const [sshKeyOnly, setSshKeyOnly] = useState(false);
  const [runScript, setRunScript] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [wstate, setWstate] = useState<WritableStateValue>(WRITABLE_STATE_DEFAULT);

  // The builder silently skips a path directive that is not absolute, so a typo
  // would be a setting that appears to have been accepted and is simply not in
  // the image. Cheaper to refuse than to discover on a machine.
  const badPaths = [
    wstate.persistPaths, wstate.slotPrivatePaths, wstate.volatilePaths,
    wstate.resetPaths, wstate.keepPaths, wstate.ownPaths,
  ].flatMap(invalidPaths);

  const start = useMutation({
    mutationFn: () => startBuild("image", {
      distro, suite, arch, hostname: hostname.trim(), username,
      password: password || "debian", profile, secureBoot,
      packages: packages.trim(), sshKey: sshKey.trim(),
      encrypt,
      luksPassphrase: encrypt ? luks : "",
      unlock: encrypt ? unlock : undefined,
      tangUrl: encrypt && unlock === "tang" ? tangUrl.trim() : undefined,
      generatePassphrase: encrypt ? genPass : undefined,
      // Only sent when given: the builder's own defaults are better than a
      // number this dialog invented, and "0" does not mean "unset" to it.
      name: name.trim() || undefined,
      imageSize: imageSize.trim() || undefined,
      rootSize: rootSize.trim() ? Number(rootSize) : undefined,
      compress,
      desktop: profile === "desktop" ? desktop : undefined,
      sshKeyOnly: sshKeyOnly || undefined,
      runScript: runScript.trim() || undefined,
      ...wstate,
    }),
    onSuccess: (job) => {
      const where = job.passphraseStoredIn === "external"
        ? `Recovery passphrase filed in the secrets manager at ${job.passphraseStoredAt}.`
        : job.passphraseStoredIn === "vault"
          ? `Recovery passphrase filed in Credentials as ${job.passphraseStoredAt}.`
          : "";
      setMsg({
        kind: "success",
        text: `Started: ${job.label}. Watch it on the Builds tab.${where ? " " + where : ""}`,
      });
      onStarted();
      onClose();
    },
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Build an image</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Stack direction="row" spacing={2}>
            <TextField select fullWidth label="Distribution" value={distro}
                       onChange={(e) => {
                         const d = e.target.value;
                         setDistro(d);
                         // The suite follows the distribution. Leaving the old one
                         // behind is a build the builder refuses, and the reason
                         // would arrive minutes later from a container.
                         setSuite(DEFAULT_SUITE[d] ?? "");
                       }}>
              <MenuItem value="debian">Debian</MenuItem>
              <MenuItem value="ubuntu">Ubuntu</MenuItem>
              <MenuItem value="almalinux">AlmaLinux</MenuItem>
              <MenuItem value="rocky">Rocky Linux</MenuItem>
            </TextField>
            {distroFamily(distro) === "rpm" ? (
              <TextField select fullWidth label="Release" value={suite}
                         onChange={(e) => setSuite(e.target.value)}
                         helperText="Major version — this family has no codenames">
                {RPM_SUITES.map((v) => <MenuItem key={v} value={v}>{v}</MenuItem>)}
              </TextField>
            ) : (
              <TextField fullWidth label="Suite" value={suite}
                         onChange={(e) => setSuite(e.target.value)}
                         placeholder={DEFAULT_SUITE[distro] ?? "trixie"}
                         helperText="Codename, e.g. trixie or noble" />
            )}
            <TextField select fullWidth label="Architecture" value={arch}
                       onChange={(e) => setArch(e.target.value)}
                       helperText="Built natively, not emulated">
              <MenuItem value="amd64">amd64</MenuItem>
              <MenuItem value="arm64">arm64</MenuItem>
            </TextField>
          </Stack>
          <TextField
            fullWidth size="small" label="Image name (optional)" value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={`${distro}-${suite}-${arch}-ab`}
            InputProps={{ style: { fontFamily: "monospace" } }}
            helperText="Left empty, a free name is chosen so a rebuild cannot overwrite an existing image — and with it the recovery passphrase filed under that name."
          />
          {distroFamily(distro) === "rpm" && (
            <Alert severity="info">
              RPM images are newly supported and <strong>have not been booted on real
              hardware yet</strong>. RAUC has no package on this family, so it is built
              from source inside the image, and the A/B root runs from dracut modules
              rather than initramfs-tools. Both ways that can be wrong are recoverable
              and loud — a passphrase prompt at boot, or a read-only root — rather than
              a machine that will not start.
            </Alert>
          )}
          <Stack direction="row" spacing={2}>
            <TextField fullWidth label="Hostname" value={hostname}
                       onChange={(e) => setHostname(e.target.value)}
                       placeholder={`${distro}-ab`}
                       helperText="Overridden per machine by a PXE assignment" />
            <TextField fullWidth label="Login user" value={username}
                       onChange={(e) => setUsername(e.target.value)} />
            <TextField fullWidth type="password" label="Password" value={password}
                       onChange={(e) => setPassword(e.target.value)}
                       helperText="Sent in the build environment, never on a command line" />
          </Stack>
          <Stack direction="row" spacing={2}>
            <TextField select fullWidth label="Profile" value={profile}
                       onChange={(e) => setProfile(e.target.value)}>
              <MenuItem value="minimal">minimal</MenuItem>
              <MenuItem value="server">server</MenuItem>
              <MenuItem value="desktop">desktop</MenuItem>
            </TextField>
            {profile === "desktop" && (
              <TextField select fullWidth label="Desktop" value={desktop}
                         onChange={(e) => setDesktop(e.target.value)}
                         helperText={distroFamily(distro) === "rpm"
                           ? "Installed as a group"
                           : "Installed as a task- metapackage"}>
                {(distroFamily(distro) === "rpm"
                  ? ["gnome", "kde", "xfce"]
                  : ["gnome", "kde", "xfce", "mate", "cinnamon", "lxqt"]
                ).map((d) => <MenuItem key={d} value={d}>{d}</MenuItem>)}
              </TextField>
            )}
            <TextField select fullWidth label="Secure Boot" value={secureBoot}
                       onChange={(e) => setSecureBoot(e.target.value)}
                       helperText="auto: on where the distribution's signed chain is available">
              <MenuItem value="auto">auto</MenuItem>
              <MenuItem value="on">require</MenuItem>
              <MenuItem value="off">off</MenuItem>
            </TextField>
          </Stack>
          <TextField fullWidth label="Extra packages" value={packages}
                     onChange={(e) => setPackages(e.target.value)}
                     placeholder="curl vim tmux" helperText="Space-separated" />
          <TextField fullWidth label="SSH authorized key" value={sshKey}
                     onChange={(e) => setSshKey(e.target.value)}
                     placeholder="ssh-ed25519 AAAA…"
                     helperText="For reaching the machine before it is enrolled" />
          <FormControlLabel
            control={<Switch checked={encrypt} onChange={(e) => setEncrypt(e.target.checked)} />}
            label="Encrypt the root filesystem (LUKS)" />
          {encrypt && (
            <>
              {/* What unlocks the disk unattended. This decides what else is
                  enrolled as a LUKS keyslot besides the passphrase — it does not
                  decide whether the passphrase is stored on this server. That is
                  the toggle further down, and the two together are what make a
                  laptop build different from a server one. */}
              <TextField select fullWidth size="small" label="Unlock method" value={unlock}
                         onChange={(e) => setUnlock(e.target.value as typeof unlock)}
                         helperText={UNLOCK_HELP[unlock]}>
                <MenuItem value="keyfile">Keyfile in the initramfs (default)</MenuItem>
                <MenuItem value="tpm2">TPM2 — sealed to the machine</MenuItem>
                <MenuItem value="tang">Tang — released by a network server</MenuItem>
                <MenuItem value="passphrase">Passphrase at every boot</MenuItem>
              </TextField>
              {unlock === "tang" && (
                <TextField fullWidth size="small" label="Tang server URL" value={tangUrl}
                           onChange={(e) => setTangUrl(e.target.value)}
                           placeholder="http://tang.example.lan"
                           helperText="Required for Tang. The machine must reach this at every boot; the root filesystem is mounted _netdev so networking comes up first." />
              )}
              {unlock === "keyfile" && (
                <Alert severity="info">
                  The key lives in the initramfs, which is <strong>not</strong> encrypted.
                  This protects the disk at rest — a drive pulled out of the machine — not
                  the machine itself in someone else's hands. TPM2 binds the key to this
                  machine instead.
                </Alert>
              )}
              {unlock === "passphrase" && (
                <Alert severity="warning">
                  Every boot stops for a typed passphrase, so the machine cannot reboot
                  unattended — including after an A/B update. Fine for a workstation,
                  usually wrong for a server.
                </Alert>
              )}
              <FormControlLabel
                control={<Switch checked={genPass} onChange={(e) => setGenPass(e.target.checked)} />}
                label="Generate the recovery passphrase and store it" />
              {genPass ? (
                <Alert severity="info">
                  A 256-bit passphrase is generated and filed <strong>before</strong> the
                  build starts — in your external secrets manager if one is connected,
                  otherwise in Credentials under <code>imaging/</code>. If it cannot be
                  stored the build does not run: an encrypted image whose recovery key was
                  never saved looks exactly like a success.
                </Alert>
              ) : (
                <>
                  <TextField fullWidth type="password" label="LUKS passphrase" value={luks}
                             onChange={(e) => setLuks(e.target.value)}
                             helperText="Enrolled as a LUKS keyslot so it always opens the disk. Travels in the environment, not on a command line." />
                  {/* The off state is a security property, not the absence of a
                      feature, and it has to say so. Read as "we did not bother to
                      store it" this looks like a gap; read correctly it is the
                      only configuration where compromising this server does not
                      also hand over the disks. */}
                  <Alert severity="warning">
                    <strong>This passphrase is not stored anywhere on this server.</strong> Not
                    in Credentials, not in a connected secrets manager, not in the audit log.
                    It is handed to the builder and forgotten.
                    {unlock === "passphrase" ? (
                      <> With <em>Passphrase at every boot</em> above, that is the whole
                        point: the machine holds no key, and neither does this server, so
                        a stolen laptop and a compromised control plane are each useless
                        on their own. Someone has to type this.</>
                    ) : (
                      <> Note that the unlock method above still puts a key on the
                        machine, so this alone does not make a stolen machine safe —
                        pair it with <em>Passphrase at every boot</em> for that.</>
                    )}
                    {" "}Keep it somewhere you will still have it when a machine will not
                    boot, because nothing here can recover it for you.
                  </Alert>
                </>
              )}
            </>
          )}
          <Divider />
          <Button size="small" sx={{ alignSelf: "flex-start" }}
                  onClick={() => setAdvanced((a) => !a)}>
            {advanced ? "Hide" : "Show"} storage, writable state and customization
          </Button>

          {advanced && (
            <Stack spacing={3} sx={{ pl: 1, borderLeft: 2, borderColor: "divider" }}>
              <Stack spacing={2}>
                <Typography variant="subtitle2">Storage</Typography>
                <Stack direction="row" spacing={2}>
                  <TextField
                    fullWidth size="small" label="Image size (GiB)" value={imageSize}
                    onChange={(e) => setImageSize(e.target.value)} placeholder="auto"
                    helperText="Empty = sized to fit. The overlay expands to fill the disk on first boot regardless."
                  />
                  <TextField
                    fullWidth size="small" label="Root slot size (MiB)" value={rootSize}
                    onChange={(e) => setRootSize(e.target.value)} placeholder="auto"
                    helperText="Each of the two slots. Too small and the build dies part-way through installing packages."
                  />
                  <TextField
                    select fullWidth size="small" label="Compression" value={compress}
                    onChange={(e) => setCompress(e.target.value)}
                    helperText="Of the finished image, for storage and transfer"
                  >
                    <MenuItem value="zstd">zstd</MenuItem>
                    <MenuItem value="gzip">gzip</MenuItem>
                    <MenuItem value="none">none</MenuItem>
                  </TextField>
                </Stack>
              </Stack>

              <WritableState value={wstate} onChange={setWstate} />

              <Stack spacing={2}>
                <Typography variant="subtitle2">Customization</Typography>
                <FormControlLabel
                  control={<Switch checked={sshKeyOnly}
                                   onChange={(e) => setSshKeyOnly(e.target.checked)} />}
                  label="SSH by key only — disable password authentication"
                />
                {sshKeyOnly && !sshKey.trim() && (
                  <Alert severity="warning">
                    Key-only with no key is a machine nobody can log into. The builder
                    refuses this combination.
                  </Alert>
                )}
                <TextField
                  fullWidth multiline minRows={4} size="small"
                  label="Customization script" value={runScript}
                  onChange={(e) => setRunScript(e.target.value)}
                  placeholder={"#!/bin/sh\n# runs in the image's chroot, after packages"}
                  InputProps={{ style: { fontFamily: "monospace", fontSize: 13 } }}
                  helperText="Runs inside the image near the end of the build. A non-zero exit fails the build."
                />
              </Stack>
            </Stack>
          )}

          <Typography variant="caption" color="text.secondary">
            The build runs in a privileged container in the builder-runner sidecar and takes
            tens of minutes. One image build runs at a time: two share the output directory,
            and the failure is not a clean error but two loop devices and a half-written file.
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions>
        {badPaths.length > 0 && (
          <Typography variant="caption" color="error" sx={{ flexGrow: 1, pl: 1 }}>
            Writable-state paths must be absolute: {badPaths.join(", ")}
          </Typography>
        )}
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained"
                disabled={start.isPending || badPaths.length > 0 || (sshKeyOnly && !sshKey.trim())}
                onClick={() => start.mutate()}>Build</Button>
      </DialogActions>
    </Dialog>
  );
}

/**
 * BuildBundleDialog: package a built image as a signed update.
 *
 * The version matters more than it looks. A rollout tells a machine that
 * installed the bundle from one that did not by comparing versions, so a bundle
 * without one produces a rollout that can never finish — which is why creating
 * such a rollout is refused rather than left running for ever.
 */
function BuildBundleDialog({ open, images, onClose, onStarted, setMsg }: {
  open: boolean; images: Image[]; onClose: () => void; onStarted: () => void;
  setMsg: (m: Note) => void;
}) {
  const [image, setImage] = useState("");
  const [version, setVersion] = useState("");
  const [description, setDescription] = useState("");
  const [luks, setLuks] = useState("");
  const chosen = images.find((i) => i.name === image);

  const start = useMutation({
    mutationFn: () => startBuild("bundle", {
      image, version: version.trim(), description: description.trim(),
      encrypted: !!chosen?.encrypted, luksPassphrase: chosen?.encrypted ? luks : "",
    }),
    onSuccess: (job) => {
      setMsg({ kind: "success", text: `Started: ${job.label}. Watch it on the Builds tab.` });
      onStarted();
      onClose();
    },
    onError: (e) => setMsg({ kind: "error", text: apiError(e) }),
  });

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Build an update bundle</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <TextField select fullWidth label="Image" value={image}
                     onChange={(e) => setImage(e.target.value)}>
            {images.map((i) => (
              <MenuItem key={i.name} value={i.name}>
                {i.name}{i.version ? ` — ${i.version}` : ""}
              </MenuItem>
            ))}
          </TextField>
          <TextField fullWidth label="Version" value={version}
                     onChange={(e) => setVersion(e.target.value)} placeholder="1.4.0"
                     helperText="How a rollout tells an updated machine from one still waiting. A bundle without one cannot be rolled out." />
          <TextField fullWidth label="Description" value={description}
                     onChange={(e) => setDescription(e.target.value)}
                     placeholder="What changed" />
          {chosen?.encrypted && (
            <TextField fullWidth type="password" label="LUKS passphrase" value={luks}
                       onChange={(e) => setLuks(e.target.value)}
                       helperText="Needed to open the encrypted image and read the root slot out of it." />
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={!image || !version.trim() || start.isPending}
                onClick={() => start.mutate()}>Build</Button>
      </DialogActions>
    </Dialog>
  );
}

export default ImagingPage;
