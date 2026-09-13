import { useState } from "react";
import {
  Alert, Box, Button, Chip, Collapse, IconButton, LinearProgress, Paper, Snackbar,
  Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Tooltip,
  Typography,
} from "@mui/material";
import DeleteSweepIcon from "@mui/icons-material/DeleteSweep";
import PauseIcon from "@mui/icons-material/Pause";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import StopIcon from "@mui/icons-material/Stop";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listRollouts, clearFinishedRollouts, getRollout, rolloutAction, type UpdateRollout,
} from "../api/containerUpdates";
import { formatDateTime } from "../lib/datetime";
import { useAuthStore } from "../store/auth";

// Staged rollouts of container image updates.
//
// A rollout is paced by the same rules image rollouts obey: canary first, a soak
// before the fleet follows, a batch size, and a failure budget that halts it.
// Progress is per host, because mid-rollout some hosts have the new bytes and
// some do not — and that distinction is the whole reason to stage it.

const errMsg = (e: unknown, fallback: string) =>
  (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? fallback;

function StateChip({ r }: { r: UpdateRollout }) {
  const failed = r.counts?.failed ?? 0;
  switch (r.state) {
    case "running":
      return <Chip label="running" size="small" color="info" />;
    case "halted":
      return (
        <Tooltip title={r.haltReason || "stopped on its failure budget"}>
          <Chip label="halted" size="small" color="error" />
        </Tooltip>
      );
    case "paused":
      return <Chip label="paused" size="small" color="warning" variant="outlined" />;
    case "completed":
      // A rollout with an unlimited failure budget reaches "completed" even when
      // every host failed. That IS the state it is in, and a green tick next to
      // it would be the wrong thing to show — so the chip carries the failures.
      if (failed > 0) {
        return (
          <Tooltip title="The rollout ran to the end; these hosts did not take the update.">
            <Chip label={`completed · ${failed} failed`} size="small" color="warning" />
          </Tooltip>
        );
      }
      return <Chip label="completed" size="small" color="success" variant="outlined" />;
    default:
      return <Chip label={r.state} size="small" variant="outlined" />;
  }
}

// progressLabel summarises a rollout from the counts the list already carries,
// so a collapsed row says how far it got without fetching every host.
function progressLabel(r: UpdateRollout): string {
  const c = r.counts ?? {};
  const total = Object.values(c).reduce((a, b) => a + b, 0);
  if (total === 0) return "";
  const parts = [`${c.verified ?? 0} of ${total} verified`];
  if (c.failed) parts.push(`${c.failed} failed`);
  if (c.applying) parts.push(`${c.applying} in progress`);
  return parts.join(", ");
}

function HostState({ state }: { state: string }) {
  const color =
    state === "verified" ? "success" :
    state === "failed" ? "error" :
    state === "applying" ? "info" : "default";
  return <Chip label={state} size="small" color={color as never} variant="outlined" />;
}

function RolloutRow({ r, canRun, onMessage }: {
  r: UpdateRollout; canRun: boolean; onMessage: (m: string) => void;
}) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);

  // Hosts are only fetched when the row is expanded. A fleet-wide rollout has as
  // many rows as hosts, and loading all of them for a collapsed list would make
  // the page slower the more there is to look at.
  const { data: detail } = useQuery({
    queryKey: ["rollout", r.id],
    queryFn: () => getRollout(r.id),
    enabled: open,
    refetchInterval: open && r.state === "running" ? 10000 : false,
  });

  const act = useMutation({
    mutationFn: (a: "pause" | "resume" | "cancel") => rolloutAction(r.id, a),
    onSuccess: (res) => {
      onMessage(`Rollout ${res.state}`);
      qc.invalidateQueries({ queryKey: ["rollouts"] });
      qc.invalidateQueries({ queryKey: ["rollout", r.id] });
    },
    onError: (e) => onMessage(errMsg(e, "That did not work.")),
  });

  const hosts = detail?.hosts ?? [];
  const counts = detail?.counts ?? {};
  const total = hosts.length;
  const done = (counts.verified ?? 0) + (counts.failed ?? 0) + (counts.skipped ?? 0);

  return (
    <>
      <TableRow hover>
        <TableCell sx={{ width: 40 }}>
          <IconButton size="small" onClick={() => setOpen((o) => !o)}>
            {open ? <KeyboardArrowDownIcon fontSize="small" /> : <KeyboardArrowRightIcon fontSize="small" />}
          </IconButton>
        </TableCell>
        <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>
          {r.repository}:{r.fromTag}
          {r.toTag !== r.fromTag
            ? <> → {r.toTag}</>
            : <Typography component="span" variant="caption" color="text.secondary"> (rebuild)</Typography>}
          {(r.imageCount ?? 0) > 1 && (
            <Typography component="span" variant="caption" color="text.secondary">
              {" "}and {r.imageCount! - 1} more image{r.imageCount! > 2 ? "s" : ""}
            </Typography>
          )}
        </TableCell>
        <TableCell><StateChip r={r} /></TableCell>
        <TableCell>
          <Typography variant="caption" color="text.secondary">
            {r.canary} canary · {r.batchSize} at a time
            {r.soakSeconds > 0 && ` · ${Math.round(r.soakSeconds / 60)}m soak`}
            {r.maxFailures > 0 ? ` · stop after ${r.maxFailures}` : " · no failure limit"}
          </Typography>
        </TableCell>
        <TableCell>
          <Typography variant="caption" color="text.secondary">
            {progressLabel(r) || "—"}
          </Typography>
        </TableCell>
        <TableCell>{formatDateTime(r.createdAt)}</TableCell>
        <TableCell align="right">
          {canRun && r.state === "running" && (
            <Tooltip title="Stop starting new hosts">
              <IconButton size="small" onClick={() => act.mutate("pause")}>
                <PauseIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
          {canRun && (r.state === "paused" || r.state === "halted") && (
            <Tooltip title={r.state === "halted"
              ? "Forgive the failures that stopped it and carry on with the rest"
              : "Carry on"}>
              <IconButton size="small" onClick={() => act.mutate("resume")}>
                <PlayArrowIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
          {canRun && r.state !== "completed" && r.state !== "cancelled" && (
            <Tooltip title="Stop for good — hosts already updated stay updated">
              <IconButton size="small" color="error" onClick={() => act.mutate("cancel")}>
                <StopIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
        </TableCell>
      </TableRow>
      <TableRow>
        <TableCell sx={{ py: 0, borderBottom: open ? undefined : "none" }} colSpan={7}>
          <Collapse in={open} unmountOnExit>
            <Box sx={{ py: 1.5, pl: 5 }}>
              {r.haltReason && <Alert severity="error" sx={{ mb: 1.5 }}>{r.haltReason}</Alert>}
              {total > 0 && (
                <Box sx={{ mb: 1.5, maxWidth: 420 }}>
                  <LinearProgress variant="determinate"
                                  value={Math.round((done / total) * 100)} />
                  <Typography variant="caption" color="text.secondary">
                    {counts.verified ?? 0} verified
                    {counts.failed ? `, ${counts.failed} failed` : ""}
                    {counts.applying ? `, ${counts.applying} in progress` : ""}
                    {counts.pending ? `, ${counts.pending} waiting` : ""}
                    {" "}of {total}
                  </Typography>
                </Box>
              )}
              {hosts.map((h) => (
                <Stack key={h.hostId} direction="row" spacing={1} alignItems="center"
                       sx={{ mb: 0.5 }}>
                  <Typography variant="body2" sx={{ minWidth: 160 }}>
                    {h.hostname || h.hostId.slice(0, 8)}
                  </Typography>
                  <HostState state={h.state} />
                  {h.error && (
                    <Typography variant="caption" color="error"
                                sx={{ flex: 1, wordBreak: "break-word" }}>
                      {h.error}
                    </Typography>
                  )}
                </Stack>
              ))}
              {open && hosts.length === 0 && (
                <Typography variant="body2" color="text.secondary">Loading hosts…</Typography>
              )}
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
}

export function RolloutsTab() {
  const canRun = useAuthStore((s) => s.has("Command.Run"));
  const [snack, setSnack] = useState("");
  const qc = useQueryClient();

  const { data: rollouts = [], isLoading } = useQuery({
    queryKey: ["rollouts"],
    queryFn: listRollouts,
    // A running rollout changes on its own, so the list refreshes without the
    // operator having to guess when to press reload.
    refetchInterval: 15000,
  });

  const running = rollouts.filter((r) => r.state === "running").length;
  const halted = rollouts.filter((r) => r.state === "halted").length;

  // A rollout that is over is history, not state. Leaving every one of them on
  // the page for ever buries the one that is actually running — an evening of
  // one-image rollouts puts thirty finished rows above it.
  //
  // Paused is deliberately not "finished": it looks inert and is not, because
  // resume is a button somebody may still be intending to press.
  const FINISHED = ["completed", "cancelled", "halted"];
  const finished = rollouts.filter((r) => FINISHED.includes(r.state));
  const clear = useMutation({
    mutationFn: clearFinishedRollouts,
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["rollouts"] });
      setSnack(`Cleared ${res.deleted} finished rollout${res.deleted === 1 ? "" : "s"}`);
    },
    onError: () => setSnack("Could not clear the finished rollouts"),
  });

  return (
    <Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Staged rollouts of container image updates — canary first, a soak before the
        fleet follows, then batches, stopping on the failure budget. A host counts as
        done only when it is running the target image, not when the deploy command
        exits.
      </Typography>

      {halted > 0 && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {halted} rollout{halted > 1 ? "s have" : " has"} stopped on its failure budget.
        </Alert>
      )}
      {running > 0 && halted === 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          {running} rollout{running > 1 ? "s are" : " is"} in progress.
        </Alert>
      )}

      {canRun && finished.length > 0 && (
        <Stack direction="row" sx={{ mb: 2 }}>
          <Button size="small" startIcon={<DeleteSweepIcon />} disabled={clear.isPending}
                  onClick={() => {
                    if (window.confirm(
                      `Clear ${finished.length} finished rollout`
                      + `${finished.length === 1 ? "" : "s"} from this list? The containers `
                      + `they updated are unaffected — this removes the history, not the state. `
                      + `Anything still running or paused is kept.`)) {
                      clear.mutate();
                    }
                  }}>
            {clear.isPending ? "Clearing…" : `Clear finished (${finished.length})`}
          </Button>
        </Stack>
      )}

      {isLoading && <Typography variant="body2">Loading…</Typography>}
      {!isLoading && rollouts.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          No rollouts yet. Start one from an available update on the Updates tab.
        </Typography>
      )}

      {rollouts.length > 0 && (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell />
                <TableCell>Image</TableCell>
                <TableCell>State</TableCell>
                <TableCell>Pacing</TableCell>
                <TableCell>Progress</TableCell>
                <TableCell>Started</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rollouts.map((r) => (
                <RolloutRow key={r.id} r={r} canRun={canRun} onMessage={setSnack} />
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Snackbar open={!!snack} autoHideDuration={6000} onClose={() => setSnack("")}
                message={snack} />
    </Box>
  );
}
