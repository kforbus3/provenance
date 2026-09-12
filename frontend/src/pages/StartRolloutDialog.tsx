import { useState } from "react";
import {
  Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle,
  Divider, MenuItem, Stack, TextField, Typography,
} from "@mui/material";
import { useMutation } from "@tanstack/react-query";
import { createRollout, type ImageUpdate } from "../api/containerUpdates";

// Starting a staged rollout of one image update.
//
// The defaults are cautious rather than fast: one host first, a fifteen-minute
// soak, and a halt on the first failure. The cost of being slow is waiting; the
// cost of being fast is every host on a broken image at the same moment.

const errMsg = (e: unknown, fallback: string) =>
  (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? fallback;

const SOAKS = [
  { label: "none", value: 0 },
  { label: "5 minutes", value: 300 },
  { label: "15 minutes", value: 900 },
  { label: "1 hour", value: 3600 },
  { label: "4 hours", value: 14400 },
];

export function StartRolloutDialog({
  update, onClose, onStarted,
}: {
  update: ImageUpdate | null;
  onClose: () => void;
  onStarted: (msg: string) => void;
}) {
  const [canary, setCanary] = useState(1);
  const [batchSize, setBatchSize] = useState(5);
  const [soakSeconds, setSoakSeconds] = useState(900);
  const [maxFailures, setMaxFailures] = useState(1);
  const [windowStart, setWindowStart] = useState("");
  const [windowEnd, setWindowEnd] = useState("");
  const [err, setErr] = useState("");

  // The target: a newer tag when one was found, otherwise the same tag whose
  // digest moved. Both are real updates — the second is a rebuild of the same
  // version, where pulling IS the whole update.
  const toTag = update?.latestTag || update?.tag || "";
  const isRebuild = !!update && toTag === update.tag;

  const start = useMutation({
    mutationFn: () => createRollout({
      repository: update!.repository,
      fromTag: update!.tag,
      toTag,
      targetDigest: update!.digest,
      canary, batchSize, soakSeconds, maxFailures,
      ...(windowStart && windowEnd ? { windowStart, windowEnd } : {}),
    }),
    onSuccess: () => {
      onStarted(`Rolling out ${update!.repository}:${toTag}`);
      onClose();
    },
    onError: (e) => setErr(errMsg(e, "Could not start the rollout.")),
  });

  // ?? not ?. — the server sends null, not [], for an image no host runs, and
  // update?.hosts.length throws on it just as surely as update.hosts.length does.
  const hostCount = update?.hosts?.length ?? 0;

  return (
    <Dialog open={update !== null} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Roll out {update?.repository}</DialogTitle>
      <DialogContent>
        {err && <Alert severity="error" sx={{ mb: 2 }}>{err}</Alert>}

        <Typography variant="body2" sx={{ mb: 1 }}>
          {isRebuild ? (
            <>
              <strong>{update?.repository}:{update?.tag}</strong> has been rebuilt — the
              tag points at different bytes than these hosts are running. The version
              number does not change; the pull is the update.
            </>
          ) : (
            <>
              Moving <strong>{update?.repository}:{update?.tag}</strong> to{" "}
              <strong>{toTag}</strong> on {hostCount} host{hostCount === 1 ? "" : "s"}.
            </>
          )}
        </Typography>

        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 2 }}>
          Only hosts whose compose file Provenance manages can be updated this way.
          A host running this image outside a managed stack is reported rather than
          guessed at — adopt its compose file first.
        </Typography>

        <Divider sx={{ mb: 2 }} />

        <Stack spacing={2}>
          <TextField
            label="Canary hosts" type="number" size="small" value={canary}
            onChange={(e) => setCanary(Math.max(0, Number(e.target.value)))}
            helperText="Proved first, alone. The rest waits on them."
          />
          <TextField
            select label="Soak" size="small" value={soakSeconds}
            onChange={(e) => setSoakSeconds(Number(e.target.value))}
            helperText="How long the canaries must run before the fleet follows."
          >
            {SOAKS.map((s) => <MenuItem key={s.value} value={s.value}>{s.label}</MenuItem>)}
          </TextField>
          <TextField
            label="Batch size" type="number" size="small" value={batchSize}
            onChange={(e) => setBatchSize(Math.max(1, Number(e.target.value)))}
            helperText="How many hosts move at once after the soak."
          />
          <TextField
            label="Stop after this many failures" type="number" size="small" value={maxFailures}
            onChange={(e) => setMaxFailures(Math.max(0, Number(e.target.value)))}
            helperText="0 means no limit — the rollout continues past every failure."
          />
          <Box>
            <Typography variant="body2" sx={{ mb: 1 }}>
              Maintenance window (optional, server local time)
            </Typography>
            <Stack direction="row" spacing={1}>
              <TextField label="From" size="small" placeholder="22:00"
                         value={windowStart} onChange={(e) => setWindowStart(e.target.value)} />
              <TextField label="To" size="small" placeholder="04:00"
                         value={windowEnd} onChange={(e) => setWindowEnd(e.target.value)} />
            </Stack>
          </Box>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={start.isPending || !update}
                onClick={() => { setErr(""); start.mutate(); }}>
          Start rollout
        </Button>
      </DialogActions>
    </Dialog>
  );
}
