import { useState } from "react";
import {
  Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle,
  Divider, MenuItem, Stack, TextField, Typography,
} from "@mui/material";
import { useMutation } from "@tanstack/react-query";
import { createRollout, type ImageUpdate, type RolloutImage } from "../api/containerUpdates";

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

// `update` is a single image; `updates` is "everything with something
// available". One dialog for both, because the pacing choices are identical and
// the only difference is how many images the rollout covers.
export function StartRolloutDialog({
  update, updates, onClose, onStarted,
}: {
  update: ImageUpdate | null;
  updates?: ImageUpdate[] | null;
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
  const many = updates ?? null;
  const toTag = update?.latestTag || update?.tag || "";
  const isRebuild = !!update && toTag === update.tag;

  // No targetDigest. The server resolves what the TARGET tag points at.
  //
  // This used to send u.digest, which is what the FROM tag points at — the same
  // thing for a rebuild, and the OLD image's digest for a version bump. A
  // correctly updated container was then compared against the bytes it had just
  // moved away from, and the rollout failed itself after succeeding.
  const imageOf = (u: ImageUpdate): RolloutImage => ({
    repository: u.repository,
    fromTag: u.tag,
    toTag: u.latestTag || u.tag,
  });
  const images = many ? many.map(imageOf) : [];

  const start = useMutation({
    mutationFn: () => createRollout({
      ...(many
        ? { images }
        : {
            repository: update!.repository,
            fromTag: update!.tag,
            toTag,
          }),
      canary, batchSize, soakSeconds, maxFailures,
      ...(windowStart && windowEnd ? { windowStart, windowEnd } : {}),
    }),
    onSuccess: () => {
      onStarted(many
        ? `Rolling out ${images.length} image${images.length === 1 ? "" : "s"}`
        : `Rolling out ${update!.repository}:${toTag}`);
      onClose();
    },
    onError: (e) => setErr(errMsg(e, "Could not start the rollout.")),
  });

  // ?? not ?. — the server sends null, not [], for an image no host runs, and
  // update?.hosts.length throws on it just as surely as update.hosts.length does.
  const hostCount = many
    ? new Set(many.flatMap((u) => (u.hosts ?? []).map((h) => h.hostId))).size
    : update?.hosts?.length ?? 0;

  return (
    <Dialog open={update !== null || (many?.length ?? 0) > 0} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        {many ? `Roll out ${images.length} update${images.length === 1 ? "" : "s"}` : `Roll out ${update?.repository}`}
      </DialogTitle>
      <DialogContent>
        {err && <Alert severity="error" sx={{ mb: 2 }}>{err}</Alert>}

        <Typography variant="body2" sx={{ mb: 1 }}>
          {many ? (
            <>
              Applying <strong>{images.length}</strong> update
              {images.length === 1 ? "" : "s"} across {hostCount} host
              {hostCount === 1 ? "" : "s"}. Each host takes every update that applies
              to it before the next host starts — so a host is either current or it
              is not, rather than half-updated across the fleet.
            </>
          ) : isRebuild ? (
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

        {many && images.length > 0 && (
          <Box sx={{ maxHeight: 140, overflow: "auto", border: 1, borderColor: "divider",
                     borderRadius: 1, p: 1, mb: 2 }}>
            {images.map((im) => (
              <Typography key={`${im.repository}:${im.fromTag}`} variant="caption"
                          sx={{ display: "block", fontFamily: "monospace" }}>
                {im.repository}:{im.fromTag}
                {im.toTag !== im.fromTag ? ` → ${im.toTag}` : " (rebuild)"}
              </Typography>
            ))}
          </Box>
        )}

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
        <Button variant="contained" disabled={start.isPending || (!update && !many?.length)}
                onClick={() => { setErr(""); start.mutate(); }}>
          Start rollout
        </Button>
      </DialogActions>
    </Dialog>
  );
}
