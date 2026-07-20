import { useEffect, useState } from "react";
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogContentText,
  DialogTitle, Divider, FormControlLabel, MenuItem, Paper, Stack, Switch, Table, TableBody,
  TableCell, TableHead, TableRow, TextField, Typography,
} from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getDRStatus, setDRConfig, drFailover, drFailback,
  type DRConfig, type DRActionResult,
} from "../api/dr";

const ROLE_COLOR: Record<string, "default" | "success" | "warning"> = {
  standalone: "default", primary: "success", standby: "warning",
};

export function DisasterRecoveryPage() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["dr-status"], queryFn: getDRStatus, refetchInterval: 10000 });

  if (isLoading || !data) {
    return <Box><Typography variant="h5" sx={{ mb: 2 }}>Disaster Recovery</Typography><Typography color="text.secondary">Loading…</Typography></Box>;
  }

  const { config, replication, peer } = data;
  // A single-instance primary has no downstream standbys, so the backend returns
  // replicas: null — normalize to an array so the render can't crash on .length/.map.
  const replicas = replication.replicas ?? [];
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["dr-status"] });

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 1 }}>Disaster Recovery</Typography>
      <Alert severity="info" sx={{ mb: 2 }}>
        Warm-standby DR across two independent instances. Fleet reflects replication state and
        triggers your orchestration — it does <b>not</b> replicate the database or move DNS itself.
        The failover/failback buttons optionally promote this instance's PostgreSQL and POST to the
        webhook you wire to your promotion / DNS / WireGuard-endpoint automation. See the
        Disaster Recovery runbook (docs/disaster-recovery.md) for the full procedure.
      </Alert>

      <Stack direction={{ xs: "column", md: "row" }} spacing={2} sx={{ mb: 3 }}>
        <Paper variant="outlined" sx={{ p: 2, flex: 1 }}>
          <Typography variant="overline" color="text.secondary">This instance</Typography>
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 0.5 }}>
            <Typography variant="body2">Configured role:</Typography>
            <Chip size="small" label={config.role} color={ROLE_COLOR[config.role] ?? "default"} />
          </Stack>
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 1 }}>
            <Typography variant="body2">Database:</Typography>
            <Chip
              size="small"
              label={replication.inRecovery ? "standby (in recovery)" : "primary (writable)"}
              color={replication.inRecovery ? "warning" : "success"}
            />
          </Stack>
          {replication.inRecovery && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              Replay lag: {replication.replayLagSeconds != null ? `${replication.replayLagSeconds.toFixed(1)}s behind primary` : "unknown"}
            </Typography>
          )}
        </Paper>

        <Paper variant="outlined" sx={{ p: 2, flex: 1 }}>
          <Typography variant="overline" color="text.secondary">Peer instance</Typography>
          {peer.configured ? (
            <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 0.5 }}>
              <Chip size="small" label={peer.reachable ? "reachable" : "unreachable"} color={peer.reachable ? "success" : "error"} />
              <Typography variant="body2" color="text.secondary">{peer.detail}</Typography>
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>No peer URL configured.</Typography>
          )}
        </Paper>
      </Stack>

      {!replication.inRecovery && replicas.length > 0 && (
        <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
          <Typography variant="overline" color="text.secondary">Connected standbys</Typography>
          <Table size="small" sx={{ mt: 0.5 }}>
            <TableHead><TableRow>
              <TableCell>Client</TableCell><TableCell>State</TableCell><TableCell>Sync</TableCell><TableCell>Lag (bytes)</TableCell>
            </TableRow></TableHead>
            <TableBody>
              {replicas.map((r, i) => (
                <TableRow key={i}>
                  <TableCell>{r.clientAddr || "—"}</TableCell>
                  <TableCell>{r.state}</TableCell>
                  <TableCell>{r.syncState}</TableCell>
                  <TableCell>{r.lagBytes ?? "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}

      <ActionsCard replication={replication} onDone={invalidate} />
      <ConfigCard config={config} onSaved={invalidate} />
    </Box>
  );
}

function ActionsCard({ replication, onDone }: { replication: { inRecovery: boolean }; onDone: () => void }) {
  const [confirm, setConfirm] = useState<null | "failover" | "failback">(null);
  const [promoteDb, setPromoteDb] = useState(replication.inRecovery);
  const [result, setResult] = useState<DRActionResult | null>(null);

  const act = useMutation({
    mutationFn: ({ kind, promote }: { kind: "failover" | "failback"; promote: boolean }) =>
      kind === "failover" ? drFailover(promote) : drFailback(promote),
    onSuccess: (r) => { setResult(r); setConfirm(null); onDone(); },
    onError: (e: unknown) => {
      setResult({ ok: false, steps: [{ step: "request", ok: false, error: (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "failed" }] });
      setConfirm(null);
    },
  });

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Failover / Failback</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Run from the instance that is <b>taking over</b>. Enable “promote this database” when this
        instance is the standby stepping up. The configured webhook fires alongside, for DNS and
        jump-host WireGuard failover.
      </Typography>
      <FormControlLabel
        control={<Switch checked={promoteDb} onChange={(e) => setPromoteDb(e.target.checked)} />}
        label="Also promote this instance's database (pg_promote)"
      />
      <Stack direction="row" spacing={2} sx={{ mt: 1 }}>
        <Button variant="contained" color="warning" onClick={() => setConfirm("failover")}>Force failover</Button>
        <Button variant="outlined" onClick={() => setConfirm("failback")}>Force failback</Button>
      </Stack>

      {result && (
        <Alert severity={result.ok ? "success" : "error"} sx={{ mt: 2 }} onClose={() => setResult(null)}>
          {result.steps.map((s, i) => (
            <div key={i}>
              {s.step}: {s.ok ? "ok" : "FAILED"}{s.error ? ` — ${s.error}` : ""}{s.skipped ? ` — ${s.skipped}` : ""}
            </div>
          ))}
        </Alert>
      )}

      <Dialog open={confirm !== null} onClose={() => setConfirm(null)}>
        <DialogTitle>Confirm {confirm}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            This will {promoteDb ? "promote this instance's database to primary and " : ""}fire the
            configured {confirm} webhook. This hands the writable role between sites — make sure the
            other instance is not also writable. Continue?
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirm(null)}>Cancel</Button>
          <Button
            color="warning" variant="contained" disabled={act.isPending}
            onClick={() => confirm && act.mutate({ kind: confirm, promote: promoteDb })}
          >
            {act.isPending ? "Working…" : `Confirm ${confirm}`}
          </Button>
        </DialogActions>
      </Dialog>
    </Paper>
  );
}

function ConfigCard({ config, onSaved }: { config: DRConfig; onSaved: () => void }) {
  const [form, setForm] = useState<DRConfig>(config);
  const [saved, setSaved] = useState(false);
  useEffect(() => { setForm(config); }, [config]);
  const set = <K extends keyof DRConfig>(k: K, v: DRConfig[K]) => { setForm((f) => ({ ...f, [k]: v })); setSaved(false); };

  const save = useMutation({
    mutationFn: () => setDRConfig(form),
    onSuccess: () => { setSaved(true); onSaved(); },
  });

  return (
    <Paper variant="outlined" sx={{ p: 2 }}>
      <Typography variant="h6">Configuration</Typography>
      <Divider sx={{ my: 1.5 }} />
      <Stack spacing={2} sx={{ maxWidth: 640 }}>
        <TextField select label="Role (label for this instance)" size="small" value={form.role}
          onChange={(e) => set("role", e.target.value as DRConfig["role"])}>
          <MenuItem value="standalone">Standalone (no DR)</MenuItem>
          <MenuItem value="primary">Primary (active writer)</MenuItem>
          <MenuItem value="standby">Standby (warm replica)</MenuItem>
        </TextField>
        <TextField label="Peer instance URL (for health only)" size="small" value={form.peerUrl}
          onChange={(e) => set("peerUrl", e.target.value)} placeholder="https://the-other-site.example.com" />
        <TextField label="Failover webhook (POSTed on Force failover)" size="small" value={form.failoverWebhook}
          onChange={(e) => set("failoverWebhook", e.target.value)}
          helperText="Wire to your promotion / DNS repoint / standby jump-host WireGuard bring-up" />
        <TextField label="Failback webhook (POSTed on Force failback)" size="small" value={form.failbackWebhook}
          onChange={(e) => set("failbackWebhook", e.target.value)} />
        <Box>
          <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>
            {saved ? "Saved" : "Save"}
          </Button>
        </Box>
      </Stack>
    </Paper>
  );
}
