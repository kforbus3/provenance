import { useState } from "react";
import {
  Box, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle,
  FormControlLabel, IconButton, MenuItem, Paper, Stack, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, TextField, Tooltip, Typography, Alert,
} from "@mui/material";
import EditIcon from "@mui/icons-material/Edit";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listSettings, setSetting } from "../api/admin";
import { assistantModels } from "../api/assistant";
import { downloadBackup } from "../api/system";

// System settings editor. Values are arbitrary JSON; the editor exposes them as
// raw JSON text and validates before PUTting the new value.
export function SettingsPage() {
  const qc = useQueryClient();
  const { data: settings = {}, isLoading } = useQuery({ queryKey: ["settings"], queryFn: listSettings });

  const [editKey, setEditKey] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);

  const openEdit = (key: string, value: unknown) => {
    setEditKey(key);
    setDraft(JSON.stringify(value, null, 2));
    setError(null);
  };

  const saveMut = useMutation({
    mutationFn: (parsed: unknown) => setSetting(editKey as string, parsed),
    onSuccess: () => { setEditKey(null); qc.invalidateQueries({ queryKey: ["settings"] }); },
  });

  const onSave = () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(draft);
    } catch {
      setError("Value must be valid JSON");
      return;
    }
    setError(null);
    saveMut.mutate(parsed);
  };

  const entries = Object.entries(settings);

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 2 }}>System Settings</Typography>

      <BrandingCard current={settings["branding"]} />
      <AssistantCard current={settings["assistant"]} />
      <WGSettingsCard current={settings["wireguard"]} />
      <RetentionCard current={settings["recordings"]} />
      <BackupCard />

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Key</TableCell>
              <TableCell>Value</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {entries.map(([key, value]) => (
              <TableRow key={key} hover>
                <TableCell sx={{ fontFamily: "monospace" }}>{key}</TableCell>
                <TableCell sx={{ fontFamily: "monospace", whiteSpace: "pre-wrap" }}>
                  {JSON.stringify(value)}
                </TableCell>
                <TableCell align="right">
                  <Tooltip title="Edit">
                    <IconButton size="small" onClick={() => openEdit(key, value)}><EditIcon fontSize="small" /></IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {!isLoading && entries.length === 0 && (
              <TableRow><TableCell colSpan={3}>
                <Typography color="text.secondary">No settings configured.</Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={editKey !== null} onClose={() => setEditKey(null)} fullWidth maxWidth="sm">
        <DialogTitle>{editKey ? `Edit · ${editKey}` : "Edit"}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            {error && <Alert severity="error">{error}</Alert>}
            <TextField label="Value (JSON)" value={draft} multiline minRows={4}
              onChange={(e) => setDraft(e.target.value)}
              sx={{ "& textarea": { fontFamily: "monospace" } }} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditKey(null)}>Cancel</Button>
          <Button variant="contained" disabled={saveMut.isPending} onClick={onSave}>Save</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

// BrandingCard customizes the application name shown across the UI (login, top
// bar, dashboard, browser title). Stored in the `branding` setting and served
// publicly via /version. Saving invalidates the version query so the new name
// takes effect immediately without a reload.
function BrandingCard({ current }: { current: unknown }) {
  const qc = useQueryClient();
  const cur = (current ?? {}) as { app_name?: string };
  const [name, setName] = useState(cur.app_name ?? "");
  const [saved, setSaved] = useState(false);
  const save = useMutation({
    mutationFn: () => setSetting("branding", { app_name: name.trim() || "Fleet Terminal" }),
    onSuccess: () => {
      setSaved(true);
      void qc.invalidateQueries({ queryKey: ["settings"] });
      void qc.invalidateQueries({ queryKey: ["version"] });
    },
  });
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Branding</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        The application name shown on the login screen, the top bar, the dashboard, and the
        browser tab. Leave blank to restore the default.
      </Typography>
      <Stack direction="row" spacing={2} alignItems="flex-start">
        <TextField
          label="Application name" value={name}
          onChange={(e) => { setName(e.target.value); setSaved(false); }}
          placeholder="Fleet Terminal" sx={{ flexGrow: 1, maxWidth: 360 }}
        />
        <Button variant="contained" sx={{ mt: 1 }} disabled={save.isPending} onClick={() => save.mutate()}>
          {saved ? "Saved" : "Save"}
        </Button>
      </Stack>
    </Paper>
  );
}

// AssistantCard configures the local Ollama instance powering the read-only AI
// assistant: enable, endpoint URL, and model (listed live from Ollama).
function AssistantCard({ current }: { current: unknown }) {
  const qc = useQueryClient();
  const cur = (current ?? {}) as { enabled?: boolean; ollamaUrl?: string; model?: string };
  const [enabled, setEnabled] = useState(Boolean(cur.enabled));
  const [url, setUrl] = useState(cur.ollamaUrl ?? "");
  const [model, setModel] = useState(cur.model ?? "");
  const [models, setModels] = useState<string[]>(cur.model ? [cur.model] : []);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadModels = useMutation({
    mutationFn: () => assistantModels(url.trim()),
    onSuccess: (list) => { setModels(list); setError(list.length ? null : "No models found at that URL."); },
    onError: () => setError("Could not reach Ollama at that URL."),
  });

  const save = useMutation({
    mutationFn: () => setSetting("assistant", { enabled, ollamaUrl: url.trim(), model }),
    onSuccess: () => {
      setSaved(true);
      void qc.invalidateQueries({ queryKey: ["settings"] });
      void qc.invalidateQueries({ queryKey: ["assistant-status"] });
    },
  });

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">AI assistant (local Ollama)</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Point Fleet at a local Ollama instance to enable read-only natural-language queries over
        your fleet (e.g. “hosts with less than 20% disk free”). Data never leaves your network;
        queries are RBAC-scoped and audited.
      </Typography>
      {error && <Alert severity="warning" sx={{ mb: 1.5 }}>{error}</Alert>}
      <Stack spacing={2}>
        <FormControlLabel
          control={<Checkbox checked={enabled} onChange={(e) => { setEnabled(e.target.checked); setSaved(false); }} />}
          label="Enable the assistant"
        />
        <Stack direction="row" spacing={2} alignItems="flex-start">
          <TextField
            label="Ollama URL" value={url} placeholder="http://10.10.0.x:11434"
            onChange={(e) => { setUrl(e.target.value); setSaved(false); }}
            sx={{ flexGrow: 1 }} size="small"
          />
          <Button sx={{ mt: 0.5 }} disabled={!url.trim() || loadModels.isPending} onClick={() => loadModels.mutate()}>
            {loadModels.isPending ? "Loading…" : "Load models"}
          </Button>
        </Stack>
        <TextField
          select size="small" label="Model" value={model} sx={{ maxWidth: 360 }}
          onChange={(e) => { setModel(e.target.value); setSaved(false); }}
          helperText={models.length ? undefined : "Load models from the URL above, then pick one."}
        >
          {models.map((m) => <MenuItem key={m} value={m}>{m}</MenuItem>)}
        </TextField>
        <Box>
          <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>
            {saved ? "Saved" : "Save"}
          </Button>
        </Box>
      </Stack>
    </Paper>
  );
}

// WGSettingsCard configures the VPN (jump host) WireGuard endpoint that managed
// hosts dial, so it doesn't have to be entered for every enrollment.
function WGSettingsCard({ current }: { current: unknown }) {
  const qc = useQueryClient();
  const cur = (current ?? {}) as { jumpHost?: string; jumpPort?: number };
  const [jumpHost, setJumpHost] = useState(cur.jumpHost ?? "");
  const [jumpPort, setJumpPort] = useState(String(cur.jumpPort ?? 51820));
  const [saved, setSaved] = useState(false);

  const save = useMutation({
    mutationFn: () => setSetting("wireguard", { jumpHost: jumpHost.trim(), jumpPort: Number(jumpPort) || 51820 }),
    onSuccess: () => { setSaved(true); void qc.invalidateQueries({ queryKey: ["settings"] }); void qc.invalidateQueries({ queryKey: ["next-wg"] }); },
  });

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">VPN server (WireGuard)</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Public address &amp; port that managed hosts use to reach the jump host over WireGuard.
        Used as the default when enrolling hosts (overridable per host). Must be reachable from
        the hosts on UDP.
      </Typography>
      <Stack direction="row" spacing={2} alignItems="flex-start">
        <TextField
          label="Server name / IP" value={jumpHost}
          onChange={(e) => { setJumpHost(e.target.value); setSaved(false); }}
          placeholder="vpn.example.com" sx={{ flexGrow: 1 }}
        />
        <TextField
          label="Port" type="number" value={jumpPort}
          onChange={(e) => { setJumpPort(e.target.value); setSaved(false); }}
          sx={{ width: 120 }}
        />
        <Button variant="contained" sx={{ mt: 1 }} disabled={save.isPending || !jumpHost.trim()} onClick={() => save.mutate()}>
          {saved ? "Saved" : "Save"}
        </Button>
      </Stack>
    </Paper>
  );
}

// RetentionCard configures automatic deletion of old session recordings to
// reclaim disk. A background job prunes recordings older than the set days.
function RetentionCard({ current }: { current: unknown }) {
  const qc = useQueryClient();
  const cur = (current ?? {}) as { retentionDays?: number };
  const [days, setDays] = useState(String(cur.retentionDays ?? 0));
  const [saved, setSaved] = useState(false);
  const save = useMutation({
    mutationFn: () => setSetting("recordings", { retentionDays: Number(days) || 0 }),
    onSuccess: () => { setSaved(true); void qc.invalidateQueries({ queryKey: ["settings"] }); },
  });
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Session recording retention</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Automatically delete session recordings older than this many days to reclaim disk space.
        Set 0 to keep recordings indefinitely. Pruning runs in the background.
      </Typography>
      <Stack direction="row" spacing={2} alignItems="flex-start">
        <TextField
          label="Retention (days)" type="number" value={days}
          onChange={(e) => { setDays(e.target.value); setSaved(false); }}
          helperText="0 = keep forever" sx={{ width: 200 }}
        />
        <Button variant="contained" sx={{ mt: 1 }} disabled={save.isPending} onClick={() => save.mutate()}>
          {saved ? "Saved" : "Save"}
        </Button>
      </Stack>
    </Paper>
  );
}

// BackupCard downloads a logical database backup. Restore is documented as an
// out-of-band operation in the disaster-recovery guide.
function BackupCard() {
  const backupMut = useMutation({ mutationFn: downloadBackup });
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Backup &amp; Restore</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Download a full logical database backup (pg_dump). Restore is performed offline:
        <code> psql "$FLEET_DATABASE_URL" &lt; fleet-backup.sql</code> — see the disaster-recovery guide.
      </Typography>
      {backupMut.isError && <Alert severity="error" sx={{ mb: 1 }}>Backup failed.</Alert>}
      <Button variant="contained" onClick={() => backupMut.mutate()} disabled={backupMut.isPending}>
        {backupMut.isPending ? "Preparing…" : "Download backup"}
      </Button>
    </Paper>
  );
}
