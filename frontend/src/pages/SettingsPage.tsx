import { useEffect, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle,
  Divider, FormControlLabel, IconButton, MenuItem, Paper, Stack, Switch, Table, TableBody,
  TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import EditIcon from "@mui/icons-material/Edit";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listSettings, setSetting } from "../api/admin";
import { assistantModels } from "../api/assistant";
import { downloadBackup } from "../api/system";
import {
  getNotifications, listEventTypes, saveNotifications, testNotification,
  type NotificationConfig,
} from "../api/notifications";
import {
  backupDownloadUrl, createBackup, getBackupPolicy, listBackups, saveBackupPolicy,
} from "../api/backups";
import { getTimezone, saveTimezone } from "../api/timezone";
import {
  getAuditForwarding, saveAuditForwarding, testAuditForwarding, type AuditForwardConfig,
} from "../api/auditForwarding";
import { getOidcConfig, saveOidcConfig, type OidcConfig } from "../api/sso";
import {
  browserTimezone, formatDateTime, setDisplayTimezone, supportedTimezones,
} from "../lib/datetime";

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

      <TimezoneCard />
      <BrandingCard current={settings["branding"]} />
      <AssistantCard current={settings["assistant"]} />
      <ScanCard current={settings["scan_policy"]} />
      <WGSettingsCard current={settings["wireguard"]} />
      <RetentionCard current={settings["recordings"]} />
      <NotificationsCard />
      <SSOCard />
      <AuditForwardingCard />
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

// TimezoneCard sets the app-wide display timezone. It controls how every
// timestamp is rendered and how schedule clock-times are interpreted, so saving
// it refreshes all views.
function TimezoneCard() {
  const qc = useQueryClient();
  const { data: current } = useQuery({ queryKey: ["timezone"], queryFn: getTimezone });
  const [tz, setTz] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  // Always a concrete IANA zone: the saved value if set, otherwise the browser's
  // detected zone (so it's a real zone the server can honor — never an empty
  // "browser default" the backend can't resolve).
  const value = tz ?? (current || browserTimezone());
  const zones = supportedTimezones();
  const unset = !current;

  const save = useMutation({
    mutationFn: () => saveTimezone(value),
    onSuccess: () => {
      setSaved(true);
      setDisplayTimezone(value);
      // Re-render every view (and re-read the recomputed schedule next-runs).
      void qc.invalidateQueries();
    },
  });

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Time zone</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        The timezone used to display all dates/times in the app and to interpret the clock times you
        set for schedules. Pre-filled with your browser's detected zone; choose a specific zone and
        Save to apply it across the app and the scheduler.
      </Typography>
      <Stack direction="row" spacing={2} alignItems="center">
        <Autocomplete
          options={zones}
          value={value}
          onChange={(_, v) => { if (v) { setTz(v); setSaved(false); } }}
          disableClearable
          sx={{ width: 360 }}
          renderInput={(params) => <TextField {...params} label="Time zone" size="small" />}
        />
        <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>
          {saved ? "Saved" : "Save"}
        </Button>
      </Stack>
      {unset && (
        <Typography variant="caption" color="warning.main" sx={{ display: "block", mt: 1 }}>
          No timezone is set yet — the server is using UTC for schedules. Save to apply your zone.
        </Typography>
      )}
    </Paper>
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
// ScanCard sets the OpenSCAP scan/remediation time budget. Strict profiles
// (ANSSI High) on hosts with many files can run for a long time; raise this to
// avoid them being cut off. Overrides the FLEET_SCAN_TIMEOUT default.
function ScanCard({ current }: { current: unknown }) {
  const qc = useQueryClient();
  const cur = (current ?? {}) as { timeoutMinutes?: number };
  const [minutes, setMinutes] = useState(String(cur.timeoutMinutes ?? 60));
  const [saved, setSaved] = useState(false);
  const save = useMutation({
    mutationFn: () => setSetting("scan_policy", { timeoutMinutes: Math.min(480, Math.max(5, Number(minutes) || 60)) }),
    onSuccess: () => { setSaved(true); void qc.invalidateQueries({ queryKey: ["settings"] }); },
  });
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Security scans</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Maximum time a scan or remediation may run before it's stopped. Strict profiles (e.g.
        ANSSI High) on hosts with very large filesystems can take a long time — raise this so they
        aren't cut off. Range 5–480 minutes; overrides the <code>FLEET_SCAN_TIMEOUT</code> default.
      </Typography>
      <Stack direction="row" spacing={2} alignItems="flex-start">
        <TextField
          label="Scan timeout (minutes)" type="number" value={minutes}
          onChange={(e) => { setMinutes(e.target.value); setSaved(false); }}
          inputProps={{ min: 5, max: 480 }} sx={{ width: 220 }} size="small"
        />
        <Button variant="contained" sx={{ mt: 0.5 }} disabled={save.isPending} onClick={() => save.mutate()}>
          {saved ? "Saved" : "Save"}
        </Button>
      </Stack>
    </Paper>
  );
}

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

// SSOCard configures OIDC single sign-on (Okta, Azure AD, Google, Keycloak,
// Authentik, …). The client secret is write-only; group→role mappings provision
// access from the IdP's groups claim.
function SSOCard() {
  const { data: loaded } = useQuery({ queryKey: ["oidc-config"], queryFn: getOidcConfig });
  const [cfg, setCfg] = useState<OidcConfig | null>(null);
  const [groupMap, setGroupMap] = useState("");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (loaded && !cfg) {
      setCfg({ ...loaded.config, clientSecret: "" });
      setGroupMap(Object.entries(loaded.config.groupRoleMap ?? {}).map(([g, r]) => `${g}=${r}`).join("\n"));
    }
  }, [loaded, cfg]);

  const save = useMutation({
    mutationFn: () => {
      const groupRoleMap: Record<string, string> = {};
      for (const line of groupMap.split("\n")) {
        const [g, r] = line.split("=");
        if (g?.trim() && r?.trim()) groupRoleMap[g.trim()] = r.trim();
      }
      return saveOidcConfig({ ...(cfg as OidcConfig), groupRoleMap });
    },
    onSuccess: () => setSaved(true),
  });

  if (!cfg) {
    return (
      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6">Single sign-on (OIDC)</Typography>
        <Typography variant="body2" color="text.secondary">Loading…</Typography>
      </Paper>
    );
  }
  const set = (patch: Partial<OidcConfig>) => { setCfg({ ...cfg, ...patch }); setSaved(false); };

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Single sign-on (OIDC)</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Let users sign in via an OpenID Connect provider (Okta, Azure AD, Google, Keycloak,
        Authentik…). Set the redirect/callback URL in your IdP to{" "}
        <code>{window.location.origin}/api/v1/auth/oidc/callback</code>.
      </Typography>
      <FormControlLabel
        control={<Switch checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} />}
        label="Enable OIDC sign-on"
      />
      {cfg.enabled && (
        <Stack spacing={1.5} sx={{ mt: 1 }}>
          <TextField label="Issuer URL" size="small" value={cfg.issuer}
            onChange={(e) => set({ issuer: e.target.value })} placeholder="https://idp.example.com/" />
          <Stack direction="row" spacing={1.5}>
            <TextField label="Client ID" size="small" value={cfg.clientId}
              onChange={(e) => set({ clientId: e.target.value })} sx={{ flexGrow: 1 }} />
            <TextField label="Client secret" size="small" type="password" value={cfg.clientSecret ?? ""}
              onChange={(e) => set({ clientSecret: e.target.value })} sx={{ flexGrow: 1 }} autoComplete="new-password"
              placeholder={loaded?.secretSet ? "•••••••• (unchanged)" : ""} />
          </Stack>
          <Stack direction="row" spacing={1.5}>
            <TextField label="Button text" size="small" value={cfg.buttonText ?? ""}
              onChange={(e) => set({ buttonText: e.target.value })} sx={{ flexGrow: 1 }} placeholder="Sign in with Okta" />
            <TextField label="Default role (new users)" size="small" value={cfg.defaultRole ?? ""}
              onChange={(e) => set({ defaultRole: e.target.value })} sx={{ flexGrow: 1 }} placeholder="Read-Only" />
          </Stack>
          <Stack direction="row" spacing={1.5}>
            <TextField label="Username claim" size="small" value={cfg.usernameClaim ?? ""}
              onChange={(e) => set({ usernameClaim: e.target.value })} sx={{ flexGrow: 1 }} placeholder="preferred_username" />
            <TextField label="Email claim" size="small" value={cfg.emailClaim ?? ""}
              onChange={(e) => set({ emailClaim: e.target.value })} sx={{ flexGrow: 1 }} placeholder="email" />
            <TextField label="Groups claim" size="small" value={cfg.groupsClaim ?? ""}
              onChange={(e) => set({ groupsClaim: e.target.value })} sx={{ flexGrow: 1 }} placeholder="groups" />
          </Stack>
          <FormControlLabel
            control={<Switch checked={cfg.autoProvision} onChange={(e) => set({ autoProvision: e.target.checked })} />}
            label="Auto-provision new users on first sign-in"
          />
          <TextField label="Group → role mappings (one per line: idpGroup=FleetRole)" size="small" multiline minRows={2}
            value={groupMap} onChange={(e) => { setGroupMap(e.target.value); setSaved(false); }}
            placeholder={"fleet-admins=Administrator\nops=Operator"} />
        </Stack>
      )}
      <Box sx={{ mt: 1.5 }}>
        <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>
          {saved ? "Saved" : "Save"}
        </Button>
      </Box>
    </Paper>
  );
}

// AuditForwardingCard streams audit events to an external collector (syslog or
// HTTP) for a SIEM. Off until enabled; the in-app hash-chained log stays the
// system of record.
function AuditForwardingCard() {
  const { data: loaded } = useQuery({ queryKey: ["audit-forwarding"], queryFn: getAuditForwarding });
  const [cfg, setCfg] = useState<AuditForwardConfig | null>(null);
  const [saved, setSaved] = useState(false);
  const [testMsg, setTestMsg] = useState<string | null>(null);

  useEffect(() => {
    if (loaded && !cfg) {
      setCfg({
        enabled: loaded.enabled ?? false,
        type: loaded.type || "syslog",
        address: loaded.address ?? "",
        protocol: loaded.protocol || "udp",
      });
    }
  }, [loaded, cfg]);

  const save = useMutation({
    mutationFn: () => saveAuditForwarding(cfg as AuditForwardConfig),
    onSuccess: () => setSaved(true),
  });
  const test = useMutation({
    mutationFn: () => testAuditForwarding(cfg as AuditForwardConfig),
    onSuccess: (r) => setTestMsg(r.ok ? "Test event sent." : `Test failed: ${r.error}`),
    onError: () => setTestMsg("Test failed."),
  });

  if (!cfg) {
    return (
      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6">Audit forwarding (SIEM)</Typography>
        <Typography variant="body2" color="text.secondary">Loading…</Typography>
      </Paper>
    );
  }
  const set = (patch: Partial<AuditForwardConfig>) => { setCfg({ ...cfg, ...patch }); setSaved(false); setTestMsg(null); };

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Audit forwarding (SIEM)</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Stream every audit event to an external collector for your SIEM. Best-effort and off by
        default; the in-app tamper-evident log remains the system of record.
      </Typography>
      <FormControlLabel
        control={<Switch checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} />}
        label="Forward audit events"
      />
      {cfg.enabled && (
        <Stack direction="row" spacing={2} alignItems="center" sx={{ mt: 1 }}>
          <TextField select size="small" label="Collector" value={cfg.type}
            onChange={(e) => set({ type: e.target.value as AuditForwardConfig["type"] })} sx={{ width: 150 }}>
            <MenuItem value="syslog">Syslog</MenuItem>
            <MenuItem value="http">HTTP (JSON)</MenuItem>
          </TextField>
          <TextField size="small" label={cfg.type === "http" ? "Collector URL" : "host:port"} value={cfg.address}
            onChange={(e) => set({ address: e.target.value })} sx={{ flexGrow: 1 }}
            placeholder={cfg.type === "http" ? "https://siem.example.com/audit" : "siem.example.com:514"} />
          {cfg.type === "syslog" && (
            <TextField select size="small" label="Protocol" value={cfg.protocol}
              onChange={(e) => set({ protocol: e.target.value as AuditForwardConfig["protocol"] })} sx={{ width: 110 }}>
              <MenuItem value="udp">UDP</MenuItem>
              <MenuItem value="tcp">TCP</MenuItem>
            </TextField>
          )}
        </Stack>
      )}
      {testMsg && <Alert severity={testMsg.startsWith("Test event") ? "success" : "error"} sx={{ mt: 1.5 }}>{testMsg}</Alert>}
      <Stack direction="row" spacing={1.5} sx={{ mt: 1.5 }}>
        <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>
          {saved ? "Saved" : "Save"}
        </Button>
        {cfg.enabled && (
          <Button variant="outlined" disabled={test.isPending || !cfg.address} onClick={() => test.mutate()}>
            Send test event
          </Button>
        )}
      </Stack>
    </Paper>
  );
}

// BackupCard manages encrypted database backups: an optional recurring schedule
// with retention, on-demand backups stored on the server, and a plaintext
// download. Restore is an out-of-band openssl + psql one-liner (below / DR guide).
function BackupCard() {
  const qc = useQueryClient();
  const { data: list } = useQuery({ queryKey: ["backups"], queryFn: listBackups });
  const { data: policy } = useQuery({ queryKey: ["backup-policy"], queryFn: getBackupPolicy });

  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [interval, setInterval] = useState("24");
  const [retention, setRetention] = useState("7");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (policy && enabled === null) {
      setEnabled(policy.enabled);
      setInterval(String(policy.intervalHours));
      setRetention(String(policy.retentionCount));
    }
  }, [policy, enabled]);

  const savePolicy = useMutation({
    mutationFn: () => saveBackupPolicy({
      enabled: !!enabled,
      intervalHours: Math.max(1, Number(interval) || 24),
      retentionCount: Math.max(1, Number(retention) || 7),
    }),
    onSuccess: () => { setSaved(true); void qc.invalidateQueries({ queryKey: ["backup-policy"] }); },
  });
  const backupNow = useMutation({
    mutationFn: createBackup,
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["backups"] }),
  });
  const plaintext = useMutation({ mutationFn: downloadBackup });

  const fmtSize = (n: number) => (n < 1024 * 1024 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`);

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Backup &amp; Restore</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Encrypted database backups (pg_dump + AES-256). Backups are stored under{" "}
        <code>{list?.dir ?? "the backup directory"}</code> — map that to off-host storage (NFS,
        external disk, or an rsync target) so a lost host doesn't take the backups with it.
      </Typography>

      {/* Scheduled policy */}
      <FormControlLabel
        control={<Switch checked={!!enabled} onChange={(e) => { setEnabled(e.target.checked); setSaved(false); }} />}
        label="Automatic scheduled backups"
      />
      <Stack direction="row" spacing={2} alignItems="center" sx={{ mt: 1, mb: 2 }}>
        <TextField label="Every (hours)" type="number" size="small" value={interval}
          onChange={(e) => { setInterval(e.target.value); setSaved(false); }} sx={{ width: 150 }}
          inputProps={{ min: 1 }} disabled={!enabled} />
        <TextField label="Keep last N" type="number" size="small" value={retention}
          onChange={(e) => { setRetention(e.target.value); setSaved(false); }} sx={{ width: 150 }}
          inputProps={{ min: 1 }} disabled={!enabled} />
        <Button variant="contained" disabled={savePolicy.isPending} onClick={() => savePolicy.mutate()}>
          {saved ? "Saved" : "Save"}
        </Button>
      </Stack>

      <Stack direction="row" spacing={1.5} sx={{ mb: 1.5 }}>
        <Button variant="outlined" onClick={() => backupNow.mutate()} disabled={backupNow.isPending}>
          {backupNow.isPending ? "Backing up…" : "Back up now"}
        </Button>
        <Button variant="text" onClick={() => plaintext.mutate()} disabled={plaintext.isPending}>
          Download plaintext (.sql)
        </Button>
      </Stack>
      {backupNow.isError && <Alert severity="error" sx={{ mb: 1 }}>{(backupNow.error as Error).message}</Alert>}

      {/* Stored backups */}
      {(list?.backups.length ?? 0) > 0 && (
        <TableContainer sx={{ mb: 1.5 }}>
          <Table size="small">
            <TableHead>
              <TableRow><TableCell>Backup</TableCell><TableCell>Size</TableCell><TableCell>Created</TableCell><TableCell /></TableRow>
            </TableHead>
            <TableBody>
              {list!.backups.map((b) => (
                <TableRow key={b.name} hover>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>{b.name}</TableCell>
                  <TableCell>{fmtSize(b.size)}</TableCell>
                  <TableCell sx={{ color: "text.secondary" }}>{formatDateTime(b.createdAt)}</TableCell>
                  <TableCell align="right">
                    <Button size="small" href={backupDownloadUrl(b.name)}>Download</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Alert severity="info" sx={{ mt: 1 }}>
        <Typography variant="body2">Restore an encrypted backup (offline):</Typography>
        <Box component="pre" sx={{ m: 0, mt: 0.5, fontSize: 12, whiteSpace: "pre-wrap" }}>
          openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:$FLEET_BACKUP_PASSPHRASE \{"\n"}
          {"  "}-in fleet-backup-*.sql.enc | psql "$FLEET_DATABASE_URL"
        </Box>
        See the break-glass / disaster-recovery guide for the full procedure.
      </Alert>
    </Paper>
  );
}

// NotificationsCard configures outbound alerts (email/webhook) and which events
// go to which channel. Everything is off until enabled. The SMTP password is
// write-only — the server stores it encrypted and never returns it.
function NotificationsCard() {
  const qc = useQueryClient();
  const { data: loaded } = useQuery({ queryKey: ["notifications"], queryFn: getNotifications });
  const { data: eventTypes = [] } = useQuery({ queryKey: ["notification-events"], queryFn: listEventTypes });

  const [cfg, setCfg] = useState<NotificationConfig | null>(null);
  const [saved, setSaved] = useState(false);
  const [testMsg, setTestMsg] = useState<string | null>(null);

  useEffect(() => {
    if (loaded && !cfg) {
      const e = loaded.email ?? ({} as NotificationConfig["email"]);
      const w = loaded.webhook ?? ({} as NotificationConfig["webhook"]);
      setCfg({
        email: {
          enabled: e.enabled ?? false, host: e.host ?? "", port: e.port || 587,
          username: e.username ?? "", from: e.from ?? "", to: e.to ?? "",
          security: e.security || "starttls",
        },
        webhook: { enabled: w.enabled ?? false, url: w.url ?? "", format: w.format || "json" },
        events: loaded.events ?? {},
        throttleMinutes: loaded.throttleMinutes || 5,
        passwordSet: loaded.passwordSet,
      });
    }
  }, [loaded, cfg]);

  const save = useMutation({
    mutationFn: () => saveNotifications(cfg as NotificationConfig),
    onSuccess: () => { setSaved(true); void qc.invalidateQueries({ queryKey: ["notifications"] }); },
  });
  const test = useMutation({
    mutationFn: (channel: "email" | "webhook") => testNotification(channel),
    onSuccess: (r) => setTestMsg(r.ok ? "Test sent successfully." : `Test failed: ${r.error}`),
    onError: () => setTestMsg("Test failed."),
  });

  if (!cfg) {
    return (
      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6">Notifications</Typography>
        <Typography variant="body2" color="text.secondary">Loading…</Typography>
      </Paper>
    );
  }

  const dirty = () => { setSaved(false); setTestMsg(null); };
  const setEmail = (patch: Partial<NotificationConfig["email"]>) => { setCfg({ ...cfg, email: { ...cfg.email, ...patch } }); dirty(); };
  const setWebhook = (patch: Partial<NotificationConfig["webhook"]>) => { setCfg({ ...cfg, webhook: { ...cfg.webhook, ...patch } }); dirty(); };
  const setRoute = (key: string, ch: "email" | "webhook", on: boolean) => {
    const row = cfg.events[key] ?? { email: false, webhook: false };
    setCfg({ ...cfg, events: { ...cfg.events, [key]: { ...row, [ch]: on } } });
    dirty();
  };

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Notifications</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Send alerts on key events (host offline, pending approvals, scan findings, failed playbook
        runs). Configure a channel, choose which events route to it, then Save. Everything is off by
        default.
      </Typography>

      {/* Email channel */}
      <FormControlLabel
        control={<Switch checked={cfg.email.enabled} onChange={(e) => setEmail({ enabled: e.target.checked })} />}
        label="Email (SMTP)"
      />
      {cfg.email.enabled && (
        <Stack spacing={1.5} sx={{ mt: 1, mb: 1, pl: 1 }}>
          <Stack direction="row" spacing={1.5}>
            <TextField label="SMTP host" size="small" value={cfg.email.host}
              onChange={(e) => setEmail({ host: e.target.value })} sx={{ flexGrow: 1 }} placeholder="smtp.example.com" />
            <TextField label="Port" size="small" type="number" value={cfg.email.port}
              onChange={(e) => setEmail({ port: Number(e.target.value) || 587 })} sx={{ width: 110 }} />
            <TextField label="Security" size="small" select value={cfg.email.security}
              onChange={(e) => setEmail({ security: e.target.value })} sx={{ width: 150 }}>
              <MenuItem value="starttls">STARTTLS</MenuItem>
              <MenuItem value="tls">TLS (SMTPS)</MenuItem>
              <MenuItem value="none">None</MenuItem>
            </TextField>
          </Stack>
          <Stack direction="row" spacing={1.5}>
            <TextField label="Username" size="small" value={cfg.email.username}
              onChange={(e) => setEmail({ username: e.target.value })} sx={{ flexGrow: 1 }} autoComplete="off" />
            <TextField label="Password" size="small" type="password" value={cfg.email.password ?? ""}
              onChange={(e) => setEmail({ password: e.target.value })} sx={{ flexGrow: 1 }} autoComplete="new-password"
              placeholder={cfg.passwordSet ? "•••••••• (unchanged)" : ""} />
          </Stack>
          <Stack direction="row" spacing={1.5}>
            <TextField label="From" size="small" value={cfg.email.from}
              onChange={(e) => setEmail({ from: e.target.value })} sx={{ flexGrow: 1 }} placeholder="fleet@example.com" />
            <TextField label="To (comma-separated)" size="small" value={cfg.email.to}
              onChange={(e) => setEmail({ to: e.target.value })} sx={{ flexGrow: 1 }} placeholder="you@example.com" />
          </Stack>
          <Box>
            <Button size="small" variant="outlined" disabled={test.isPending} onClick={() => test.mutate("email")}>
              Send test email
            </Button>
          </Box>
        </Stack>
      )}

      <Divider sx={{ my: 1.5 }} />

      {/* Webhook channel */}
      <FormControlLabel
        control={<Switch checked={cfg.webhook.enabled} onChange={(e) => setWebhook({ enabled: e.target.checked })} />}
        label="Webhook"
      />
      {cfg.webhook.enabled && (
        <Stack spacing={1.5} sx={{ mt: 1, mb: 1, pl: 1 }}>
          <Stack direction="row" spacing={1.5}>
            <TextField label="Webhook URL" size="small" value={cfg.webhook.url}
              onChange={(e) => setWebhook({ url: e.target.value })} sx={{ flexGrow: 1 }}
              placeholder="https://hooks.example.com/…" />
            <TextField label="Format" size="small" select value={cfg.webhook.format}
              onChange={(e) => setWebhook({ format: e.target.value })} sx={{ width: 160 }}>
              <MenuItem value="json">Generic JSON</MenuItem>
              <MenuItem value="slack">Slack / Mattermost</MenuItem>
              <MenuItem value="discord">Discord</MenuItem>
            </TextField>
          </Stack>
          <Box>
            <Button size="small" variant="outlined" disabled={test.isPending} onClick={() => test.mutate("webhook")}>
              Send test webhook
            </Button>
          </Box>
        </Stack>
      )}

      {testMsg && <Alert severity={testMsg.startsWith("Test sent") ? "success" : "error"} sx={{ my: 1 }}>{testMsg}</Alert>}

      <Divider sx={{ my: 1.5 }} />

      {/* Event routing matrix */}
      <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Which events to send</Typography>
      <TableContainer>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Event</TableCell>
              <TableCell align="center">Email</TableCell>
              <TableCell align="center">Webhook</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {eventTypes.map((ev) => {
              const row = cfg.events[ev.key] ?? { email: false, webhook: false };
              return (
                <TableRow key={ev.key}>
                  <TableCell>{ev.label}</TableCell>
                  <TableCell align="center">
                    <Checkbox size="small" checked={row.email} disabled={!cfg.email.enabled}
                      onChange={(e) => setRoute(ev.key, "email", e.target.checked)} />
                  </TableCell>
                  <TableCell align="center">
                    <Checkbox size="small" checked={row.webhook} disabled={!cfg.webhook.enabled}
                      onChange={(e) => setRoute(ev.key, "webhook", e.target.checked)} />
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>

      <Stack direction="row" spacing={2} alignItems="center" sx={{ mt: 1.5 }}>
        <TextField label="Throttle (minutes)" size="small" type="number" value={cfg.throttleMinutes}
          onChange={(e) => { setCfg({ ...cfg, throttleMinutes: Number(e.target.value) || 5 }); dirty(); }}
          sx={{ width: 180 }} helperText="Suppress repeats of the same event" />
        <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>
          {saved ? "Saved" : "Save"}
        </Button>
      </Stack>
    </Paper>
  );
}
