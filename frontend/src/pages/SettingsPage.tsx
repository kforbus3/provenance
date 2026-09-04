import { useEffect, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Checkbox, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, Divider, FormControlLabel, IconButton, MenuItem, Paper, Stack,
  Switch, Tab, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Tabs, TextField,
  Tooltip, Typography,
} from "@mui/material";
import EditIcon from "@mui/icons-material/Edit";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listSettings, setSetting } from "../api/admin";
import { nextWGAddress } from "../api/hosts";
import { assistantModels, assistantStatus, getActionPolicy, saveActionPolicy } from "../api/assistant";
import { downloadBackup } from "../api/system";
import { UpdatesCard } from "./settings/UpdatesCard";
import {
  getNotifications, listEventTypes, saveNotifications, testNotification,
  type NotificationConfig,
} from "../api/notifications";
import {
  backupDownloadUrl, createBackup, getBackupPolicy, listBackups, saveBackupPolicy,
} from "../api/backups";
import { getTimezone, saveTimezone } from "../api/timezone";
import { getKMSStatus } from "../api/kms";
import { getITSM, saveITSM, testITSM } from "../api/itsm";
import {
  getAuditForwarding, saveAuditForwarding, testAuditForwarding, type AuditForwardConfig,
} from "../api/auditForwarding";
import {
  getDigest, saveDigest, previewDigest, sendDigest, type DigestPolicy,
} from "../api/digest";
import {
  getReportSchedule, saveReportSchedule, sendReportScheduleNow, type ReportSchedule,
} from "../api/reportSchedule";
import {
  getOidcConfig, saveOidcConfig, getLdapConfig, saveLdapConfig,
  getSamlConfig, saveSamlConfig, getScimConfig, saveScimConfig, issueScimToken, revokeScimToken,
  type OidcConfig, type LdapConfig, type SamlConfig,
} from "../api/sso";
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
  const [tab, setTab] = useState(0);

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

      <Tabs
        value={tab}
        onChange={(_, v) => setTab(v as number)}
        variant="scrollable"
        scrollButtons="auto"
        sx={{ mb: 2, borderBottom: 1, borderColor: "divider" }}
      >
        <Tab label="General" />
        <Tab label="Authentication" />
        <Tab label="Integrations" />
        <Tab label="Infrastructure" />
        <Tab label="Maintenance" />
      </Tabs>

      {/* Several cards seed their form state from the loaded settings on first
          mount, so the panels must not render until the query resolves — otherwise
          they initialize blank and never re-sync when the data arrives. */}
      {isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", my: 4 }}><CircularProgress /></Box>
      ) : (
        <>
          {tab === 0 && (
            <>
              <TimezoneCard />
              <BrandingCard current={settings["branding"]} />
              <RetentionCard current={settings["recordings"]} />
            </>
          )}
          {tab === 1 && (
            <>
              <SessionPolicyCard current={settings["session_policy"]} />
              <SSOCard />
              <SAMLCard />
              <LDAPCard />
              <SCIMCard />
            </>
          )}
          {tab === 2 && (
            <>
              <AssistantCard current={settings["assistant"]} />
              <ActionPolicyCard />
              <NotificationsCard />
              <DigestCard />
              <ReportScheduleCard />
              <ITSMCard />
              <AuditForwardingCard />
            </>
          )}
          {tab === 3 && (
            <>
              <EncryptionCard />
              <WGSettingsCard current={settings["wireguard"]} />
              <ScanCard current={settings["scan_policy"]} />
              <ScriptCard current={settings["scripts"]} />
            </>
          )}
          {tab === 4 && (
            <>
              <UpdatesCard />
              <BackupCard />
              <Typography variant="h6" sx={{ mt: 1 }}>Advanced — raw settings</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
                Direct view of the underlying settings store. Prefer the forms above; edit the raw
                JSON only if you know what you are doing.
              </Typography>
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
                    {entries.length === 0 && (
                      <TableRow><TableCell colSpan={3}>
                        <Typography color="text.secondary">No settings configured.</Typography>
                      </TableCell></TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            </>
          )}
        </>
      )}

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
    mutationFn: () => setSetting("branding", { app_name: name.trim() || "Blackfriars" }),
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
          placeholder="Blackfriars" sx={{ flexGrow: 1, maxWidth: 360 }}
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
  // Reports where the configured URL actually points, so the card can say
  // whether the data stays on this network rather than assuming it does.
  const { data: status } = useQuery({ queryKey: ["assistant-status"], queryFn: assistantStatus });
  const cur = (current ?? {}) as { enabled?: boolean; ollamaUrl?: string; model?: string; numCtx?: number };
  const [enabled, setEnabled] = useState(Boolean(cur.enabled));
  const [url, setUrl] = useState(cur.ollamaUrl ?? "");
  const [model, setModel] = useState(cur.model ?? "");
  const [numCtx, setNumCtx] = useState(cur.numCtx ? String(cur.numCtx) : "");
  const [models, setModels] = useState<string[]>(cur.model ? [cur.model] : []);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadModels = useMutation({
    mutationFn: () => assistantModels(url.trim()),
    onSuccess: (list) => { setModels(list); setError(list.length ? null : "No models found at that URL."); },
    onError: () => setError("Could not reach Ollama at that URL."),
  });

  const save = useMutation({
    mutationFn: () => setSetting("assistant", {
      enabled, ollamaUrl: url.trim(), model,
      // Blank = let the backend use its default. The backend also floors whatever is
      // sent, because a window too small to hold the prompt is not a slower assistant
      // — it is one running with its instructions silently deleted.
      numCtx: Number(numCtx.trim()) || 0,
    }),
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
        Point Blackfriars at a local Ollama instance to enable read-only natural-language queries over
        your fleet (e.g. “hosts with less than 20% disk free”). Queries are RBAC-scoped and
        audited, and answering one sends the data it reads — host inventory, sessions, audit
        entries — to whichever Ollama instance you configure below.
      </Typography>
      {/* The card used to state flatly that data never leaves your network. That
          holds only for a local URL, and the field takes any URL at all, so the
          claim is made conditional and the backend says which case applies. */}
      {status?.destination?.external && (
        <Alert severity="warning" sx={{ mb: 1.5 }}>
          <strong>{status.destination.host}</strong>
          {status.destination.resolved ? ` (${status.destination.resolved})` : ""} is a public
          address, so fleet data leaves your network to be answered. Point this at an Ollama
          instance on your own network if that is not what you intend.
        </Alert>
      )}
      {status?.contextWarning && (
        <Alert severity="warning" sx={{ mb: 1.5 }}>{status.contextWarning}</Alert>
      )}
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
        <TextField
          size="small" type="number" label="Context window (tokens)" value={numCtx} sx={{ maxWidth: 360 }}
          placeholder={String(status?.contextWindow ?? 32768)}
          onChange={(e) => { setNumCtx(e.target.value); setSaved(false); }}
          helperText={
            `Leave blank for the default (${status?.contextWindow ?? 32768}). The assistant's instructions and tool ` +
            `definitions alone cost about ${status?.promptFloorTokens ?? "9,000"} tokens; Ollama does not error when a ` +
            `prompt exceeds the window — it drops the oldest tokens, i.e. the instructions. Raise this only if you have ` +
            `the VRAM for it.`
          }
        />
        <Box>
          <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>
            {saved ? "Saved" : "Save"}
          </Button>
        </Box>
      </Stack>
    </Paper>
  );
}

// ActionPolicyCard controls which actions the assistant may propose and whether
// they require approval (System.Configure).
function ActionPolicyCard() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ["action-policy"], queryFn: getActionPolicy });
  const [requireAll, setRequireAll] = useState<boolean | null>(null);
  const [disabled, setDisabled] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);

  const reqAll = requireAll ?? data?.policy.requireApprovalForAll ?? false;
  const disabledKinds = disabled ?? data?.policy.disabledKinds ?? [];
  const actions = data?.actions ?? [];

  const save = useMutation({
    mutationFn: () => saveActionPolicy({ requireApprovalForAll: reqAll, disabledKinds }),
    onSuccess: () => { setSaved(true); void qc.invalidateQueries({ queryKey: ["action-policy"] }); },
  });
  const toggleKind = (k: string) => {
    setDisabled(disabledKinds.includes(k) ? disabledKinds.filter((x) => x !== k) : [...disabledKinds, k]);
    setSaved(false);
  };

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Assistant actions</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Control the actions the assistant may propose (for users with <code>Assistant.Act</code>).
        Guarded actions always need a second person's approval; you can require approval for every
        action, or disable specific ones entirely.
      </Typography>
      <FormControlLabel
        control={<Switch checked={reqAll} onChange={(e) => { setRequireAll(e.target.checked); setSaved(false); }} />}
        label="Require approval for ALL assistant actions (even safe ones)"
      />
      <Box sx={{ mt: 1 }}>
        <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Available actions</Typography>
        {actions.length === 0 && <Typography variant="body2" color="text.secondary">Loading…</Typography>}
        {actions.map((a) => (
          <FormControlLabel key={a.kind} sx={{ display: "block" }}
            control={<Checkbox size="small" checked={!disabledKinds.includes(a.kind)} onChange={() => toggleKind(a.kind)} />}
            label={`${a.kind} — ${a.risk}, needs ${a.permission}`}
          />
        ))}
      </Box>
      <Box sx={{ mt: 1 }}>
        <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>
          {saved ? "Saved" : "Save"}
        </Button>
      </Box>
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

// ScriptCard sets the maximum time a PowerShell script may run on a single Windows
// host (the WinRM operation timeout) before it's stopped. The whole-run timeout scales
// from this and the host/batch count.
function ScriptCard({ current }: { current: unknown }) {
  const qc = useQueryClient();
  const cur = (current ?? {}) as { timeoutMinutes?: number };
  const [minutes, setMinutes] = useState(String(cur.timeoutMinutes ?? 15));
  const [saved, setSaved] = useState(false);
  const save = useMutation({
    mutationFn: () => setSetting("scripts", { timeoutMinutes: Math.min(240, Math.max(1, Number(minutes) || 15)) }),
    onSuccess: () => { setSaved(true); void qc.invalidateQueries({ queryKey: ["settings"] }); },
  });
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">PowerShell scripts</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Maximum time a PowerShell script may run on a single Windows host before it's stopped.
        Raise it for longer scripts; for very long jobs (e.g. installing large Windows updates)
        prefer a fire-and-forget script that starts a scheduled task on the host and returns.
        Range 1–240 minutes; defaults to 15.
      </Typography>
      <Stack direction="row" spacing={2} alignItems="flex-start">
        <TextField
          label="Script timeout (minutes)" type="number" value={minutes}
          onChange={(e) => { setMinutes(e.target.value); setSaved(false); }}
          inputProps={{ min: 1, max: 240 }} sx={{ width: 220 }} size="small"
        />
        <Button variant="contained" sx={{ mt: 0.5 }} disabled={save.isPending} onClick={() => save.mutate()}>
          {saved ? "Saved" : "Save"}
        </Button>
      </Stack>
    </Paper>
  );
}

// SessionPolicyCard configures the global conditional-access policy: which client
// IP ranges may sign in, and how many concurrent sessions a user may hold. Both
// are enforced at session creation across every login method (local, LDAP, OIDC,
// SAML). Per-user overrides live on the user's detail dialog.
function SessionPolicyCard({ current }: { current: unknown }) {
  const qc = useQueryClient();
  const cur = (current ?? {}) as { ipAllowlist?: string[]; maxConcurrentSessions?: number };
  const [allowlist, setAllowlist] = useState((cur.ipAllowlist ?? []).join("\n"));
  const [maxConcurrent, setMaxConcurrent] = useState(String(cur.maxConcurrentSessions ?? 0));
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const parseAllowlist = () =>
    allowlist.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);

  const save = useMutation({
    mutationFn: () =>
      setSetting("session_policy", {
        ipAllowlist: parseAllowlist(),
        maxConcurrentSessions: Math.max(0, Number(maxConcurrent) || 0),
      }),
    onSuccess: () => { setSaved(true); setError(null); void qc.invalidateQueries({ queryKey: ["settings"] }); },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setError(msg ?? "Could not save session policy.");
    },
  });

  const restricted = parseAllowlist().length > 0;
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Conditional access</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Restrict who can sign in and hold sessions. Enforced at login for every method
        (password, LDAP, OIDC, SAML). Leave the allowlist empty to allow any network, and the
        session limit at 0 for unlimited. These are the fleet-wide defaults; you can override
        them per user from a user's details.
      </Typography>
      {error && <Alert severity="error" sx={{ mb: 1.5 }}>{error}</Alert>}
      <Stack spacing={2} sx={{ maxWidth: 520 }}>
        <TextField
          label="IP allowlist (one CIDR or IP per line)"
          placeholder={"10.0.0.0/8\n203.0.113.5"}
          value={allowlist} multiline minRows={3}
          onChange={(e) => { setAllowlist(e.target.value); setSaved(false); }}
          sx={{ "& textarea": { fontFamily: "monospace" } }}
          helperText={restricted
            ? "Only clients in these ranges may sign in. Your current IP must be included, or the save is rejected to prevent lockout."
            : "Empty — sign-in is allowed from any network."}
        />
        <TextField
          label="Max concurrent sessions per user" type="number" value={maxConcurrent}
          onChange={(e) => { setMaxConcurrent(e.target.value); setSaved(false); }}
          inputProps={{ min: 0 }} sx={{ width: 280 }} size="small"
          helperText="0 = unlimited. New logins are refused once a user is at the limit."
        />
        <Box>
          <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>
            {saved ? "Saved" : "Save"}
          </Button>
        </Box>
        <Typography variant="caption" color="text.secondary">
          Accurate client IPs behind a reverse proxy require FLEET_TRUSTED_PROXIES to be set
          (off by default) — otherwise the allowlist sees the proxy's address, not the user's.
        </Typography>
      </Stack>
    </Paper>
  );
}

// EncryptionCard reports the at-rest encryption posture: whether an external KMS/HSM
// envelope-protects the master passphrases (CA signing key + credential vault) and
// whether that backend is currently healthy. Read-only — KMS configuration is boot-
// time environment (FLEET_KMS_*); this surfaces it in-product for operators/auditors.
function EncryptionCard() {
  const { data, isLoading } = useQuery({ queryKey: ["kms-status"], queryFn: getKMSStatus, refetchInterval: 60_000 });
  const enabled = data?.enabled ?? false;
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Encryption at rest</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        The CA signing key and every credential-vault secret are AES-256-GCM sealed. An external
        Key Management Service (KMS) or HSM can additionally protect the master passphrases: they are
        stored only in KMS-wrapped form and unsealed into memory at boot, so a stolen disk or database
        backup cannot be decrypted without live access to the KMS. Configured via <code>FLEET_KMS_*</code>.
      </Typography>
      {isLoading ? (
        <CircularProgress size={22} />
      ) : (
        <Stack spacing={1.2}>
          <Stack direction="row" spacing={1} alignItems="center">
            <Typography variant="body2" sx={{ minWidth: 200 }}>External KMS backend</Typography>
            {enabled ? (
              <Chip size="small" color="success" label={data?.provider} />
            ) : (
              <Chip size="small" variant="outlined" label="local (no external KMS)" />
            )}
          </Stack>
          {enabled && (
            <>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography variant="body2" sx={{ minWidth: 200 }}>Key ID</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{data?.keyId || "—"}</Typography>
              </Stack>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography variant="body2" sx={{ minWidth: 200 }}>Backend health</Typography>
                <Chip size="small" color={data?.healthy ? "success" : "error"}
                  label={data?.healthy ? "healthy" : (data?.health || "unhealthy")} />
              </Stack>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography variant="body2" sx={{ minWidth: 200 }}>CA passphrase</Typography>
                <Chip size="small" color={data?.caPassphraseWrapped ? "success" : "default"}
                  variant={data?.caPassphraseWrapped ? "filled" : "outlined"}
                  label={data?.caPassphraseWrapped ? "KMS-wrapped" : "plaintext env"} />
              </Stack>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography variant="body2" sx={{ minWidth: 200 }}>Vault passphrase</Typography>
                <Chip size="small" color={data?.vaultPassphraseWrapped ? "success" : "default"}
                  variant={data?.vaultPassphraseWrapped ? "filled" : "outlined"}
                  label={data?.vaultPassphraseWrapped ? "KMS-wrapped" : "plaintext env"} />
              </Stack>
            </>
          )}
          {!enabled && (
            <Alert severity="info" sx={{ mt: 0.5 }}>
              No external KMS is configured. Master passphrases are read from the environment. To enable,
              set <code>FLEET_KMS_PROVIDER</code> (vault-transit or aws-kms) and wrap your passphrases with
              <code> fleetctl kms wrap</code>. See docs/kms.md.
            </Alert>
          )}
        </Stack>
      )}
    </Paper>
  );
}

// ITSMCard configures the ServiceNow/Jira integration: opening a change ticket for
// each access approval so privileged-access requests carry a change reference.
function ITSMCard() {
  const { data, isLoading } = useQuery({ queryKey: ["itsm"], queryFn: getITSM });
  const [form, setForm] = useState<{ provider: string; baseUrl: string; user: string; project: string; enabled: boolean; token: string } | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const f = form ?? {
    provider: data?.provider || "servicenow", baseUrl: data?.baseUrl ?? "", user: data?.user ?? "",
    project: data?.project ?? "", enabled: data?.enabled ?? false, token: "",
  };
  const set = (patch: Partial<typeof f>) => setForm({ ...f, ...patch });
  const save = useMutation({
    mutationFn: () => saveITSM({ provider: f.provider, baseUrl: f.baseUrl, user: f.user, project: f.project, enabled: f.enabled, token: f.token || undefined }),
    onSuccess: () => setMsg({ ok: true, text: "Saved." }),
    onError: () => setMsg({ ok: false, text: "Could not save." }),
  });
  const test = useMutation({
    mutationFn: testITSM,
    onSuccess: () => setMsg({ ok: true, text: "Connection OK." }),
    onError: (e) => setMsg({ ok: false, text: ((e as { response?: { data?: { error?: string } } })?.response?.data?.error) || "Connection failed." }),
  });

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">ITSM integration (ServiceNow / Jira)</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        When enabled, Blackfriars opens a change/incident ticket for each just-in-time access request and
        attaches its reference to the approval. Best-effort — a request is never blocked if the ITSM is
        unreachable.
      </Typography>
      {isLoading ? <CircularProgress size={22} /> : (
        <Stack spacing={2}>
          <Stack direction="row" spacing={2} alignItems="center">
            <TextField select label="Provider" size="small" value={f.provider} onChange={(e) => set({ provider: e.target.value })} sx={{ width: 160 }}>
              <MenuItem value="servicenow">ServiceNow</MenuItem>
              <MenuItem value="jira">Jira</MenuItem>
            </TextField>
            <FormControlLabel control={<Switch checked={f.enabled} onChange={(e) => set({ enabled: e.target.checked })} />} label="Enabled" />
          </Stack>
          <TextField label={f.provider === "jira" ? "Base URL (https://org.atlassian.net)" : "Instance URL (https://org.service-now.com)"}
            size="small" value={f.baseUrl} onChange={(e) => set({ baseUrl: e.target.value })} fullWidth />
          <Stack direction="row" spacing={2}>
            <TextField label={f.provider === "jira" ? "Account email" : "Username"} size="small" value={f.user} onChange={(e) => set({ user: e.target.value })} sx={{ flexGrow: 1 }} />
            <TextField label={f.provider === "jira" ? "Project key (e.g. OPS)" : "Table (default incident)"} size="small" value={f.project} onChange={(e) => set({ project: e.target.value })} sx={{ width: 220 }} />
          </Stack>
          <TextField label={data?.hasToken ? (f.provider === "jira" ? "API token (leave blank to keep current)" : "Password (leave blank to keep current)") : (f.provider === "jira" ? "API token" : "Password")}
            size="small" type="password" value={f.token} onChange={(e) => set({ token: e.target.value })} autoComplete="new-password" fullWidth />
          {msg && <Alert severity={msg.ok ? "success" : "error"}>{msg.text}</Alert>}
          <Stack direction="row" spacing={1}>
            <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>Save</Button>
            <Button variant="outlined" disabled={test.isPending || !data?.enabled} onClick={() => test.mutate()}>Test connection</Button>
          </Stack>
        </Stack>
      )}
    </Paper>
  );
}

// OverlayPlans shows both VPN transports' address plans and the ports they need
// open. A deployment can run either or both, on separate subnets, and which one a
// host uses is chosen per host at enrollment — so "which pool will this host land in
// and which port must my firewall allow" is a question the settings page has to be
// able to answer for both, not just for WireGuard.
function OverlayPlans() {
  const { data } = useQuery({ queryKey: ["next-wg"], queryFn: nextWGAddress });
  const plans = data?.overlays ?? [];
  if (plans.length === 0) return null;
  return (
    <Table size="small" sx={{ mb: 2, maxWidth: 560 }}>
      <TableHead>
        <TableRow>
          <TableCell>Overlay</TableCell>
          <TableCell>Subnet</TableCell>
          <TableCell>Jump address</TableCell>
          <TableCell>Port</TableCell>
          <TableCell>Next free</TableCell>
        </TableRow>
      </TableHead>
      <TableBody>
        {plans.map((p) => (
          <TableRow key={p.name}>
            <TableCell>
              {p.name === "openvpn" ? "OpenVPN" : "WireGuard"}
              {data?.overlay === p.name && (
                <Chip size="small" label="default" sx={{ ml: 1 }} variant="outlined" />
              )}
            </TableCell>
            <TableCell><code>{p.subnet}</code></TableCell>
            <TableCell><code>{p.jumpIp}</code></TableCell>
            <TableCell><code>{p.port}/{p.protocol}</code></TableCell>
            <TableCell>
              {data?.exhaustedOverlays?.[p.name]
                ? <Typography variant="caption" color="error">pool exhausted</Typography>
                : <code>{data?.nextAddress?.[p.name] ?? "—"}</code>}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function WGSettingsCard({ current }: { current: unknown }) {
  const qc = useQueryClient();
  const cur = (current ?? {}) as { jumpHost?: string; jumpPort?: number; requireOverlay?: boolean };
  const [jumpHost, setJumpHost] = useState(cur.jumpHost ?? "");
  const [jumpPort, setJumpPort] = useState(String(cur.jumpPort ?? 51820));
  const [requireOverlay, setRequireOverlay] = useState(Boolean(cur.requireOverlay));
  const [saved, setSaved] = useState(false);

  const save = useMutation({
    mutationFn: () => setSetting("wireguard", {
      jumpHost: jumpHost.trim(), jumpPort: Number(jumpPort) || 51820, requireOverlay,
    }),
    onSuccess: () => { setSaved(true); void qc.invalidateQueries({ queryKey: ["settings"] }); void qc.invalidateQueries({ queryKey: ["next-wg"] }); },
  });

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">VPN server (jump host)</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Public address managed hosts use to reach the jump host. Used as the default when
        enrolling hosts (overridable per host). Must be reachable from the hosts on UDP.
      </Typography>
      <OverlayPlans />
      <Stack direction="row" spacing={2} alignItems="flex-start">
        <TextField
          label="Server name / IP" value={jumpHost}
          onChange={(e) => { setJumpHost(e.target.value); setSaved(false); }}
          placeholder="vpn.example.com" sx={{ flexGrow: 1 }}
        />
        <TextField
          label="WireGuard port" type="number" value={jumpPort}
          onChange={(e) => { setJumpPort(e.target.value); setSaved(false); }}
          sx={{ width: 150 }}
          helperText="OpenVPN's port is set by FLEET_OVPN_PORT"
        />
        <Button variant="contained" sx={{ mt: 1 }} disabled={save.isPending || !jumpHost.trim()} onClick={() => save.mutate()}>
          {saved ? "Saved" : "Save"}
        </Button>
      </Stack>
      <FormControlLabel
        sx={{ mt: 1.5 }}
        control={
          <Switch
            checked={requireOverlay}
            onChange={(e) => { setRequireOverlay(e.target.checked); setSaved(false); }}
          />
        }
        label="Strict overlay — require the VPN overlay for connections"
      />
      <Typography variant="body2" color="text.secondary" sx={{ ml: 0.5 }}>
        When on, an enrolled host that has an overlay address is reachable only over its overlay —
        WireGuard or OpenVPN, whichever it was enrolled onto. If its tunnel is down, connections are
        refused instead of quietly falling back to the host's direct network address; this covers
        terminal and file transfer (Linux/SSH) as well as desktop (Windows/RDP) sessions. Hosts with
        no overlay address are unaffected.
      </Typography>
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
  const { data: loaded, isError, refetch } = useQuery({ queryKey: ["oidc-config"], queryFn: getOidcConfig });
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

  if (isError) {
    return (
      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6" gutterBottom>Single sign-on (OIDC)</Typography>
        <Alert severity="error" action={<Button size="small" onClick={() => void refetch()}>Retry</Button>}>
          Couldn't load the current configuration. If you just updated Blackfriars, hard-refresh the page
          (Ctrl/Cmd-Shift-R) to clear a cached bundle, then retry.
        </Alert>
      </Paper>
    );
  }
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

// SAMLCard configures SAML 2.0 single sign-on (SP side). The admin registers the
// IdP's entity ID, SSO URL, and signing certificate; Fleet exposes the ACS,
// entity ID, and metadata URL the IdP needs in return.
function SAMLCard() {
  const { data: loaded, isError, refetch } = useQuery({ queryKey: ["saml-config"], queryFn: getSamlConfig });
  const [cfg, setCfg] = useState<SamlConfig | null>(null);
  const [groupMap, setGroupMap] = useState("");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (loaded && !cfg) {
      setCfg({ ...loaded.config });
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
      return saveSamlConfig({ ...(cfg as SamlConfig), groupRoleMap });
    },
    onSuccess: () => setSaved(true),
  });

  if (isError) {
    return (
      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6" gutterBottom>Single sign-on (SAML)</Typography>
        <Alert severity="error" action={<Button size="small" onClick={() => void refetch()}>Retry</Button>}>
          Couldn't load the current configuration. If you just updated Blackfriars, hard-refresh the page
          (Ctrl/Cmd-Shift-R) to clear a cached bundle, then retry.
        </Alert>
      </Paper>
    );
  }
  if (!cfg) {
    return (
      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6">Single sign-on (SAML)</Typography>
        <Typography variant="body2" color="text.secondary">Loading…</Typography>
      </Paper>
    );
  }
  const set = (patch: Partial<SamlConfig>) => { setCfg({ ...cfg, ...patch }); setSaved(false); };

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Single sign-on (SAML)</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Let users sign in via a SAML 2.0 identity provider (Okta, Azure AD, OneLogin, ADFS…).
        Register these values in your IdP:
      </Typography>
      <Stack spacing={0.5} sx={{ mb: 1.5, fontSize: "0.85rem" }}>
        <Box>ACS (Reply) URL: <code>{loaded?.acsUrl}</code></Box>
        <Box>SP Entity ID / Audience: <code>{loaded?.spEntityId}</code></Box>
        <Box>SP metadata: <code>{loaded?.metadataUrl}</code></Box>
      </Stack>
      <FormControlLabel
        control={<Switch checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} />}
        label="Enable SAML sign-on"
      />
      {cfg.enabled && (
        <Stack spacing={1.5} sx={{ mt: 1 }}>
          <TextField label="IdP Entity ID (issuer)" size="small" value={cfg.idpEntityId}
            onChange={(e) => set({ idpEntityId: e.target.value })} placeholder="https://idp.example.com/saml/metadata" />
          <TextField label="IdP SSO URL (redirect binding)" size="small" value={cfg.idpSsoUrl}
            onChange={(e) => set({ idpSsoUrl: e.target.value })} placeholder="https://idp.example.com/sso/saml" />
          <TextField label="IdP signing certificate (PEM or base64)" size="small" multiline minRows={3}
            value={cfg.idpCertificate} onChange={(e) => set({ idpCertificate: e.target.value })}
            placeholder={"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"} />
          <Stack direction="row" spacing={1.5}>
            <TextField label="Button text" size="small" value={cfg.buttonText ?? ""}
              onChange={(e) => set({ buttonText: e.target.value })} sx={{ flexGrow: 1 }} placeholder="Sign in with SAML" />
            <TextField label="Default role (new users)" size="small" value={cfg.defaultRole ?? ""}
              onChange={(e) => set({ defaultRole: e.target.value })} sx={{ flexGrow: 1 }} placeholder="Read-Only" />
          </Stack>
          <Stack direction="row" spacing={1.5}>
            <TextField label="Username attribute" size="small" value={cfg.usernameAttr ?? ""}
              onChange={(e) => set({ usernameAttr: e.target.value })} sx={{ flexGrow: 1 }} placeholder="(NameID if blank)" />
            <TextField label="Email attribute" size="small" value={cfg.emailAttr ?? ""}
              onChange={(e) => set({ emailAttr: e.target.value })} sx={{ flexGrow: 1 }} placeholder="email" />
            <TextField label="Groups attribute" size="small" value={cfg.groupsAttr ?? ""}
              onChange={(e) => set({ groupsAttr: e.target.value })} sx={{ flexGrow: 1 }} placeholder="groups" />
          </Stack>
          <FormControlLabel
            control={<Switch checked={cfg.autoProvision} onChange={(e) => set({ autoProvision: e.target.checked })} />}
            label="Auto-provision new users on first sign-in (off = require SCIM/admin to create the account first)"
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

// SCIMCard manages SCIM 2.0 provisioning: issue/revoke the bearer token an IdP
// uses to create, update, and deprovision Fleet accounts automatically.
function SCIMCard() {
  const qc = useQueryClient();
  const { data: cfg } = useQuery({ queryKey: ["scim-config"], queryFn: getScimConfig });
  const [defaultRole, setDefaultRole] = useState<string | null>(null);
  const [authSource, setAuthSource] = useState<string | null>(null);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const role = defaultRole ?? cfg?.defaultRole ?? "Read-Only";
  const src = authSource ?? cfg?.authSource ?? "saml";

  const save = useMutation({
    mutationFn: () => saveScimConfig({ enabled: cfg?.enabled ?? false, defaultRole: role, authSource: src }),
    onSuccess: () => { setSaved(true); qc.invalidateQueries({ queryKey: ["scim-config"] }); },
  });
  const issue = useMutation({
    mutationFn: issueScimToken,
    onSuccess: (d) => { setNewToken(d.token); qc.invalidateQueries({ queryKey: ["scim-config"] }); },
  });
  const revoke = useMutation({
    mutationFn: revokeScimToken,
    onSuccess: () => { setNewToken(null); qc.invalidateQueries({ queryKey: ["scim-config"] }); },
  });

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Provisioning (SCIM 2.0)</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Let your identity provider create, update, and — importantly — deprovision Blackfriars accounts
        automatically. Pairs with SAML SSO: SCIM manages the account lifecycle, SAML authenticates the
        login. Point your IdP's SCIM connector at the base URL below with the bearer token.
      </Typography>
      <Box sx={{ mb: 1.5, fontSize: "0.85rem" }}>
        SCIM base URL: <code>{cfg?.baseUrl}</code>
      </Box>

      <Stack direction="row" spacing={1.5} sx={{ mb: 1.5 }}>
        <TextField label="Default role (provisioned users)" size="small" value={role}
          onChange={(e) => { setDefaultRole(e.target.value); setSaved(false); }} sx={{ flexGrow: 1 }} placeholder="Read-Only" />
        <TextField select label="Sign-in method" size="small" value={src}
          onChange={(e) => { setAuthSource(e.target.value); setSaved(false); }} sx={{ width: 180 }}
          helperText="AuthSource for new users">
          <MenuItem value="saml">SAML</MenuItem>
          <MenuItem value="oidc">OIDC</MenuItem>
          <MenuItem value="ldap">LDAP</MenuItem>
        </TextField>
        <Button variant="outlined" disabled={save.isPending} onClick={() => save.mutate()} sx={{ height: 40 }}>
          {saved ? "Saved" : "Save"}
        </Button>
      </Stack>

      {newToken && (
        <Alert severity="success" sx={{ mb: 1.5 }} onClose={() => setNewToken(null)}>
          Token issued — copy it now, it will not be shown again:
          <Box component="code" sx={{ display: "block", mt: 0.5, wordBreak: "break-all", fontSize: "0.8rem" }}>{newToken}</Box>
        </Alert>
      )}

      <Stack direction="row" spacing={1.5} alignItems="center">
        <Button variant="contained" disabled={issue.isPending} onClick={() => issue.mutate()}>
          {cfg?.tokenSet ? "Reissue token" : "Issue token"}
        </Button>
        {cfg?.tokenSet && (
          <Button color="error" disabled={revoke.isPending} onClick={() => { if (window.confirm("Revoke the SCIM token? Provisioning will stop until a new token is issued.")) revoke.mutate(); }}>
            Revoke token
          </Button>
        )}
        <Typography variant="body2" color="text.secondary">
          {cfg?.tokenSet ? (cfg.enabled ? "Provisioning active." : "Token set (disabled).") : "No token issued."}
        </Typography>
      </Stack>
    </Paper>
  );
}

// LDAPCard configures LDAP / Active Directory authentication. Users sign in on
// the normal form with their directory credentials; accounts are provisioned
// from directory attributes and group→role mappings.
function LDAPCard() {
  const { data: loaded, isError, refetch } = useQuery({ queryKey: ["ldap-config"], queryFn: getLdapConfig });
  const [cfg, setCfg] = useState<LdapConfig | null>(null);
  const [groupMap, setGroupMap] = useState("");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (loaded && !cfg) {
      setCfg({ ...loaded.config, bindPassword: "" });
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
      return saveLdapConfig({ ...(cfg as LdapConfig), groupRoleMap });
    },
    onSuccess: () => setSaved(true),
  });

  if (isError) {
    return (
      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6" gutterBottom>LDAP / Active Directory</Typography>
        <Alert severity="error" action={<Button size="small" onClick={() => void refetch()}>Retry</Button>}>
          Couldn't load the current configuration. If you just updated Blackfriars, hard-refresh the page
          (Ctrl/Cmd-Shift-R) to clear a cached bundle, then retry.
        </Alert>
      </Paper>
    );
  }
  if (!cfg) {
    return (
      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6">LDAP / Active Directory</Typography>
        <Typography variant="body2" color="text.secondary">Loading…</Typography>
      </Paper>
    );
  }
  const set = (patch: Partial<LdapConfig>) => { setCfg({ ...cfg, ...patch }); setSaved(false); };

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">LDAP / Active Directory</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Let users sign in with their directory credentials on the normal sign-in form. A service
        account looks up the user, then their password is verified by a bind.
      </Typography>
      <FormControlLabel
        control={<Switch checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} />}
        label="Enable LDAP/AD sign-on"
      />
      {cfg.enabled && (
        <Stack spacing={1.5} sx={{ mt: 1 }}>
          <Stack direction="row" spacing={1.5}>
            <TextField label="Server URL" size="small" value={cfg.url}
              onChange={(e) => set({ url: e.target.value })} sx={{ flexGrow: 1 }}
              placeholder="ldaps://dc.example.com:636" />
            <FormControlLabel control={<Switch checked={cfg.startTls} onChange={(e) => set({ startTls: e.target.checked })} />}
              label="StartTLS" />
          </Stack>
          <Stack direction="row" spacing={1.5}>
            <TextField label="Bind DN (service account)" size="small" value={cfg.bindDn}
              onChange={(e) => set({ bindDn: e.target.value })} sx={{ flexGrow: 1 }}
              placeholder="CN=svc-fleet,OU=Service,DC=example,DC=com" />
            <TextField label="Bind password" size="small" type="password" value={cfg.bindPassword ?? ""}
              onChange={(e) => set({ bindPassword: e.target.value })} sx={{ flexGrow: 1 }} autoComplete="new-password"
              placeholder={loaded?.secretSet ? "•••••••• (unchanged)" : ""} />
          </Stack>
          <Stack direction="row" spacing={1.5}>
            <TextField label="Base DN" size="small" value={cfg.baseDn}
              onChange={(e) => set({ baseDn: e.target.value })} sx={{ flexGrow: 1 }}
              placeholder="OU=Users,DC=example,DC=com" />
            <TextField label="User filter (%s = username)" size="small" value={cfg.userFilter ?? ""}
              onChange={(e) => set({ userFilter: e.target.value })} sx={{ flexGrow: 1 }}
              placeholder="(sAMAccountName=%s)" />
          </Stack>
          <Stack direction="row" spacing={1.5}>
            <TextField label="Username attr" size="small" value={cfg.usernameAttr ?? ""}
              onChange={(e) => set({ usernameAttr: e.target.value })} sx={{ flexGrow: 1 }} placeholder="sAMAccountName" />
            <TextField label="Email attr" size="small" value={cfg.emailAttr ?? ""}
              onChange={(e) => set({ emailAttr: e.target.value })} sx={{ flexGrow: 1 }} placeholder="mail" />
            <TextField label="Groups attr" size="small" value={cfg.groupsAttr ?? ""}
              onChange={(e) => set({ groupsAttr: e.target.value })} sx={{ flexGrow: 1 }} placeholder="memberOf" />
          </Stack>
          <Stack direction="row" spacing={1.5} alignItems="center">
            <TextField label="Default role (new users)" size="small" value={cfg.defaultRole ?? ""}
              onChange={(e) => set({ defaultRole: e.target.value })} sx={{ width: 220 }} placeholder="Read-Only" />
            <FormControlLabel control={<Switch checked={cfg.autoProvision} onChange={(e) => set({ autoProvision: e.target.checked })} />}
              label="Auto-provision new users" />
          </Stack>
          <TextField label="Group → role mappings (one per line: GroupCN=FleetRole)" size="small" multiline minRows={2}
            value={groupMap} onChange={(e) => { setGroupMap(e.target.value); setSaved(false); }}
            placeholder={"Domain Admins=Administrator\nFleet-Operators=Operator"} />
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

const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

// DigestCard configures the recurring fleet-health digest. The cadence lives here;
// delivery is via the notification channels above — route the "Scheduled
// fleet-health digest" event to email/webhook there for it to actually send.
function DigestCard() {
  const qc = useQueryClient();
  const { data: loaded } = useQuery({ queryKey: ["digest"], queryFn: getDigest });
  const [p, setP] = useState<DigestPolicy | null>(null);
  const [saved, setSaved] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);
  const [sentMsg, setSentMsg] = useState<string | null>(null);

  useEffect(() => {
    if (loaded && !p) setP(loaded);
  }, [loaded, p]);

  const save = useMutation({
    mutationFn: () => saveDigest(p as DigestPolicy),
    onSuccess: () => { setSaved(true); void qc.invalidateQueries({ queryKey: ["digest"] }); },
  });
  const doPreview = useMutation({
    mutationFn: previewDigest,
    onSuccess: (r) => setPreview(r.body),
  });
  const doSend = useMutation({
    mutationFn: sendDigest,
    onSuccess: () => setSentMsg("Digest sent to the configured channels (if the event is routed)."),
    onError: () => setSentMsg("Send failed."),
  });

  if (!p) {
    return (
      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6">Fleet-health digest</Typography>
        <Typography variant="body2" color="text.secondary">Loading…</Typography>
      </Paper>
    );
  }

  const set = (patch: Partial<DigestPolicy>) => { setP({ ...p, ...patch }); setSaved(false); setSentMsg(null); };

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Fleet-health digest</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        A recurring summary of what needs attention across the fleet — offline hosts, low disk,
        capacity runway, high load, pending security updates. It is delivered through the channels
        above: route the <b>Scheduled fleet-health digest</b> event to email or webhook in
        Notifications for it to send.
      </Typography>

      <FormControlLabel
        control={<Switch checked={p.enabled} onChange={(e) => set({ enabled: e.target.checked })} />}
        label="Send a scheduled digest"
      />

      <Stack direction="row" spacing={2} sx={{ mt: 1, flexWrap: "wrap" }}>
        <TextField
          select size="small" label="Frequency" value={p.frequency} sx={{ minWidth: 140 }}
          disabled={!p.enabled} onChange={(e) => set({ frequency: e.target.value as DigestPolicy["frequency"] })}
        >
          <MenuItem value="daily">Daily</MenuItem>
          <MenuItem value="weekly">Weekly</MenuItem>
        </TextField>
        {p.frequency === "weekly" && (
          <TextField
            select size="small" label="Day" value={p.weekday} sx={{ minWidth: 140 }}
            disabled={!p.enabled} onChange={(e) => set({ weekday: Number(e.target.value) })}
          >
            {WEEKDAYS.map((d, i) => <MenuItem key={d} value={i}>{d}</MenuItem>)}
          </TextField>
        )}
        <TextField
          select size="small" label="Hour (server time)" value={p.hour} sx={{ minWidth: 160 }}
          disabled={!p.enabled} onChange={(e) => set({ hour: Number(e.target.value) })}
        >
          {Array.from({ length: 24 }, (_, h) => (
            <MenuItem key={h} value={h}>{String(h).padStart(2, "0")}:00</MenuItem>
          ))}
        </TextField>
      </Stack>

      <Stack direction="row" spacing={1} sx={{ mt: 2 }} alignItems="center" flexWrap="wrap">
        <Button variant="contained" onClick={() => save.mutate()} disabled={save.isPending}>Save</Button>
        <Button onClick={() => doPreview.mutate()} disabled={doPreview.isPending}>Preview</Button>
        <Button onClick={() => doSend.mutate()} disabled={doSend.isPending}>Send now</Button>
        {saved && <Alert severity="success" sx={{ py: 0 }}>Saved.</Alert>}
        {sentMsg && <Typography variant="body2" color="text.secondary">{sentMsg}</Typography>}
      </Stack>

      {preview != null && (
        <Box
          component="pre"
          sx={{
            mt: 2, p: 1.5, bgcolor: "action.hover", borderRadius: 1, whiteSpace: "pre-wrap",
            fontFamily: "monospace", fontSize: 13, overflowX: "auto",
          }}
        >
          {preview || "No issues detected — all monitored hosts look healthy."}
        </Box>
      )}
    </Paper>
  );
}

const REPORT_KINDS = [
  { key: "access", label: "Access report" },
  { key: "audit", label: "Audit trail" },
  { key: "certificates", label: "Certificate issuance" },
  { key: "scans", label: "Scan posture" },
];

// ReportScheduleCard configures recurring delivery of compliance CSV reports. The
// cadence lives here; delivery is via the notification channels above — route the
// "Scheduled compliance report" event to email (reports attach as CSV files).
function ReportScheduleCard() {
  const qc = useQueryClient();
  const { data: loaded } = useQuery({ queryKey: ["report-schedule"], queryFn: getReportSchedule });
  const [p, setP] = useState<ReportSchedule | null>(null);
  const [saved, setSaved] = useState(false);
  const [sentMsg, setSentMsg] = useState<string | null>(null);

  useEffect(() => { if (loaded && !p) setP(loaded); }, [loaded, p]);

  const save = useMutation({
    mutationFn: () => saveReportSchedule(p as ReportSchedule),
    onSuccess: () => { setSaved(true); void qc.invalidateQueries({ queryKey: ["report-schedule"] }); },
  });
  const send = useMutation({
    mutationFn: sendReportScheduleNow,
    onSuccess: () => setSentMsg("Reports sent to the configured channels (if the event is routed to email)."),
    onError: () => setSentMsg("Send failed."),
  });

  if (!p) {
    return (
      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6">Scheduled compliance reports</Typography>
        <Typography variant="body2" color="text.secondary">Loading…</Typography>
      </Paper>
    );
  }

  const set = (patch: Partial<ReportSchedule>) => { setP({ ...p, ...patch }); setSaved(false); setSentMsg(null); };
  const toggleReport = (key: string, on: boolean) =>
    set({ reports: on ? [...p.reports, key] : p.reports.filter((k) => k !== key) });

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6">Scheduled compliance reports</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 1.5 }}>
        Deliver the selected evidence reports as CSV attachments on a schedule (for access reviews and
        SOC 2 / ISO / PCI audits). Route the <b>Scheduled compliance report</b> event to email in
        Notifications above for delivery.
      </Typography>

      <FormControlLabel
        control={<Switch checked={p.enabled} onChange={(e) => set({ enabled: e.target.checked })} />}
        label="Send reports on a schedule"
      />

      <Box sx={{ my: 1 }}>
        <Typography variant="body2" sx={{ mb: 0.5 }}>Reports to include</Typography>
        <Stack direction="row" flexWrap="wrap">
          {REPORT_KINDS.map((rk) => (
            <FormControlLabel key={rk.key}
              control={<Checkbox size="small" checked={p.reports.includes(rk.key)}
                disabled={!p.enabled} onChange={(e) => toggleReport(rk.key, e.target.checked)} />}
              label={rk.label} />
          ))}
        </Stack>
      </Box>

      <Stack direction="row" spacing={2} sx={{ mt: 1 }} flexWrap="wrap">
        <TextField select size="small" label="Frequency" value={p.frequency} sx={{ minWidth: 130 }}
          disabled={!p.enabled} onChange={(e) => set({ frequency: e.target.value as ReportSchedule["frequency"] })}>
          <MenuItem value="weekly">Weekly</MenuItem>
          <MenuItem value="monthly">Monthly</MenuItem>
        </TextField>
        {p.frequency === "weekly" ? (
          <TextField select size="small" label="Day" value={p.weekday} sx={{ minWidth: 130 }}
            disabled={!p.enabled} onChange={(e) => set({ weekday: Number(e.target.value) })}>
            {WEEKDAYS.map((d, i) => <MenuItem key={d} value={i}>{d}</MenuItem>)}
          </TextField>
        ) : (
          <TextField select size="small" label="Day of month" value={p.dayOfMonth} sx={{ minWidth: 130 }}
            disabled={!p.enabled} onChange={(e) => set({ dayOfMonth: Number(e.target.value) })}>
            {Array.from({ length: 28 }, (_, i) => <MenuItem key={i + 1} value={i + 1}>{i + 1}</MenuItem>)}
          </TextField>
        )}
        <TextField select size="small" label="Hour" value={p.hour} sx={{ minWidth: 120 }}
          disabled={!p.enabled} onChange={(e) => set({ hour: Number(e.target.value) })}>
          {Array.from({ length: 24 }, (_, h) => <MenuItem key={h} value={h}>{String(h).padStart(2, "0")}:00</MenuItem>)}
        </TextField>
        <TextField type="number" size="small" label="Lookback (days)" value={p.lookbackDays}
          disabled={!p.enabled} sx={{ width: 140 }}
          onChange={(e) => set({ lookbackDays: Math.max(1, Number(e.target.value) || 1) })} />
      </Stack>

      <Stack direction="row" spacing={1} sx={{ mt: 2 }} alignItems="center" flexWrap="wrap">
        <Button variant="contained" onClick={() => save.mutate()} disabled={save.isPending}>Save</Button>
        <Button onClick={() => send.mutate()} disabled={send.isPending || p.reports.length === 0}>Send now</Button>
        {saved && <Alert severity="success" sx={{ py: 0 }}>Saved.</Alert>}
        {sentMsg && <Typography variant="body2" color="text.secondary">{sentMsg}</Typography>}
      </Stack>
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
        pagerduty: {
          enabled: loaded.pagerduty?.enabled ?? false,
          minSeverity: loaded.pagerduty?.minSeverity || "warning",
        },
        opsgenie: {
          enabled: loaded.opsgenie?.enabled ?? false,
          region: loaded.opsgenie?.region || "us",
          minSeverity: loaded.opsgenie?.minSeverity || "warning",
        },
        events: loaded.events ?? {},
        throttleMinutes: loaded.throttleMinutes || 5,
        passwordSet: loaded.passwordSet,
        pagerdutyKeySet: loaded.pagerdutyKeySet,
        opsgenieKeySet: loaded.opsgenieKeySet,
      });
    }
  }, [loaded, cfg]);

  const save = useMutation({
    mutationFn: () => saveNotifications(cfg as NotificationConfig),
    onSuccess: () => { setSaved(true); void qc.invalidateQueries({ queryKey: ["notifications"] }); },
  });
  const test = useMutation({
    mutationFn: (channel: "email" | "webhook" | "pagerduty" | "opsgenie") => testNotification(channel),
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
  const setPager = (patch: Partial<NotificationConfig["pagerduty"]>) => { setCfg({ ...cfg, pagerduty: { ...cfg.pagerduty, ...patch } }); dirty(); };
  const setOpsgenie = (patch: Partial<NotificationConfig["opsgenie"]>) => { setCfg({ ...cfg, opsgenie: { ...cfg.opsgenie, ...patch } }); dirty(); };
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
              <MenuItem value="teams">Microsoft Teams</MenuItem>
            </TextField>
          </Stack>
          <Box>
            <Button size="small" variant="outlined" disabled={test.isPending} onClick={() => test.mutate("webhook")}>
              Send test webhook
            </Button>
          </Box>
        </Stack>
      )}

      <Divider sx={{ my: 1.5 }} />

      {/* PagerDuty — incident channel, severity-gated (not per-event). */}
      <FormControlLabel
        control={<Switch checked={cfg.pagerduty.enabled} onChange={(e) => setPager({ enabled: e.target.checked })} />}
        label="PagerDuty"
      />
      {cfg.pagerduty.enabled && (
        <Stack spacing={1.5} sx={{ ml: 4, mb: 1 }}>
          <Stack direction="row" spacing={1} flexWrap="wrap">
            <TextField label={cfg.pagerdutyKeySet ? "Routing key (set — leave blank to keep)" : "Integration/Routing key"}
              size="small" type="password" value={cfg.pagerduty.routingKey ?? ""}
              onChange={(e) => setPager({ routingKey: e.target.value })} sx={{ flexGrow: 1, minWidth: 240 }} />
            <TextField label="Page on" size="small" select value={cfg.pagerduty.minSeverity} sx={{ width: 160 }}
              onChange={(e) => setPager({ minSeverity: e.target.value })}>
              <MenuItem value="error">Errors only</MenuItem>
              <MenuItem value="warning">Warnings &amp; errors</MenuItem>
              <MenuItem value="info">Everything</MenuItem>
            </TextField>
          </Stack>
          <Box>
            <Button size="small" variant="outlined" disabled={test.isPending} onClick={() => test.mutate("pagerduty")}>
              Send test page
            </Button>
          </Box>
        </Stack>
      )}

      <Divider sx={{ my: 1.5 }} />

      {/* Opsgenie — incident channel, severity-gated. */}
      <FormControlLabel
        control={<Switch checked={cfg.opsgenie.enabled} onChange={(e) => setOpsgenie({ enabled: e.target.checked })} />}
        label="Opsgenie"
      />
      {cfg.opsgenie.enabled && (
        <Stack spacing={1.5} sx={{ ml: 4, mb: 1 }}>
          <Stack direction="row" spacing={1} flexWrap="wrap">
            <TextField label={cfg.opsgenieKeySet ? "API key (set — leave blank to keep)" : "API key"}
              size="small" type="password" value={cfg.opsgenie.apiKey ?? ""}
              onChange={(e) => setOpsgenie({ apiKey: e.target.value })} sx={{ flexGrow: 1, minWidth: 220 }} />
            <TextField label="Region" size="small" select value={cfg.opsgenie.region} sx={{ width: 110 }}
              onChange={(e) => setOpsgenie({ region: e.target.value })}>
              <MenuItem value="us">US</MenuItem>
              <MenuItem value="eu">EU</MenuItem>
            </TextField>
            <TextField label="Alert on" size="small" select value={cfg.opsgenie.minSeverity} sx={{ width: 160 }}
              onChange={(e) => setOpsgenie({ minSeverity: e.target.value })}>
              <MenuItem value="error">Errors only</MenuItem>
              <MenuItem value="warning">Warnings &amp; errors</MenuItem>
              <MenuItem value="info">Everything</MenuItem>
            </TextField>
          </Stack>
          <Box>
            <Button size="small" variant="outlined" disabled={test.isPending} onClick={() => test.mutate("opsgenie")}>
              Send test alert
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
