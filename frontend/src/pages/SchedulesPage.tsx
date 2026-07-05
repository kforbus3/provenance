import { useEffect, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  FormControlLabel, IconButton, MenuItem, Paper, Snackbar, Stack, Switch, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, TextField, ToggleButton, ToggleButtonGroup, Tooltip,
  Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createSchedule, deleteSchedule, listSchedules, runScheduleNow, setScheduleEnabled,
  updateSchedule, type Recurrence, type Schedule,
} from "../api/schedules";
import { listHosts, type Host } from "../api/hosts";
import { listGroups, type Group } from "../api/admin";
import { listPlaybooks, type Playbook } from "../api/playbooks";
import { listScanProfiles } from "../api/scans";
import { formatDateTime } from "../lib/datetime";

const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

function recurrenceText(r: Recurrence): string {
  switch (r.type) {
    case "interval": return `Every ${r.everyMinutes ?? 60} min`;
    case "daily": return `Daily at ${r.timeOfDay ?? "00:00"}`;
    case "weekly": return `${WEEKDAYS[r.weekday ?? 0]} at ${r.timeOfDay ?? "00:00"}`;
    default: return "—";
  }
}

// Recurring scans and playbook runs. Disabled by default; enable one to start it.
export function SchedulesPage() {
  const qc = useQueryClient();
  const { data: schedules = [], isLoading } = useQuery({ queryKey: ["schedules"], queryFn: listSchedules });
  const [editor, setEditor] = useState<Schedule | "new" | null>(null);
  const [toast, setToast] = useState<{ msg: string; severity: "success" | "warning" | "error" } | null>(null);
  const invalidate = () => qc.invalidateQueries({ queryKey: ["schedules"] });

  const enableMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => setScheduleEnabled(id, enabled),
    onSuccess: invalidate,
  });
  const deleteMut = useMutation({ mutationFn: (id: string) => deleteSchedule(id), onSuccess: invalidate });
  const runMut = useMutation({
    mutationFn: (id: string) => runScheduleNow(id),
    onSuccess: (res) => {
      invalidate();
      // Fire returns a short status: "started" on success, otherwise a reason
      // like "skipped: no hosts" or "error: …". Surface it so a no-op is visible.
      const status = res?.status ?? "";
      const ok = status === "started";
      setToast({
        msg: ok ? "Run started — see the Scans / Playbooks page for progress." : `Not run — ${status || "unknown result"}`,
        severity: ok ? "success" : status.startsWith("error") ? "error" : "warning",
      });
    },
    onError: (e) => setToast({ msg: (e as Error).message || "Run failed", severity: "error" }),
  });

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>Schedules</Typography>
        <Button startIcon={<AddIcon />} variant="contained" onClick={() => setEditor("new")}>
          New Schedule
        </Button>
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Run scans or playbooks on a recurring basis. New schedules are disabled until you turn them
        on. Times use the app's configured timezone (set it in Settings → Time zone).
      </Typography>

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>On</TableCell>
              <TableCell>Name</TableCell>
              <TableCell>Kind</TableCell>
              <TableCell>Target</TableCell>
              <TableCell>Recurrence</TableCell>
              <TableCell>Next run</TableCell>
              <TableCell>Last</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {schedules.map((s) => (
              <TableRow key={s.id} hover>
                <TableCell>
                  <Switch size="small" checked={s.enabled}
                    onChange={(e) => enableMut.mutate({ id: s.id, enabled: e.target.checked })} />
                </TableCell>
                <TableCell>{s.name}</TableCell>
                <TableCell><Chip size="small" label={s.kind} /></TableCell>
                <TableCell>{s.targetName} <Typography component="span" variant="caption" color="text.secondary">({s.targetKind})</Typography></TableCell>
                <TableCell>{recurrenceText(s.recurrence)}</TableCell>
                <TableCell sx={{ color: "text.secondary" }}>
                  {s.enabled && s.nextRunAt
                    ? formatDateTime(s.nextRunAt, { timeZoneName: "short" })
                    : "—"}
                </TableCell>
                <TableCell sx={{ color: "text.secondary" }}>
                  {s.lastRunAt ? `${formatDateTime(s.lastRunAt)} (${s.lastStatus})` : "never"}
                </TableCell>
                <TableCell align="right">
                  <Tooltip title="Run now">
                    <span>
                      <IconButton size="small" color="primary" disabled={runMut.isPending}
                        onClick={() => runMut.mutate(s.id)}>
                        <PlayArrowIcon fontSize="small" />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip title="Edit">
                    <IconButton size="small" onClick={() => setEditor(s)}><EditIcon fontSize="small" /></IconButton>
                  </Tooltip>
                  <Tooltip title="Delete">
                    <IconButton size="small"
                      onClick={() => { if (confirm(`Delete schedule "${s.name}"?`)) deleteMut.mutate(s.id); }}>
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {!isLoading && schedules.length === 0 && (
              <TableRow>
                <TableCell colSpan={8} align="center" sx={{ color: "text.secondary", py: 4 }}>
                  No schedules yet.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {editor && (
        <ScheduleEditor
          schedule={editor === "new" ? null : editor}
          onClose={() => setEditor(null)}
          onSaved={() => { setEditor(null); invalidate(); }}
        />
      )}

      <Snackbar
        open={toast !== null} autoHideDuration={5000} onClose={() => setToast(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      >
        {toast ? (
          <Alert severity={toast.severity} onClose={() => setToast(null)} variant="filled">
            {toast.msg}
          </Alert>
        ) : undefined}
      </Snackbar>
    </Box>
  );
}

function ScheduleEditor({ schedule, onClose, onSaved }: { schedule: Schedule | null; onClose: () => void; onSaved: () => void }) {
  const isNew = schedule === null;
  const { data: hostData } = useQuery({ queryKey: ["hosts"], queryFn: listHosts });
  const { data: groups = [] } = useQuery({ queryKey: ["groups"], queryFn: listGroups });
  const { data: playbooks = [] } = useQuery({ queryKey: ["playbooks"], queryFn: listPlaybooks });
  const hosts = hostData?.hosts ?? [];

  const [name, setName] = useState(schedule?.name ?? "");
  const [kind, setKind] = useState<"scan" | "playbook">(schedule?.kind ?? "scan");
  const [targetKind, setTargetKind] = useState<"host" | "group">(schedule?.targetKind ?? "host");
  const [host, setHost] = useState<Host | null>(null);
  const [group, setGroup] = useState<Group | null>(null);
  const [enabled, setEnabled] = useState(schedule?.enabled ?? false);

  // recurrence
  const [recType, setRecType] = useState<Recurrence["type"]>(schedule?.recurrence.type ?? "daily");
  const [everyMinutes, setEveryMinutes] = useState(String(schedule?.recurrence.everyMinutes ?? 60));
  const [timeOfDay, setTimeOfDay] = useState(schedule?.recurrence.timeOfDay ?? "02:00");
  const [weekday, setWeekday] = useState(schedule?.recurrence.weekday ?? 0);

  // payload
  const initPayload = (schedule?.payload ?? {}) as Record<string, unknown>;
  const [profile, setProfile] = useState(String(initPayload.profile ?? ""));
  const [skipFs, setSkipFs] = useState(Boolean(initPayload.skipExpensiveFsRules));
  const [playbook, setPlaybook] = useState<Playbook | null>(null);
  const [checkMode, setCheckMode] = useState(initPayload.checkMode !== false);

  // hydrate target/playbook selections once data arrives
  useEffect(() => {
    if (schedule?.targetId && targetKind === "host" && !host) {
      const h = hosts.find((x) => x.id === schedule.targetId);
      if (h) setHost(h);
    }
    if (schedule?.targetId && targetKind === "group" && !group) {
      const g = groups.find((x) => x.id === schedule.targetId);
      if (g) setGroup(g);
    }
    if (kind === "playbook" && !playbook && initPayload.playbookId) {
      const p = playbooks.find((x) => x.id === initPayload.playbookId);
      if (p) setPlaybook(p);
    }
  }, [hosts, groups, playbooks]); // eslint-disable-line react-hooks/exhaustive-deps

  // For a scan schedule, discover available profiles from the target host (or a
  // member of the target group) so the user can pick from a dropdown.
  const repHostId =
    targetKind === "host"
      ? host?.id
      : hosts.find((h) => (h.groups ?? []).includes(group?.name ?? ""))?.id;
  const { data: prof, isLoading: profLoading } = useQuery({
    queryKey: ["scan-profiles", repHostId],
    queryFn: () => listScanProfiles(repHostId as string),
    enabled: kind === "scan" && !!repHostId,
  });

  const recurrence = (): Recurrence => {
    if (recType === "interval") return { type: "interval", everyMinutes: Number(everyMinutes) || 60 };
    if (recType === "weekly") return { type: "weekly", weekday, timeOfDay };
    return { type: "daily", timeOfDay };
  };
  const payload = () =>
    kind === "scan"
      ? { profile: profile.trim(), skipExpensiveFsRules: skipFs, skipRules: [] }
      : { playbookId: playbook?.id ?? "", checkMode };

  const targetId = targetKind === "host" ? host?.id : group?.id;
  const playbookOk = kind !== "playbook" || !!playbook;

  const save = useMutation({
    mutationFn: () => {
      const input = {
        name: name.trim(), kind, enabled, targetKind, targetId: targetId as string,
        recurrence: recurrence(), payload: payload(),
      };
      return isNew ? createSchedule(input) : updateSchedule(schedule!.id, input);
    },
    onSuccess: onSaved,
  });

  return (
    <Dialog open fullWidth maxWidth="sm" onClose={onClose}>
      <DialogTitle>{isNew ? "New Schedule" : "Edit Schedule"}</DialogTitle>
      <DialogContent dividers>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <TextField label="Name" size="small" value={name} onChange={(e) => setName(e.target.value)} autoFocus fullWidth />

          <TextField label="What to run" size="small" select value={kind} onChange={(e) => setKind(e.target.value as "scan" | "playbook")}>
            <MenuItem value="scan">Security scan</MenuItem>
            <MenuItem value="playbook">Ansible playbook</MenuItem>
          </TextField>

          {kind === "scan" ? (
            <Stack direction="row" spacing={2} alignItems="center">
              <TextField
                select label="Profile" size="small" value={profile}
                onChange={(e) => setProfile(e.target.value)} sx={{ flexGrow: 1 }}
                helperText={
                  !repHostId ? "Pick a target to load its profiles"
                  : profLoading ? "Loading profiles from the host…"
                  : prof ? `${prof.profiles.length} profiles available${targetKind === "group" ? " (from a group member)" : ""}`
                  : undefined
                }
              >
                <MenuItem value="">Standard (default)</MenuItem>
                {/* keep a previously-saved profile that isn't in the loaded list */}
                {profile && !(prof?.profiles ?? []).some((p) => p.id === profile) && (
                  <MenuItem value={profile}>{profile}</MenuItem>
                )}
                {prof?.profiles.map((p) => (
                  <MenuItem key={p.id} value={p.id}>{p.title || p.id}</MenuItem>
                ))}
              </TextField>
              <FormControlLabel control={<Switch checked={skipFs} onChange={(e) => setSkipFs(e.target.checked)} />}
                label="Skip slow FS rules" />
            </Stack>
          ) : (
            <Stack direction="row" spacing={2} alignItems="center">
              <Autocomplete sx={{ flexGrow: 1 }} options={playbooks} value={playbook}
                onChange={(_, v) => setPlaybook(v)} getOptionLabel={(p) => p.name}
                isOptionEqualToValue={(a, b) => a.id === b.id}
                renderInput={(params) => <TextField {...params} label="Playbook" size="small" />} />
              <FormControlLabel control={<Switch checked={checkMode} onChange={(e) => setCheckMode(e.target.checked)} />}
                label="Dry run" />
            </Stack>
          )}

          <Box>
            <Typography variant="caption" color="text.secondary">Target</Typography>
            <Stack direction="row" spacing={2} alignItems="center" sx={{ mt: 0.5 }}>
              <ToggleButtonGroup size="small" exclusive value={targetKind}
                onChange={(_, v) => { if (v) setTargetKind(v); }}>
                <ToggleButton value="host">Host</ToggleButton>
                <ToggleButton value="group">Group</ToggleButton>
              </ToggleButtonGroup>
              {targetKind === "host" ? (
                <Autocomplete sx={{ flexGrow: 1 }} options={hosts} value={host}
                  onChange={(_, v) => setHost(v)} getOptionLabel={(h) => h.hostname}
                  isOptionEqualToValue={(a, b) => a.id === b.id}
                  renderInput={(params) => <TextField {...params} label="Host" size="small" />} />
              ) : (
                <Autocomplete sx={{ flexGrow: 1 }} options={groups} value={group}
                  onChange={(_, v) => setGroup(v)} getOptionLabel={(g) => g.name}
                  isOptionEqualToValue={(a, b) => a.id === b.id}
                  renderInput={(params) => <TextField {...params} label="Group" size="small" />} />
              )}
            </Stack>
          </Box>

          <Box>
            <Typography variant="caption" color="text.secondary">Recurrence</Typography>
            <Stack direction="row" spacing={2} alignItems="center" sx={{ mt: 0.5 }}>
              <TextField select size="small" value={recType} onChange={(e) => setRecType(e.target.value as Recurrence["type"])} sx={{ width: 140 }}>
                <MenuItem value="interval">Interval</MenuItem>
                <MenuItem value="daily">Daily</MenuItem>
                <MenuItem value="weekly">Weekly</MenuItem>
              </TextField>
              {recType === "interval" && (
                <TextField label="Every (minutes)" size="small" type="number" value={everyMinutes}
                  onChange={(e) => setEveryMinutes(e.target.value)} sx={{ width: 160 }} inputProps={{ min: 1 }} />
              )}
              {recType === "weekly" && (
                <TextField select size="small" label="Day" value={weekday}
                  onChange={(e) => setWeekday(Number(e.target.value))} sx={{ width: 140 }}>
                  {WEEKDAYS.map((d, i) => <MenuItem key={i} value={i}>{d}</MenuItem>)}
                </TextField>
              )}
              {(recType === "daily" || recType === "weekly") && (
                <TextField label="Time" size="small" type="time" value={timeOfDay}
                  onChange={(e) => setTimeOfDay(e.target.value)} sx={{ width: 130 }}
                  InputLabelProps={{ shrink: true }} />
              )}
            </Stack>
          </Box>

          <FormControlLabel control={<Switch checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />}
            label="Enabled" />

          {save.error != null && <Alert severity="error">{(save.error as Error).message}</Alert>}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={!name.trim() || !targetId || !playbookOk || save.isPending}
          onClick={() => save.mutate()}>
          {isNew ? "Create" : "Save"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
