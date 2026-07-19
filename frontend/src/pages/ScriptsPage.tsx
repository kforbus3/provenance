import { useEffect, useRef, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  IconButton, LinearProgress, Paper, Stack, Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, TextField, ToggleButton, ToggleButtonGroup, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import HistoryIcon from "@mui/icons-material/History";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import CodeMirror from "@uiw/react-codemirror";
import {
  createScript, deleteScript, getScript, getScriptRun, listScriptRuns, listScripts,
  runScript, updateScript, type Script,
} from "../api/scripts";
import { listHosts, type Host } from "../api/hosts";
import { listGroups, type Group } from "../api/admin";
import { useUIStore } from "../store/ui";
import { useAuthStore } from "../store/auth";
import { formatDateTime } from "../lib/datetime";

const STARTER = `# Example PowerShell script — runs on the target Windows host(s).
# Output (stdout/stderr) and the exit code are captured per host.
Write-Output "Hostname: $env:COMPUTERNAME"
Get-Service -Name Spooler | Select-Object Name, Status
`;

// Authoring surface for PowerShell scripts. Scripts are stored in Fleet, edited
// here, and run on Windows hosts over WinRM as the host's credentialed user.
export function ScriptsPage() {
  const qc = useQueryClient();
  const has = useAuthStore((s) => s.has);
  const canRun = has("Script.Run");
  const { data: scripts = [], isLoading } = useQuery({ queryKey: ["scripts"], queryFn: listScripts });

  const [editorId, setEditorId] = useState<string | null>(null); // script id, "" = new, null = closed
  const [runTarget, setRunTarget] = useState<Script | null>(null);
  const [runsTarget, setRunsTarget] = useState<Script | null>(null);
  const invalidate = () => qc.invalidateQueries({ queryKey: ["scripts"] });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteScript(id),
    onSuccess: invalidate,
  });

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>PowerShell Scripts</Typography>
        <Button startIcon={<AddIcon />} variant="contained" onClick={() => setEditorId("")}>
          New Script
        </Button>
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Author PowerShell scripts here, then run them on Windows hosts over WinRM. Scripts execute as
        the host's vaulted credential (honoring its check-out policy).
      </Typography>

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Description</TableCell>
              <TableCell>Version</TableCell>
              <TableCell>Updated</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {scripts.map((p) => (
              <TableRow key={p.id} hover sx={{ cursor: "pointer" }} onClick={() => setEditorId(p.id)}>
                <TableCell>{p.name}</TableCell>
                <TableCell sx={{ color: "text.secondary" }}>{p.description}</TableCell>
                <TableCell><Chip size="small" label={`v${p.version}`} /></TableCell>
                <TableCell sx={{ color: "text.secondary" }}>{formatDateTime(p.updatedAt)}</TableCell>
                <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                  {canRun && (
                    <>
                      <Tooltip title="Run">
                        <IconButton size="small" color="primary" onClick={() => setRunTarget(p)}>
                          <PlayArrowIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Run history">
                        <IconButton size="small" onClick={() => setRunsTarget(p)}>
                          <HistoryIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </>
                  )}
                  <Tooltip title="Edit">
                    <IconButton size="small" onClick={() => setEditorId(p.id)}><EditIcon fontSize="small" /></IconButton>
                  </Tooltip>
                  <Tooltip title="Delete">
                    <IconButton
                      size="small"
                      onClick={() => { if (confirm(`Delete script "${p.name}"?`)) deleteMut.mutate(p.id); }}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {!isLoading && scripts.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} align="center" sx={{ color: "text.secondary", py: 4 }}>
                  No scripts yet. Click “New Script” to create one.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {editorId !== null && (
        <ScriptEditor
          id={editorId || null}
          onClose={() => setEditorId(null)}
          onSaved={() => { setEditorId(null); invalidate(); }}
        />
      )}
      {runTarget && <ScriptRunDialog script={runTarget} onClose={() => setRunTarget(null)} />}
      {runsTarget && <ScriptRunsDialog script={runsTarget} onClose={() => setRunsTarget(null)} />}
    </Box>
  );
}

const TERMINAL = new Set(["completed", "failed"]);

// Run a script on one or more accessible Windows hosts, or every Windows host in a
// group. After launch: poll the run and stream its per-host output into a console.
function ScriptRunDialog({ script, onClose }: { script: Script; onClose: () => void }) {
  const { data: hostData } = useQuery({ queryKey: ["hosts"], queryFn: listHosts });
  const { data: groups = [] } = useQuery({ queryKey: ["groups"], queryFn: listGroups });
  // Only Windows hosts can run PowerShell.
  const hosts = (hostData?.hosts ?? []).filter((h) => h.protocol === "rdp");

  const [mode, setMode] = useState<"host" | "group">("host");
  const [selectedHosts, setSelectedHosts] = useState<Host[]>([]);
  const [group, setGroup] = useState<Group | null>(null);
  const [runId, setRunId] = useState<string | null>(null);

  const targetReady = mode === "host" ? selectedHosts.length > 0 : !!group;
  const targetLabel =
    mode === "host"
      ? selectedHosts.length === 1 ? selectedHosts[0].hostname : `${selectedHosts.length} hosts`
      : group ? `group “${group.name}”` : "the group";

  const startMut = useMutation({
    mutationFn: () =>
      runScript(
        script.id,
        mode === "host"
          ? { targetKind: "host", hostIds: selectedHosts.map((h) => h.id) }
          : { targetKind: "group", groupId: group!.id },
      ),
    onSuccess: (r) => setRunId(r.id),
  });

  const { data: run } = useQuery({
    queryKey: ["script-run", runId],
    queryFn: () => getScriptRun(runId as string),
    enabled: !!runId,
    refetchInterval: (q) => (q.state.data && TERMINAL.has(q.state.data.status) ? false : 1000),
  });

  const running = !!runId && (!run || !TERMINAL.has(run.status));

  const logRef = useRef<HTMLPreElement>(null);
  const stickToBottom = useRef(true);
  useEffect(() => {
    const el = logRef.current;
    if (el && stickToBottom.current) el.scrollTop = el.scrollHeight;
  }, [run?.output]);
  const onLogScroll = () => {
    const el = logRef.current;
    if (el) stickToBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };

  return (
    <Dialog open fullWidth maxWidth="md" onClose={running ? undefined : onClose}>
      <DialogTitle>Run “{script.name}”</DialogTitle>
      <DialogContent dividers>
        {!runId ? (
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Alert severity="info">
              The script runs on each target over WinRM (through the Fleet jump host) as the host's
              vaulted credential. Only Windows hosts are listed.
            </Alert>
            <ToggleButtonGroup
              size="small" exclusive value={mode}
              onChange={(_, v) => { if (v) setMode(v); }}
            >
              <ToggleButton value="host">Hosts</ToggleButton>
              <ToggleButton value="group">Group</ToggleButton>
            </ToggleButtonGroup>
            {mode === "host" ? (
              <Autocomplete
                multiple
                options={hosts}
                value={selectedHosts}
                onChange={(_, v) => setSelectedHosts(v)}
                getOptionLabel={(h) => h.hostname}
                isOptionEqualToValue={(a, b) => a.id === b.id}
                renderInput={(params) => (
                  <TextField {...params} label="Target Windows hosts" size="small" autoFocus
                    placeholder={selectedHosts.length ? "" : "Add one or more Windows hosts"} />
                )}
              />
            ) : (
              <Autocomplete
                options={groups}
                value={group}
                onChange={(_, v) => setGroup(v)}
                getOptionLabel={(g) => g.name}
                isOptionEqualToValue={(a, b) => a.id === b.id}
                renderInput={(params) => <TextField {...params} label="Target group" size="small" autoFocus />}
              />
            )}
            {mode === "group" && (
              <Typography variant="body2" color="text.secondary">
                The script runs on every Windows host in the group that you can access.
              </Typography>
            )}
            {targetReady && (
              <Alert severity="warning">
                This will execute the script on <strong>{targetLabel}</strong>.
              </Alert>
            )}
            {startMut.error != null && <Alert severity="error">{(startMut.error as Error).message}</Alert>}
          </Stack>
        ) : (
          <Stack spacing={1} sx={{ mt: 1 }}>
            <Stack direction="row" spacing={1} alignItems="center">
              <RunStatusChip status={run?.status} />
              <Typography variant="body2" color="text.secondary">
                {run?.targetName}{run && run.hostCount > 1 ? ` (${run.hostCount} hosts)` : ""}
              </Typography>
              {run && TERMINAL.has(run.status) && run.exitCode != null && (
                <Typography variant="body2" color="text.secondary">exit {run.exitCode}</Typography>
              )}
            </Stack>
            {running && <LinearProgress />}
            <Box
              component="pre"
              ref={logRef}
              onScroll={onLogScroll}
              sx={{
                m: 0, p: 1.5, bgcolor: "#0b0b0b", color: "#e0e0e0", borderRadius: 1,
                fontFamily: "monospace", fontSize: 12.5, whiteSpace: "pre-wrap",
                maxHeight: 420, minHeight: 200, overflow: "auto",
              }}
            >
              {run?.output || (running ? "Starting…" : "(no output)")}
            </Box>
            {run?.error && <Alert severity="error">{run.error}</Alert>}
          </Stack>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={running}>{runId ? "Close" : "Cancel"}</Button>
        {!runId && (
          <Button
            variant="contained" startIcon={<PlayArrowIcon />}
            disabled={!targetReady || startMut.isPending}
            onClick={() => startMut.mutate()}
          >
            Run
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}

// Past runs for a script, with a drill-down into a run's captured output.
function ScriptRunsDialog({ script, onClose }: { script: Script; onClose: () => void }) {
  const { data: runs = [] } = useQuery({
    queryKey: ["script-runs", script.id],
    queryFn: () => listScriptRuns(script.id),
  });
  const [openRun, setOpenRun] = useState<string | null>(null);
  const { data: detail } = useQuery({
    queryKey: ["script-run", openRun],
    queryFn: () => getScriptRun(openRun as string),
    enabled: !!openRun,
  });

  return (
    <Dialog open fullWidth maxWidth="md" onClose={onClose}>
      <DialogTitle>Run history — {script.name}</DialogTitle>
      <DialogContent dividers>
        {openRun ? (
          <Stack spacing={1}>
            <Button size="small" onClick={() => setOpenRun(null)} sx={{ alignSelf: "flex-start" }}>
              ← Back to history
            </Button>
            <Stack direction="row" spacing={1} alignItems="center">
              <RunStatusChip status={detail?.status} />
              <Typography variant="body2" color="text.secondary">{detail?.targetName}</Typography>
            </Stack>
            <Box
              component="pre"
              sx={{
                m: 0, p: 1.5, bgcolor: "#0b0b0b", color: "#e0e0e0", borderRadius: 1,
                fontFamily: "monospace", fontSize: 12.5, whiteSpace: "pre-wrap",
                maxHeight: 420, overflow: "auto",
              }}
            >
              {detail?.output || "(no output)"}
            </Box>
          </Stack>
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>When</TableCell>
                  <TableCell>Target</TableCell>
                  <TableCell>By</TableCell>
                  <TableCell>Status</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {runs.map((r) => (
                  <TableRow key={r.id} hover sx={{ cursor: "pointer" }} onClick={() => setOpenRun(r.id)}>
                    <TableCell>{formatDateTime(r.createdAt)}</TableCell>
                    <TableCell>{r.targetName}</TableCell>
                    <TableCell>
                      {r.scheduled
                        ? <Chip size="small" variant="outlined" label="scheduled" />
                        : r.requester}
                    </TableCell>
                    <TableCell><RunStatusChip status={r.status} /></TableCell>
                  </TableRow>
                ))}
                {runs.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} align="center" sx={{ color: "text.secondary", py: 3 }}>
                      No runs yet.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

function RunStatusChip({ status }: { status?: string }) {
  const color =
    status === "completed" ? "success" : status === "failed" ? "error" :
    status === "running" ? "info" : "default";
  return <Chip size="small" color={color as "success" | "error" | "info" | "default"} label={status ?? "…"} />;
}

function ScriptEditor({ id, onClose, onSaved }: { id: string | null; onClose: () => void; onSaved: () => void }) {
  const mode = useUIStore((s) => s.mode);
  const isNew = id === null;

  const { data: existing } = useQuery({
    queryKey: ["script", id],
    queryFn: () => getScript(id as string),
    enabled: !isNew,
  });

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [content, setContent] = useState(STARTER);
  const [loaded, setLoaded] = useState(isNew);

  useEffect(() => {
    if (existing && !loaded) {
      setName(existing.name);
      setDescription(existing.description ?? "");
      setContent(existing.content ?? "");
      setLoaded(true);
    }
  }, [existing, loaded]);

  const saveMut = useMutation({
    mutationFn: () =>
      isNew
        ? createScript({ name, description, content })
        : updateScript(id as string, { name, description, content }),
    onSuccess: onSaved,
  });

  return (
    <Dialog open fullWidth maxWidth="lg" onClose={onClose}>
      <DialogTitle>{isNew ? "New Script" : "Edit Script"}</DialogTitle>
      <DialogContent dividers>
        <Stack spacing={2}>
          <TextField
            label="Name" value={name} onChange={(e) => setName(e.target.value)}
            size="small" fullWidth autoFocus required
          />
          <TextField
            label="Description" value={description} onChange={(e) => setDescription(e.target.value)}
            size="small" fullWidth
          />
          <Box sx={{ border: 1, borderColor: "divider", borderRadius: 1, overflow: "hidden" }}>
            <CodeMirror
              value={content}
              height="380px"
              theme={mode === "dark" ? "dark" : "light"}
              onChange={(v) => setContent(v)}
            />
          </Box>
          {saveMut.error != null && <Alert severity="error">{(saveMut.error as Error).message}</Alert>}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained" onClick={() => saveMut.mutate()}
          disabled={!name.trim() || saveMut.isPending}
        >
          {isNew ? "Create" : "Save"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
