import { useEffect, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  FormControlLabel, IconButton, LinearProgress, Paper, Stack, Switch, Table, TableBody,
  TableCell, TableContainer, TableHead, TableRow, TextField, ToggleButton,
  ToggleButtonGroup, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import RuleIcon from "@mui/icons-material/Rule";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import HistoryIcon from "@mui/icons-material/History";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import CodeMirror from "@uiw/react-codemirror";
import { yaml } from "@codemirror/lang-yaml";
import {
  createPlaybook, deletePlaybook, getPlaybook, getPlaybookRun, listPlaybookRuns, listPlaybooks,
  lintPlaybook, runPlaybook, runnerStatus, updatePlaybook, validatePlaybook,
  type CheckResult, type Playbook,
} from "../api/playbooks";
import { listHosts, type Host } from "../api/hosts";
import { listGroups, type Group } from "../api/admin";
import { useUIStore } from "../store/ui";
import { useAuthStore } from "../store/auth";

const STARTER = `---
- name: Example playbook
  hosts: all
  become: true
  tasks:
    - name: Ensure the system is up to date
      ansible.builtin.package:
        name: "*"
        state: latest
`;

// Authoring surface for Ansible playbooks. Playbooks are stored in Fleet,
// edited here, and validated/linted by the ansible-runner sidecar. Running them
// against hosts arrives in a later phase.
export function PlaybooksPage() {
  const qc = useQueryClient();
  const has = useAuthStore((s) => s.has);
  const canRun = has("Playbook.Run");
  const { data: playbooks = [], isLoading } = useQuery({ queryKey: ["playbooks"], queryFn: listPlaybooks });
  const { data: runner } = useQuery({ queryKey: ["playbook-runner"], queryFn: runnerStatus });

  const [editorId, setEditorId] = useState<string | null>(null); // playbook id, "" = new, null = closed
  const [runTarget, setRunTarget] = useState<Playbook | null>(null);
  const [runsTarget, setRunsTarget] = useState<Playbook | null>(null);
  const invalidate = () => qc.invalidateQueries({ queryKey: ["playbooks"] });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deletePlaybook(id),
    onSuccess: invalidate,
  });

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>Playbooks</Typography>
        <Button startIcon={<AddIcon />} variant="contained" onClick={() => setEditorId("")}>
          New Playbook
        </Button>
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Author Ansible playbooks here, then validate and lint them. Running playbooks against hosts
        is coming in a later phase.
      </Typography>

      {runner && !runner.available && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          The ansible-runner service is not reachable, so Validate and Lint are unavailable. You can
          still create and edit playbooks.
        </Alert>
      )}

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
            {playbooks.map((p) => (
              <TableRow key={p.id} hover sx={{ cursor: "pointer" }} onClick={() => setEditorId(p.id)}>
                <TableCell>{p.name}</TableCell>
                <TableCell sx={{ color: "text.secondary" }}>{p.description}</TableCell>
                <TableCell><Chip size="small" label={`v${p.version}`} /></TableCell>
                <TableCell sx={{ color: "text.secondary" }}>
                  {new Date(p.updatedAt).toLocaleString()}
                </TableCell>
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
                      onClick={() => { if (confirm(`Delete playbook "${p.name}"?`)) deleteMut.mutate(p.id); }}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {!isLoading && playbooks.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} align="center" sx={{ color: "text.secondary", py: 4 }}>
                  No playbooks yet. Click “New Playbook” to create one.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {editorId !== null && (
        <PlaybookEditor
          id={editorId || null}
          onClose={() => setEditorId(null)}
          onSaved={() => { setEditorId(null); invalidate(); }}
        />
      )}
      {runTarget && <PlaybookRunDialog playbook={runTarget} onClose={() => setRunTarget(null)} />}
      {runsTarget && <PlaybookRunsDialog playbook={runsTarget} onClose={() => setRunsTarget(null)} />}
    </Box>
  );
}

const TERMINAL = new Set(["completed", "failed"]);

// Run a playbook against one or more accessible hosts, or every host in a group.
// Pre-run: choose targets + dry-run. After launch: poll the run and stream its
// output into a console until it reaches a terminal state.
function PlaybookRunDialog({ playbook, onClose }: { playbook: Playbook; onClose: () => void }) {
  const { data: hostData } = useQuery({ queryKey: ["hosts"], queryFn: listHosts });
  const { data: groups = [] } = useQuery({ queryKey: ["groups"], queryFn: listGroups });
  const hosts = hostData?.hosts ?? [];

  const [mode, setMode] = useState<"host" | "group">("host");
  const [selectedHosts, setSelectedHosts] = useState<Host[]>([]);
  const [group, setGroup] = useState<Group | null>(null);
  const [checkMode, setCheckMode] = useState(true);
  const [runId, setRunId] = useState<string | null>(null);

  const targetReady = mode === "host" ? selectedHosts.length > 0 : !!group;
  const targetLabel =
    mode === "host"
      ? selectedHosts.length === 1 ? selectedHosts[0].hostname : `${selectedHosts.length} hosts`
      : group ? `group “${group.name}”` : "the group";

  const startMut = useMutation({
    mutationFn: () =>
      runPlaybook(
        playbook.id,
        mode === "host"
          ? { targetKind: "host", hostIds: selectedHosts.map((h) => h.id), checkMode }
          : { targetKind: "group", groupId: group!.id, checkMode },
      ),
    onSuccess: (r) => setRunId(r.id),
  });

  const { data: run } = useQuery({
    queryKey: ["playbook-run", runId],
    queryFn: () => getPlaybookRun(runId as string),
    enabled: !!runId,
    refetchInterval: (q) => (q.state.data && TERMINAL.has(q.state.data.status) ? false : 1000),
  });

  const running = !!runId && (!run || !TERMINAL.has(run.status));

  return (
    <Dialog open fullWidth maxWidth="md" onClose={running ? undefined : onClose}>
      <DialogTitle>Run “{playbook.name}”</DialogTitle>
      <DialogContent dividers>
        {!runId ? (
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Alert severity="info">
              The playbook runs through the Fleet jump host as the privileged host account. Make sure
              its plays target <code>hosts: all</code> — Fleet supplies the inventory and limits it to
              the targets you pick.
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
                  <TextField {...params} label="Target hosts" size="small" autoFocus
                    placeholder={selectedHosts.length ? "" : "Add one or more hosts"} />
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
                The playbook runs on every host in the group that you can access.
              </Typography>
            )}
            <FormControlLabel
              control={<Switch checked={checkMode} onChange={(e) => setCheckMode(e.target.checked)} />}
              label="Dry run (check mode — report changes without applying them)"
            />
            {!checkMode && targetReady && (
              <Alert severity="warning">
                This will apply changes on <strong>{targetLabel}</strong>.
              </Alert>
            )}
            {startMut.error != null && <Alert severity="error">{(startMut.error as Error).message}</Alert>}
          </Stack>
        ) : (
          <Stack spacing={1} sx={{ mt: 1 }}>
            <Stack direction="row" spacing={1} alignItems="center">
              <RunStatusChip status={run?.status} />
              {run?.checkMode && <Chip size="small" label="dry run" variant="outlined" />}
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
            {checkMode ? "Dry run" : "Run"}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}

// Past runs for a playbook, with a drill-down into a run's captured output.
function PlaybookRunsDialog({ playbook, onClose }: { playbook: Playbook; onClose: () => void }) {
  const { data: runs = [] } = useQuery({
    queryKey: ["playbook-runs", playbook.id],
    queryFn: () => listPlaybookRuns(playbook.id),
  });
  const [openRun, setOpenRun] = useState<string | null>(null);
  const { data: detail } = useQuery({
    queryKey: ["playbook-run", openRun],
    queryFn: () => getPlaybookRun(openRun as string),
    enabled: !!openRun,
  });

  return (
    <Dialog open fullWidth maxWidth="md" onClose={onClose}>
      <DialogTitle>Run history — {playbook.name}</DialogTitle>
      <DialogContent dividers>
        {openRun ? (
          <Stack spacing={1}>
            <Button size="small" onClick={() => setOpenRun(null)} sx={{ alignSelf: "flex-start" }}>
              ← Back to history
            </Button>
            <Stack direction="row" spacing={1} alignItems="center">
              <RunStatusChip status={detail?.status} />
              {detail?.checkMode && <Chip size="small" label="dry run" variant="outlined" />}
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
                  <TableCell>Mode</TableCell>
                  <TableCell>By</TableCell>
                  <TableCell>Status</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {runs.map((r) => (
                  <TableRow key={r.id} hover sx={{ cursor: "pointer" }} onClick={() => setOpenRun(r.id)}>
                    <TableCell>{new Date(r.createdAt).toLocaleString()}</TableCell>
                    <TableCell>{r.targetName}</TableCell>
                    <TableCell>{r.checkMode ? "dry run" : "apply"}</TableCell>
                    <TableCell>{r.requester}</TableCell>
                    <TableCell><RunStatusChip status={r.status} /></TableCell>
                  </TableRow>
                ))}
                {runs.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} align="center" sx={{ color: "text.secondary", py: 3 }}>
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

function PlaybookEditor({ id, onClose, onSaved }: { id: string | null; onClose: () => void; onSaved: () => void }) {
  const mode = useUIStore((s) => s.mode);
  const isNew = id === null;

  const { data: existing } = useQuery({
    queryKey: ["playbook", id],
    queryFn: () => getPlaybook(id as string),
    enabled: !isNew,
  });

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [content, setContent] = useState(STARTER);
  const [check, setCheck] = useState<{ kind: "validate" | "lint"; result: CheckResult } | null>(null);
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
        ? createPlaybook({ name, description, content })
        : updatePlaybook(id as string, { name, description, content }),
    onSuccess: onSaved,
  });
  const validateMut = useMutation({
    mutationFn: () => validatePlaybook(content),
    onSuccess: (r) => setCheck({ kind: "validate", result: r }),
  });
  const lintMut = useMutation({
    mutationFn: () => lintPlaybook(content),
    onSuccess: (r) => setCheck({ kind: "lint", result: r }),
  });

  const runnerError = (validateMut.error || lintMut.error) as Error | null;

  return (
    <Dialog open fullWidth maxWidth="lg" onClose={onClose}>
      <DialogTitle>{isNew ? "New Playbook" : "Edit Playbook"}</DialogTitle>
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
              extensions={[yaml()]}
              onChange={(v) => setContent(v)}
            />
          </Box>

          <Stack direction="row" spacing={1}>
            <Button
              startIcon={<CheckCircleIcon />} variant="outlined" size="small"
              onClick={() => validateMut.mutate()} disabled={validateMut.isPending}
            >
              Validate
            </Button>
            <Button
              startIcon={<RuleIcon />} variant="outlined" size="small"
              onClick={() => lintMut.mutate()} disabled={lintMut.isPending}
            >
              Lint
            </Button>
          </Stack>

          {runnerError && <Alert severity="error">{runnerError.message}</Alert>}
          {check && (
            <Alert severity={check.result.ok ? "success" : check.kind === "lint" ? "warning" : "error"}>
              <Typography variant="subtitle2">
                {check.kind === "validate" ? "Syntax check" : "Lint"}: {check.result.ok ? "passed" : "issues found"}
              </Typography>
              <Box component="pre" sx={{ m: 0, mt: 1, whiteSpace: "pre-wrap", fontSize: 12, fontFamily: "monospace" }}>
                {check.result.output}
              </Box>
            </Alert>
          )}
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
