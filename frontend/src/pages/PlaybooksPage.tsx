import { useEffect, useRef, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  FormControlLabel, IconButton, LinearProgress, MenuItem, Paper, Stack, Switch, Table, TableBody,
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
import BlastRadiusWarning from "../components/BlastRadiusWarning";
import { listHosts, type Host } from "../api/hosts";
import { listGroups, type Group } from "../api/admin";
import { useUIStore } from "../store/ui";
import { useAuthStore } from "../store/auth";
import { formatDateTime } from "../lib/datetime";
import { PLAYBOOK_TEMPLATES } from "../lib/playbook-templates";

const STARTER = PLAYBOOK_TEMPLATES[0].content;

// Authoring surface for Ansible playbooks. Playbooks are stored in Provenance,
// edited here, and validated/linted by the ansible-runner sidecar. Running them
// against hosts arrives in a later phase.
export function PlaybooksPage() {
  const qc = useQueryClient();
  const has = useAuthStore((s) => s.has);
  // A playbook run is arbitrary root-level execution (the runner always sets
  // become), so the backend requires Host.Sudo alongside Playbook.Run.
  const canRun = has("Playbook.Run") && has("Host.Sudo");
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
        Author Ansible playbooks here, then validate, lint and run them against hosts or a group.
        A new playbook can start from a template — including one that installs an A/B (RAUC) update.
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
                  {formatDateTime(p.updatedAt)}
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

const TERMINAL = new Set(["completed", "failed", "interrupted"]);

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

  // The hosts this run will actually touch, for the dependency preview.
  //
  // A group is resolved here rather than server-side because the host list is
  // already loaded for the picker and carries its own group membership. A run
  // targeting a group is the shape a fleet upgrade actually takes, so leaving
  // group mode unpreviewed would miss the case the preview exists for.
  const targetHostIds =
    mode === "host"
      ? selectedHosts.map((h) => h.id)
      : group
        ? hosts.filter((h) => (h.groups ?? []).includes(group.name)).map((h) => h.id)
        : [];
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

  // Auto-scroll the live console to the bottom as output streams in, unless the
  // user has scrolled up to read (then leave them be until they return to the
  // bottom).
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
      <DialogTitle>Run “{playbook.name}”</DialogTitle>
      <DialogContent dividers>
        {!runId ? (
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Alert severity="info">
              The playbook runs through the Provenance jump host as the privileged host account. Make sure
              its plays target <code>hosts: all</code> — Provenance supplies the inventory and limits it to
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
            {/* Only for a real run. A dry run changes nothing, so a warning that
                this reaches other hosts would be false there — and a warning
                shown when it does not apply is how people learn to skip it. */}
            {!checkMode && <BlastRadiusWarning hostIds={targetHostIds} />}
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
                    <TableCell>{formatDateTime(r.createdAt)}</TableCell>
                    <TableCell>{r.targetName}</TableCell>
                    <TableCell>{r.checkMode ? "dry run" : "apply"}</TableCell>
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
  // "interrupted" (amber) = Provenance restarted mid-run and the result was never
  // collected (e.g. the playbook rebooted the machine hosting Provenance) — the
  // target hosts may still have completed their tasks. Distinct from a red
  // "failed", where ansible itself reported failure.
  const color =
    status === "completed" ? "success" : status === "failed" ? "error" :
    status === "interrupted" ? "warning" :
    status === "running" ? "info" : "default";
  return <Chip size="small" color={color as "success" | "error" | "warning" | "info" | "default"} label={status ?? "…"} />;
}

function PlaybookEditor({ id, onClose, onSaved }: { id: string | null; onClose: () => void; onSaved: () => void }) {
  const mode = useUIStore((s) => s.mode);
  const isNew = id === null;
  const qc = useQueryClient();

  const { data: existing } = useQuery({
    queryKey: ["playbook", id],
    queryFn: () => getPlaybook(id as string),
    enabled: !isNew,
  });

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [content, setContent] = useState(STARTER);
  const [template, setTemplate] = useState(PLAYBOOK_TEMPLATES[0].id);

  // Switching template replaces the editor contents, and also the name and
  // description when they are still empty or still the previous template's --
  // so picking "A/B update" gives a playbook that is named, described and
  // written, rather than a body with an empty name above it. Anything typed is
  // left alone: an overwrite of someone's own words to save them a keystroke is
  // not a trade worth making.
  const pickTemplate = (id: string) => {
    const t = PLAYBOOK_TEMPLATES.find((x) => x.id === id);
    if (!t) return;
    const prev = PLAYBOOK_TEMPLATES.find((x) => x.id === template);
    setTemplate(id);
    setContent(t.content);
    if (!name.trim() || name === prev?.name) setName(t.name);
    if (!description.trim() || description === prev?.playbookDescription) {
      setDescription(t.playbookDescription);
    }
  };
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
    onSuccess: () => {
      // Drop the cached per-playbook query so re-opening the editor refetches the
      // just-saved content instead of serving stale cache (the `loaded` guard would
      // otherwise lock the old value in). Runs already read fresh content from the DB.
      if (!isNew) qc.removeQueries({ queryKey: ["playbook", id] });
      onSaved();
    },
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
          {isNew && (
            <TextField
              select label="Start from" value={template} size="small" fullWidth
              onChange={(e) => pickTemplate(e.target.value)}
              helperText={PLAYBOOK_TEMPLATES.find((t) => t.id === template)?.description}
            >
              {PLAYBOOK_TEMPLATES.map((t) => (
                <MenuItem key={t.id} value={t.id}>{t.label}</MenuItem>
              ))}
            </TextField>
          )}
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
