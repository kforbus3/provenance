import { useEffect, useState } from "react";
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  IconButton, Paper, Stack, Table, TableBody, TableCell, TableContainer, TableHead,
  TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import RuleIcon from "@mui/icons-material/Rule";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import CodeMirror from "@uiw/react-codemirror";
import { yaml } from "@codemirror/lang-yaml";
import {
  createPlaybook, deletePlaybook, getPlaybook, listPlaybooks, lintPlaybook,
  runnerStatus, updatePlaybook, validatePlaybook, type CheckResult,
} from "../api/playbooks";
import { useUIStore } from "../store/ui";

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
  const { data: playbooks = [], isLoading } = useQuery({ queryKey: ["playbooks"], queryFn: listPlaybooks });
  const { data: runner } = useQuery({ queryKey: ["playbook-runner"], queryFn: runnerStatus });

  const [editorId, setEditorId] = useState<string | null>(null); // playbook id, "" = new, null = closed
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
    </Box>
  );
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
