import { useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  IconButton, InputAdornment, MenuItem, Paper, Stack, Table, TableBody, TableCell, TableHead,
  TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import VisibilityIcon from "@mui/icons-material/Visibility";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import GroupIcon from "@mui/icons-material/Group";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "../store/auth";
import { listUsers, listGroups } from "../api/admin";
import {
  listVaultSecrets, createVaultSecret, updateVaultSecret, deleteVaultSecret, revealVaultSecret,
  listVaultGrants, createVaultGrant, deleteVaultGrant,
  type VaultSecret, type VaultSecretInput,
} from "../api/vault";

const TYPES = [
  { value: "password", label: "Password" },
  { value: "ssh_key", label: "SSH key" },
  { value: "api_key", label: "API key" },
  { value: "generic", label: "Generic secret" },
];

// VaultPage: the credential vault — store static credentials, reveal them
// (audited), and delegate access via per-secret grants.
export function VaultPage() {
  const qc = useQueryClient();
  const has = useAuthStore((s) => s.has);
  const canManage = has("Credential.Manage");
  const { data: secrets = [], isLoading } = useQuery({ queryKey: ["vault-secrets"], queryFn: listVaultSecrets });
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<VaultSecret | null>(null);
  const [revealing, setRevealing] = useState<VaultSecret | null>(null);
  const [granting, setGranting] = useState<VaultSecret | null>(null);
  const invalidate = () => qc.invalidateQueries({ queryKey: ["vault-secrets"] });

  const del = useMutation({ mutationFn: (id: string) => deleteVaultSecret(id), onSuccess: invalidate });

  return (
    <Box sx={{ maxWidth: 1150 }}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
        <Box>
          <Typography variant="h5">Credentials</Typography>
          <Typography variant="body2" color="text.secondary">
            Store passwords, SSH keys, and API keys encrypted at rest. Revealing a credential is audited.
          </Typography>
        </Box>
        {canManage && <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreating(true)}>New credential</Button>}
      </Stack>

      <Paper variant="outlined" sx={{ overflowX: "auto", mt: 1 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Folder</TableCell>
              <TableCell>Name</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Username</TableCell>
              <TableCell>Target</TableCell>
              <TableCell>Ver</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {secrets.map((s) => (
              <TableRow key={s.id} hover>
                <TableCell>{s.folder || "—"}</TableCell>
                <TableCell>{s.name}</TableCell>
                <TableCell><Chip size="small" variant="outlined" label={TYPES.find((t) => t.value === s.type)?.label ?? s.type} /></TableCell>
                <TableCell>{s.username || "—"}</TableCell>
                <TableCell>{s.target || "—"}</TableCell>
                <TableCell>{s.version}</TableCell>
                <TableCell align="right">
                  <Tooltip title="Reveal (audited)"><IconButton size="small" onClick={() => setRevealing(s)}><VisibilityIcon fontSize="small" /></IconButton></Tooltip>
                  {canManage && <>
                    <Tooltip title="Edit"><IconButton size="small" onClick={() => setEditing(s)}><EditIcon fontSize="small" /></IconButton></Tooltip>
                    <Tooltip title="Grants"><IconButton size="small" onClick={() => setGranting(s)}><GroupIcon fontSize="small" /></IconButton></Tooltip>
                    <Tooltip title="Delete"><IconButton size="small" color="error"
                      onClick={() => { if (window.confirm(`Delete credential "${s.name}"? This cannot be undone.`)) del.mutate(s.id); }}>
                      <DeleteIcon fontSize="small" /></IconButton></Tooltip>
                  </>}
                </TableCell>
              </TableRow>
            ))}
            {secrets.length === 0 && (
              <TableRow><TableCell colSpan={7}>
                <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                  {isLoading ? "Loading…" : canManage ? "No credentials yet. Add one to get started." : "No credentials are shared with you."}
                </Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>

      {creating && <SecretDialog onClose={() => setCreating(false)} onSaved={() => { setCreating(false); invalidate(); }} />}
      {editing && <SecretDialog secret={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); invalidate(); }} />}
      {revealing && <RevealDialog secret={revealing} onClose={() => setRevealing(null)} />}
      {granting && <GrantsDialog secret={granting} onClose={() => setGranting(null)} />}
    </Box>
  );
}

function SecretDialog({ secret, onClose, onSaved }: { secret?: VaultSecret; onClose: () => void; onSaved: () => void }) {
  const editing = !!secret;
  const [form, setForm] = useState<VaultSecretInput>({
    name: secret?.name ?? "", folder: secret?.folder ?? "", type: secret?.type ?? "password",
    username: secret?.username ?? "", target: secret?.target ?? "", description: secret?.description ?? "", secret: "",
  });
  const [err, setErr] = useState<string | null>(null);
  const set = (patch: Partial<VaultSecretInput>) => setForm((f) => ({ ...f, ...patch }));

  const save = useMutation({
    mutationFn: () => editing ? updateVaultSecret(secret!.id, form) : createVaultSecret(form),
    onSuccess: onSaved,
    onError: (e) => setErr(((e as { response?: { data?: { error?: string } } })?.response?.data?.error) || "Could not save."),
  });
  const valid = form.name.trim() && (editing || form.secret);

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{editing ? "Edit credential" : "New credential"}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error">{err}</Alert>}
          <Stack direction="row" spacing={1.5}>
            <TextField label="Name" size="small" value={form.name} onChange={(e) => set({ name: e.target.value })} autoFocus sx={{ flexGrow: 1 }} />
            <TextField label="Folder" size="small" value={form.folder} onChange={(e) => set({ folder: e.target.value })} placeholder="e.g. network" sx={{ width: 180 }} />
          </Stack>
          <Stack direction="row" spacing={1.5}>
            <TextField select label="Type" size="small" value={form.type} onChange={(e) => set({ type: e.target.value })} sx={{ width: 180 }}>
              {TYPES.map((t) => <MenuItem key={t.value} value={t.value}>{t.label}</MenuItem>)}
            </TextField>
            <TextField label="Username" size="small" value={form.username} onChange={(e) => set({ username: e.target.value })} sx={{ flexGrow: 1 }} />
          </Stack>
          <TextField label="Target (host / URL)" size="small" value={form.target} onChange={(e) => set({ target: e.target.value })} placeholder="e.g. switch-01 or https://api.example.com" />
          <TextField label={editing ? "New secret value (leave blank to keep current)" : "Secret value"} size="small" multiline minRows={form.type === "ssh_key" ? 4 : 1}
            value={form.secret} onChange={(e) => set({ secret: e.target.value })} type={form.type === "ssh_key" ? "text" : "password"} autoComplete="new-password" />
          <TextField label="Description" size="small" value={form.description} onChange={(e) => set({ description: e.target.value })} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={!valid || save.isPending} onClick={() => save.mutate()}>{editing ? "Save" : "Create"}</Button>
      </DialogActions>
    </Dialog>
  );
}

function RevealDialog({ secret, onClose }: { secret: VaultSecret; onClose: () => void }) {
  const [value, setValue] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const reveal = useMutation({
    mutationFn: () => revealVaultSecret(secret.id),
    onSuccess: (v) => { setErr(null); setValue(v); },
    onError: (e) => setErr(((e as { response?: { data?: { error?: string } } })?.response?.data?.error) || "Could not reveal."),
  });

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{secret.name}</DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Revealing this credential is recorded in the audit log.
        </Typography>
        {err && <Alert severity="error" sx={{ mb: 2 }}>{err}</Alert>}
        {value === null ? (
          <Button variant="contained" startIcon={<VisibilityIcon />} disabled={reveal.isPending} onClick={() => reveal.mutate()}>
            {reveal.isPending ? "Revealing…" : "Reveal secret"}
          </Button>
        ) : (
          <TextField fullWidth multiline value={value} InputProps={{
            readOnly: true,
            endAdornment: (
              <InputAdornment position="end">
                <Tooltip title="Copy"><IconButton onClick={() => void navigator.clipboard?.writeText(value)}><ContentCopyIcon fontSize="small" /></IconButton></Tooltip>
              </InputAdornment>
            ),
          }} sx={{ "& textarea": { fontFamily: "monospace" } }} />
        )}
      </DialogContent>
      <DialogActions><Button onClick={onClose}>Close</Button></DialogActions>
    </Dialog>
  );
}

function GrantsDialog({ secret, onClose }: { secret: VaultSecret; onClose: () => void }) {
  const qc = useQueryClient();
  const { data: grants = [] } = useQuery({ queryKey: ["vault-grants", secret.id], queryFn: () => listVaultGrants(secret.id) });
  const { data: users = [] } = useQuery({ queryKey: ["users"], queryFn: listUsers });
  const { data: groups = [] } = useQuery({ queryKey: ["groups"], queryFn: listGroups });
  const [kind, setKind] = useState<"user" | "group">("user");
  const [subjectId, setSubjectId] = useState("");
  const [access, setAccess] = useState("view");
  const refresh = () => qc.invalidateQueries({ queryKey: ["vault-grants", secret.id] });

  const add = useMutation({ mutationFn: () => createVaultGrant(secret.id, { subjectKind: kind, subjectId, access }), onSuccess: () => { setSubjectId(""); refresh(); } });
  const remove = useMutation({ mutationFn: (grantId: string) => deleteVaultGrant(secret.id, grantId), onSuccess: refresh });

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Access to {secret.name}</DialogTitle>
      <DialogContent>
        <Paper variant="outlined" sx={{ mb: 2 }}>
          <Table size="small">
            <TableBody>
              {grants.map((g) => (
                <TableRow key={g.id}>
                  <TableCell>{g.subjectKind === "user" ? "User" : "Group"}: {g.subjectName || g.subjectId}</TableCell>
                  <TableCell><Chip size="small" label={g.access} /></TableCell>
                  <TableCell align="right"><IconButton size="small" color="error" onClick={() => remove.mutate(g.id)}><DeleteIcon fontSize="small" /></IconButton></TableCell>
                </TableRow>
              ))}
              {grants.length === 0 && <TableRow><TableCell><Typography variant="body2" color="text.secondary" sx={{ py: 0.5 }}>No grants. Only Credential.Manage holders can access this.</Typography></TableCell></TableRow>}
            </TableBody>
          </Table>
        </Paper>
        <Stack direction="row" spacing={1} alignItems="center">
          <TextField select size="small" label="Kind" value={kind} onChange={(e) => { setKind(e.target.value as "user" | "group"); setSubjectId(""); }} sx={{ width: 100 }}>
            <MenuItem value="user">User</MenuItem>
            <MenuItem value="group">Group</MenuItem>
          </TextField>
          <Autocomplete size="small" sx={{ flexGrow: 1 }}
            options={(kind === "user"
              ? users.map((u) => ({ id: u.id, label: u.username }))
              : groups.map((g) => ({ id: g.id, label: g.name })))}
            getOptionLabel={(o) => o.label}
            onChange={(_, v) => setSubjectId(v?.id ?? "")}
            renderInput={(p) => <TextField {...p} label={kind === "user" ? "User" : "Group"} />} />
          <TextField select size="small" label="Access" value={access} onChange={(e) => setAccess(e.target.value)} sx={{ width: 110 }}>
            <MenuItem value="view">View</MenuItem>
            <MenuItem value="use">Use</MenuItem>
            <MenuItem value="manage">Manage</MenuItem>
          </TextField>
          <Button variant="outlined" disabled={!subjectId || add.isPending} onClick={() => add.mutate()}>Grant</Button>
        </Stack>
      </DialogContent>
      <DialogActions><Button onClick={onClose}>Close</Button></DialogActions>
    </Dialog>
  );
}
