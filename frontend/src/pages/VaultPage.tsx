import { useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  FormControlLabel, IconButton, InputAdornment, MenuItem, Paper, Stack, Table, TableBody, TableCell, TableHead,
  TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import VisibilityIcon from "@mui/icons-material/Visibility";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import GroupIcon from "@mui/icons-material/Group";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import LockClockIcon from "@mui/icons-material/LockClock";
import AutorenewIcon from "@mui/icons-material/Autorenew";
import ScheduleIcon from "@mui/icons-material/Schedule";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "../store/auth";
import { listUsers, listGroups } from "../api/admin";
import { formatDateTime } from "../lib/datetime";
import {
  listVaultSecrets, createVaultSecret, updateVaultSecret, deleteVaultSecret, revealVaultSecret,
  listVaultGrants, createVaultGrant, deleteVaultGrant,
  requestCheckout, listMyCheckouts, listCheckoutApprovals, approveCheckout, denyCheckout,
  rotateVaultSecret, setVaultRotationPolicy,
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
  const canApprove = has("Credential.Approve");
  const canRotate = has("Credential.Rotate");
  const [rotateMsg, setRotateMsg] = useState<string | null>(null);
  const { data: secrets = [], isLoading } = useQuery({ queryKey: ["vault-secrets"], queryFn: listVaultSecrets });
  const { data: myCheckouts = [] } = useQuery({ queryKey: ["vault-my-checkouts"], queryFn: listMyCheckouts });
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<VaultSecret | null>(null);
  const [revealing, setRevealing] = useState<VaultSecret | null>(null);
  const [granting, setGranting] = useState<VaultSecret | null>(null);
  const [checkingOut, setCheckingOut] = useState<VaultSecret | null>(null);
  const [scheduling, setScheduling] = useState<VaultSecret | null>(null);
  const invalidate = () => qc.invalidateQueries({ queryKey: ["vault-secrets"] });

  // Secrets the caller currently holds an active check-out for.
  const activeCheckouts = new Set(myCheckouts.filter((c) => c.status === "active").map((c) => c.secretId));
  const canReveal = (s: VaultSecret) => s.accessPolicy === "open" || activeCheckouts.has(s.id);

  const del = useMutation({ mutationFn: (id: string) => deleteVaultSecret(id), onSuccess: invalidate });
  const rotate = useMutation({
    mutationFn: (id: string) => rotateVaultSecret(id),
    onSuccess: (res) => { setRotateMsg(res.warning ? `Rotated on ${res.host} (${res.warning})` : `Rotated on ${res.host}.`); invalidate(); },
    onError: (e) => setRotateMsg(((e as { response?: { data?: { error?: string } } })?.response?.data?.error) || "Rotation failed."),
  });

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

      {canApprove && <CheckoutApprovalsInbox />}
      {rotateMsg && (
        <Alert severity={rotateMsg.startsWith("Rotated") ? "success" : "error"} sx={{ mb: 2 }} onClose={() => setRotateMsg(null)}>
          {rotateMsg}
        </Alert>
      )}

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
                <TableCell>
                  {s.name}
                  {s.accessPolicy !== "open" && (
                    <Chip size="small" variant="outlined" color="warning" sx={{ ml: 0.5 }}
                      label={s.accessPolicy === "approval" ? "approval" : "checkout"} />
                  )}
                  {s.rotationIntervalDays > 0 && (
                    <Tooltip title={s.nextRotationAt ? `Next rotation ${formatDateTime(s.nextRotationAt)}` : "Automatic rotation scheduled"}>
                      <Chip size="small" variant="outlined" color="success" icon={<ScheduleIcon />} sx={{ ml: 0.5 }}
                        label={`auto ${s.rotationIntervalDays}d`} />
                    </Tooltip>
                  )}
                </TableCell>
                <TableCell><Chip size="small" variant="outlined" label={TYPES.find((t) => t.value === s.type)?.label ?? s.type} /></TableCell>
                <TableCell>{s.username || "—"}</TableCell>
                <TableCell>{s.target || "—"}</TableCell>
                <TableCell>{s.version}</TableCell>
                <TableCell align="right">
                  {canReveal(s)
                    ? <Tooltip title="Reveal (audited)"><IconButton size="small" onClick={() => setRevealing(s)}><VisibilityIcon fontSize="small" /></IconButton></Tooltip>
                    : <Tooltip title="Check out to access"><IconButton size="small" color="warning" onClick={() => setCheckingOut(s)}><LockClockIcon fontSize="small" /></IconButton></Tooltip>}
                  {canRotate && s.type === "password" && (
                    <Tooltip title="Rotate on host"><span><IconButton size="small" disabled={rotate.isPending}
                      onClick={() => { if (window.confirm(`Rotate the password for "${s.name}" on its host now? A new value is set on the host and stored.`)) rotate.mutate(s.id); }}>
                      <AutorenewIcon fontSize="small" /></IconButton></span></Tooltip>
                  )}
                  {canRotate && s.type === "password" && (
                    <Tooltip title="Schedule automatic rotation"><IconButton size="small"
                      color={s.rotationIntervalDays > 0 ? "success" : "default"} onClick={() => setScheduling(s)}>
                      <ScheduleIcon fontSize="small" /></IconButton></Tooltip>
                  )}
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
      {checkingOut && <CheckoutDialog secret={checkingOut}
        onClose={() => setCheckingOut(null)}
        onDone={() => { setCheckingOut(null); qc.invalidateQueries({ queryKey: ["vault-my-checkouts"] }); }} />}
      {scheduling && <RotationPolicyDialog secret={scheduling}
        onClose={() => setScheduling(null)}
        onSaved={() => { setScheduling(null); invalidate(); }} />}
    </Box>
  );
}

// RotationPolicyDialog configures automatic scheduled rotation for a password
// credential. A background job rotates it on its host every N days; 0 disables it.
function RotationPolicyDialog({ secret, onClose, onSaved }: { secret: VaultSecret; onClose: () => void; onSaved: () => void }) {
  const [days, setDays] = useState<number>(secret.rotationIntervalDays || 0);
  const save = useMutation({
    mutationFn: () => setVaultRotationPolicy(secret.id, days),
    onSuccess: onSaved,
  });
  return (
    <Dialog open onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>Automatic rotation — {secret.name}</DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Rotate this password on its host automatically. A background job generates a new
          value, changes it on the host, verifies it, and stores it — no one sees the password.
          Set to “Off” to disable.
        </Typography>
        <TextField select fullWidth label="Rotate every" value={days}
          onChange={(e) => setDays(Number(e.target.value))}>
          <MenuItem value={0}>Off (manual only)</MenuItem>
          <MenuItem value={1}>1 day</MenuItem>
          <MenuItem value={7}>7 days</MenuItem>
          <MenuItem value={30}>30 days</MenuItem>
          <MenuItem value={60}>60 days</MenuItem>
          <MenuItem value={90}>90 days</MenuItem>
        </TextField>
        {secret.lastRotatedAt && (
          <Typography variant="caption" color="text.secondary" sx={{ mt: 1.5, display: "block" }}>
            Last rotated {formatDateTime(secret.lastRotatedAt)}
            {days > 0 && secret.nextRotationAt ? ` · next ${formatDateTime(secret.nextRotationAt)}` : ""}
          </Typography>
        )}
        {save.isError && <Alert severity="error" sx={{ mt: 2 }}>Could not save the rotation policy.</Alert>}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>Save</Button>
      </DialogActions>
    </Dialog>
  );
}

// CheckoutDialog requests a time-boxed check-out (self-service or pending approval).
function CheckoutDialog({ secret, onClose, onDone }: { secret: VaultSecret; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState("");
  const [minutes, setMinutes] = useState(60);
  const [msg, setMsg] = useState<string | null>(null);
  const req = useMutation({
    mutationFn: () => requestCheckout(secret.id, { reason, minutes }),
    onSuccess: (c) => { if (c.status === "pending") setMsg("Check-out requested — awaiting approval."); else onDone(); },
    onError: (e) => setMsg(((e as { response?: { data?: { error?: string } } })?.response?.data?.error) || "Could not check out."),
  });
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="xs">
      <DialogTitle>Check out {secret.name}</DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {secret.accessPolicy === "approval"
            ? "This credential requires a second person's approval before you can access it."
            : "Check out this credential for time-boxed access."}
        </Typography>
        {msg && <Alert severity={msg.includes("awaiting") ? "info" : "error"} sx={{ mb: 2 }}>{msg}</Alert>}
        <Stack spacing={2}>
          <TextField label="Reason" size="small" value={reason} onChange={(e) => setReason(e.target.value)} autoFocus />
          <TextField label="Minutes" size="small" type="number" value={minutes} sx={{ width: 140 }}
            onChange={(e) => setMinutes(Math.max(1, Math.min(480, Number(e.target.value) || 60)))} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
        <Button variant="contained" disabled={req.isPending} onClick={() => req.mutate()}>
          {secret.accessPolicy === "approval" ? "Request" : "Check out"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// CheckoutApprovalsInbox lists check-out requests awaiting the current user's
// approval. Only rendered for Credential.Approve holders.
function CheckoutApprovalsInbox() {
  const qc = useQueryClient();
  const { data: pending = [] } = useQuery({ queryKey: ["vault-checkout-approvals"], queryFn: listCheckoutApprovals });
  const refresh = () => qc.invalidateQueries({ queryKey: ["vault-checkout-approvals"] });
  const approve = useMutation({ mutationFn: (id: string) => approveCheckout(id), onSuccess: refresh });
  const deny = useMutation({ mutationFn: (id: string) => denyCheckout(id), onSuccess: refresh });
  if (pending.length === 0) return null;
  const busy = approve.isPending || deny.isPending;
  return (
    <Paper variant="outlined" sx={{ p: 1.5, mb: 2, borderColor: "warning.main" }}>
      <Typography variant="subtitle2" sx={{ mb: 1 }}>Check-outs awaiting your approval ({pending.length})</Typography>
      <Stack spacing={1}>
        {pending.map((c) => (
          <Box key={c.id} sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
            <Typography variant="body2" sx={{ flexGrow: 1, minWidth: 200 }}>
              <b>{c.username}</b> → {c.secretName}{c.reason ? ` — ${c.reason}` : ""}
            </Typography>
            <Button size="small" color="success" disabled={busy} onClick={() => approve.mutate(c.id)}>Approve</Button>
            <Button size="small" color="error" disabled={busy} onClick={() => deny.mutate(c.id)}>Deny</Button>
          </Box>
        ))}
      </Stack>
    </Paper>
  );
}

function SecretDialog({ secret, onClose, onSaved }: { secret?: VaultSecret; onClose: () => void; onSaved: () => void }) {
  const editing = !!secret;
  const [form, setForm] = useState<VaultSecretInput>({
    name: secret?.name ?? "", folder: secret?.folder ?? "", type: secret?.type ?? "password",
    username: secret?.username ?? "", target: secret?.target ?? "", description: secret?.description ?? "",
    accessPolicy: secret?.accessPolicy ?? "open", secret: "",
    externalProvider: secret?.externalProvider ?? "", externalRef: secret?.externalRef ?? "",
  });
  const [err, setErr] = useState<string | null>(null);
  const set = (patch: Partial<VaultSecretInput>) => setForm((f) => ({ ...f, ...patch }));
  const external = !!form.externalProvider;

  const save = useMutation({
    mutationFn: () => editing ? updateVaultSecret(secret!.id, form) : createVaultSecret(form),
    onSuccess: onSaved,
    onError: (e) => setErr(((e as { response?: { data?: { error?: string } } })?.response?.data?.error) || "Could not save."),
  });
  const valid = form.name.trim() && (editing || (external ? form.externalRef?.trim() : form.secret));

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
          {!editing && (
            <FormControlLabel
              control={<Checkbox size="small" checked={external}
                onChange={(e) => set({ externalProvider: e.target.checked ? "vault-kv" : "", externalRef: "" })} />}
              label="Store in an external secrets manager (HashiCorp Vault KV)" />
          )}
          {external ? (
            <TextField label="External reference" size="small" value={form.externalRef}
              onChange={(e) => set({ externalRef: e.target.value })} disabled={editing}
              placeholder="secret/db/prod#password"
              helperText="Vault KV path and field. Fleet fetches the value on demand — it is never stored here." />
          ) : (
            <TextField label={editing ? "New secret value (leave blank to keep current)" : "Secret value"} size="small" multiline minRows={form.type === "ssh_key" ? 4 : 1}
              value={form.secret} onChange={(e) => set({ secret: e.target.value })} type={form.type === "ssh_key" ? "text" : "password"} autoComplete="new-password" />
          )}
          <TextField label="Description" size="small" value={form.description} onChange={(e) => set({ description: e.target.value })} />
          <TextField select label="Access policy" size="small" value={form.accessPolicy} onChange={(e) => set({ accessPolicy: e.target.value })}
            helperText="Whether this credential requires a check-out (and approval) before it can be revealed or injected">
            <MenuItem value="open">Open — reveal/use directly per grants</MenuItem>
            <MenuItem value="checkout">Check-out required — time-boxed, self-service</MenuItem>
            <MenuItem value="approval">Approval required — a second person approves each check-out</MenuItem>
          </TextField>
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
