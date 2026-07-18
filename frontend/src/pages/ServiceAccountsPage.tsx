import { useMemo, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, Dialog, DialogActions, DialogContent,
  DialogTitle, IconButton, MenuItem, Paper, Stack, Table, TableBody, TableCell,
  TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import KeyIcon from "@mui/icons-material/Key";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { formatDateTime } from "../lib/datetime";
import { listRoles, listGroups } from "../api/admin";
import {
  listServiceAccounts, createServiceAccount, updateServiceAccount, deleteServiceAccount,
  listTokens, createToken, revokeToken, type ServiceAccount, type ApiToken,
} from "../api/serviceAccounts";

const EXPIRY_OPTIONS = [
  { label: "30 days", days: 30 },
  { label: "90 days", days: 90 },
  { label: "1 year", days: 365 },
  { label: "No expiry", days: 0 },
];

// ServiceAccountsPage manages non-human identities and their API tokens for
// automation (CI/CD, IaC, monitoring). Gated by ServiceAccount.Manage.
export function ServiceAccountsPage() {
  const qc = useQueryClient();
  const { data: accounts = [], isLoading } = useQuery({
    queryKey: ["service-accounts"], queryFn: listServiceAccounts,
  });
  const { data: roles = [] } = useQuery({ queryKey: ["roles"], queryFn: listRoles });
  const { data: groups = [] } = useQuery({ queryKey: ["groups"], queryFn: listGroups });

  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<ServiceAccount | null>(null);
  const [tokensFor, setTokensFor] = useState<ServiceAccount | null>(null);

  const invalidate = () => qc.invalidateQueries({ queryKey: ["service-accounts"] });

  return (
    <Box sx={{ maxWidth: 1100 }}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
        <Box>
          <Typography variant="h5">Service accounts</Typography>
          <Typography variant="body2" color="text.secondary">
            Non-human identities for automation. Each authenticates via API tokens and reaches hosts
            through its group memberships, with permissions from its roles.
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreating(true)}>
          New service account
        </Button>
      </Stack>

      <Paper variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Roles</TableCell>
              <TableCell>Groups</TableCell>
              <TableCell align="right">Tokens</TableCell>
              <TableCell>Last used</TableCell>
              <TableCell>Status</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {accounts.map((sa) => (
              <TableRow key={sa.id}>
                <TableCell>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>{sa.username}</Typography>
                  {sa.displayName && <Typography variant="caption" color="text.secondary">{sa.displayName}</Typography>}
                </TableCell>
                <TableCell><ChipList items={sa.roles} empty="none" /></TableCell>
                <TableCell><ChipList items={sa.groups} empty="no host access" /></TableCell>
                <TableCell align="right">{sa.tokenCount}</TableCell>
                <TableCell>{sa.lastUsedAt ? formatDateTime(sa.lastUsedAt) : "—"}</TableCell>
                <TableCell>
                  <Chip size="small" label={sa.isDisabled ? "disabled" : "active"}
                    color={sa.isDisabled ? "default" : "success"} />
                </TableCell>
                <TableCell align="right">
                  <Tooltip title="Manage tokens">
                    <IconButton size="small" onClick={() => setTokensFor(sa)}><KeyIcon fontSize="small" /></IconButton>
                  </Tooltip>
                  <Tooltip title="Edit">
                    <IconButton size="small" onClick={() => setEditing(sa)}><EditIcon fontSize="small" /></IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {accounts.length === 0 && (
              <TableRow>
                <TableCell colSpan={7}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                    {isLoading ? "Loading…" : "No service accounts yet. Create one to issue API tokens for automation."}
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>

      {creating && (
        <EditDialog
          title="New service account"
          roles={roles} groups={groups}
          onClose={() => setCreating(false)}
          onSave={async (v) => {
            await createServiceAccount({
              username: v.username, displayName: v.displayName, roleIds: v.roleIds, groupIds: v.groupIds,
            });
            invalidate(); setCreating(false);
          }}
        />
      )}

      {editing && (
        <EditDialog
          title={`Edit ${editing.username}`}
          initial={editing} roles={roles} groups={groups}
          onClose={() => setEditing(null)}
          onDelete={async () => { await deleteServiceAccount(editing.id); invalidate(); setEditing(null); }}
          onSave={async (v) => {
            await updateServiceAccount(editing.id, {
              displayName: v.displayName, disabled: v.disabled, roleIds: v.roleIds, groupIds: v.groupIds,
            });
            invalidate(); setEditing(null);
          }}
        />
      )}

      {tokensFor && (
        <TokensDialog sa={tokensFor} onClose={() => { setTokensFor(null); invalidate(); }} />
      )}
    </Box>
  );
}

function ChipList({ items, empty }: { items: string[]; empty: string }) {
  if (!items.length) return <Typography variant="caption" color="text.secondary">{empty}</Typography>;
  return (
    <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
      {items.map((i) => <Chip key={i} size="small" label={i} />)}
    </Stack>
  );
}

interface NamedOption { id: string; name: string }

function EditDialog({
  title, initial, roles, groups, onClose, onSave, onDelete,
}: {
  title: string;
  initial?: ServiceAccount;
  roles: NamedOption[];
  groups: NamedOption[];
  onClose: () => void;
  onSave: (v: { username: string; displayName: string; disabled: boolean; roleIds: string[]; groupIds: string[] }) => Promise<void>;
  onDelete?: () => Promise<void>;
}) {
  const roleByName = useMemo(() => new Map(roles.map((r) => [r.name, r])), [roles]);
  const groupByName = useMemo(() => new Map(groups.map((g) => [g.name, g])), [groups]);

  const [username, setUsername] = useState(initial?.username ?? "");
  const [displayName, setDisplayName] = useState(initial?.displayName ?? "");
  const [disabled, setDisabled] = useState(initial?.isDisabled ?? false);
  const [selRoles, setSelRoles] = useState<NamedOption[]>(
    (initial?.roles ?? []).map((n) => roleByName.get(n)).filter(Boolean) as NamedOption[]);
  const [selGroups, setSelGroups] = useState<NamedOption[]>(
    (initial?.groups ?? []).map((n) => groupByName.get(n)).filter(Boolean) as NamedOption[]);
  const [err, setErr] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: () => onSave({
      username: username.trim(), displayName: displayName.trim(), disabled,
      roleIds: selRoles.map((r) => r.id), groupIds: selGroups.map((g) => g.id),
    }),
    onError: (e: unknown) => setErr(errMsg(e)),
  });
  const del = useMutation({ mutationFn: () => onDelete!(), onError: (e: unknown) => setErr(errMsg(e)) });

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          {err && <Alert severity="error">{err}</Alert>}
          {!initial ? (
            <TextField
              label="Username" size="small" value={username} autoFocus
              onChange={(e) => setUsername(e.target.value)}
              helperText="Lowercase identifier for the account, e.g. gitlab-ci"
            />
          ) : (
            <TextField label="Username" size="small" value={username} disabled />
          )}
          <TextField
            label="Display name" size="small" value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            helperText="Human-friendly description, e.g. GitLab CI runner"
          />
          <Autocomplete
            multiple size="small" options={roles} getOptionLabel={(o) => o.name}
            value={selRoles} onChange={(_, v) => setSelRoles(v)}
            isOptionEqualToValue={(a, b) => a.id === b.id}
            renderInput={(p) => <TextField {...p} label="Roles (permissions)" />}
          />
          <Autocomplete
            multiple size="small" options={groups} getOptionLabel={(o) => o.name}
            value={selGroups} onChange={(_, v) => setSelGroups(v)}
            isOptionEqualToValue={(a, b) => a.id === b.id}
            renderInput={(p) => <TextField {...p} label="Groups (host access)" />}
          />
          {initial && (
            <TextField
              select size="small" label="Status" value={disabled ? "disabled" : "active"}
              onChange={(e) => setDisabled(e.target.value === "disabled")}
            >
              <MenuItem value="active">Active</MenuItem>
              <MenuItem value="disabled">Disabled (all tokens refused)</MenuItem>
            </TextField>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        {onDelete && (
          <Button color="error" startIcon={<DeleteIcon />} disabled={del.isPending}
            onClick={() => { if (confirm("Delete this service account and all its tokens?")) del.mutate(); }}>
            Delete
          </Button>
        )}
        <Box sx={{ flexGrow: 1 }} />
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={() => save.mutate()}
          disabled={save.isPending || (!initial && !username.trim())}>
          Save
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function TokensDialog({ sa, onClose }: { sa: ServiceAccount; onClose: () => void }) {
  const qc = useQueryClient();
  const { data: tokens = [] } = useQuery({
    queryKey: ["sa-tokens", sa.id], queryFn: () => listTokens(sa.id),
  });
  const [name, setName] = useState("");
  const [days, setDays] = useState(90);
  const [created, setCreated] = useState<ApiToken | null>(null);
  const [copied, setCopied] = useState(false);
  const refresh = () => qc.invalidateQueries({ queryKey: ["sa-tokens", sa.id] });

  const create = useMutation({
    mutationFn: () => createToken(sa.id, { name: name.trim(), expiresInDays: days }),
    onSuccess: (t) => { setCreated(t); setName(""); refresh(); },
  });
  const revoke = useMutation({
    mutationFn: (tokenId: string) => revokeToken(sa.id, tokenId),
    onSuccess: refresh,
  });

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>Tokens — {sa.username}</DialogTitle>
      <DialogContent>
        {created?.secret && (
          <Alert severity="success" sx={{ mb: 2 }}
            action={
              <Button size="small" startIcon={<ContentCopyIcon />}
                onClick={() => { navigator.clipboard?.writeText(created.secret!); setCopied(true); }}>
                {copied ? "Copied" : "Copy"}
              </Button>
            }>
            <Typography variant="body2" sx={{ fontWeight: 600 }}>Copy this token now — it won't be shown again.</Typography>
            <Box component="code" sx={{ display: "block", mt: 0.5, fontFamily: "monospace", wordBreak: "break-all" }}>
              {created.secret}
            </Box>
          </Alert>
        )}

        <Stack direction="row" spacing={1} sx={{ mb: 2 }} alignItems="flex-start" flexWrap="wrap">
          <TextField size="small" label="New token name" value={name}
            onChange={(e) => { setName(e.target.value); setCreated(null); setCopied(false); }}
            placeholder="e.g. gitlab-ci" />
          <TextField select size="small" label="Expiry" value={days} sx={{ minWidth: 130 }}
            onChange={(e) => setDays(Number(e.target.value))}>
            {EXPIRY_OPTIONS.map((o) => <MenuItem key={o.label} value={o.days}>{o.label}</MenuItem>)}
          </TextField>
          <Button variant="contained" sx={{ mt: 0.25 }} disabled={!name.trim() || create.isPending}
            onClick={() => create.mutate()}>
            Create token
          </Button>
        </Stack>

        <Paper variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Prefix</TableCell>
                <TableCell>Created</TableCell>
                <TableCell>Expires</TableCell>
                <TableCell>Last used</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right"></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {tokens.map((t) => {
                const expired = t.expiresAt && new Date(t.expiresAt).getTime() < Date.now();
                const status = t.revokedAt ? "revoked" : expired ? "expired" : "active";
                return (
                  <TableRow key={t.id}>
                    <TableCell>{t.name}</TableCell>
                    <TableCell><code>{t.prefix}…</code></TableCell>
                    <TableCell>{formatDateTime(t.createdAt)}</TableCell>
                    <TableCell>{t.expiresAt ? formatDateTime(t.expiresAt) : "never"}</TableCell>
                    <TableCell>{t.lastUsedAt ? formatDateTime(t.lastUsedAt) : "—"}</TableCell>
                    <TableCell>
                      <Chip size="small" label={status}
                        color={status === "active" ? "success" : "default"} />
                    </TableCell>
                    <TableCell align="right">
                      {status === "active" && (
                        <Button size="small" color="error"
                          disabled={revoke.isPending}
                          onClick={() => { if (confirm(`Revoke token "${t.name}"?`)) revoke.mutate(t.id); }}>
                          Revoke
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
              {tokens.length === 0 && (
                <TableRow><TableCell colSpan={7}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>No tokens yet.</Typography>
                </TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </Paper>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

function errMsg(e: unknown): string {
  const r = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
  return r || "Request failed.";
}
