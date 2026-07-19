import { useEffect, useState } from "react";
import { formatDateTime } from "../lib/datetime";
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  Divider, FormControlLabel, IconButton, List, ListItem, ListItemText, Menu,
  MenuItem, Snackbar, Stack, Switch, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, TextField, Typography, Paper, Tooltip,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import EditIcon from "@mui/icons-material/Edit";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import DnsIcon from "@mui/icons-material/Dns";
import SecurityIcon from "@mui/icons-material/Security";
import { Checkbox, FormGroup } from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  assignUserRole, createUser, deleteUser, getGlobalRequireMFA, listRoles, listUsers,
  removeUserRole, resetUserMFA, resetUserPassword, restoreUserHostAccess,
  revokeUserHostAccess, setGlobalRequireMFA, setUserDisabled, setUserRequireMFA,
  terminateUserSessions, unlockUser, updateUser, userHostAccess, userLoginHistory,
  getUserSessionPolicy, setUserSessionPolicy, clearUserSessionPolicy,
  type AuthEvent, type CreateUserInput, type User,
} from "../api/admin";

const EMPTY_CREATE: CreateUserInput = {
  username: "", email: "", displayName: "", password: "",
  isSuperAdmin: false, mustChangePassword: true,
};

// User administration: listing, creation, edit, and deletion against the admin
// API. Mutations invalidate the cached user list on success.
export function UsersPage() {
  const qc = useQueryClient();
  const { data: users = [], isLoading } = useQuery({ queryKey: ["users"], queryFn: listUsers });

  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState<CreateUserInput>(EMPTY_CREATE);
  const [editing, setEditing] = useState<User | null>(null);
  const [menuEl, setMenuEl] = useState<null | HTMLElement>(null);
  const [menuUser, setMenuUser] = useState<User | null>(null);
  const [snack, setSnack] = useState<string | null>(null);
  const [history, setHistory] = useState<{ user: User; events: AuthEvent[] } | null>(null);
  const [hostAccessUser, setHostAccessUser] = useState<User | null>(null);
  const [rolesUser, setRolesUser] = useState<User | null>(null);
  const [policyUser, setPolicyUser] = useState<User | null>(null);

  // Per-user host access: the hosts a user can reach plus revoke/restore controls.
  const { data: hostAccess = [], isLoading: hostAccessLoading } = useQuery({
    queryKey: ["user-host-access", hostAccessUser?.id],
    queryFn: () => userHostAccess(hostAccessUser!.id),
    enabled: Boolean(hostAccessUser),
  });
  const hostAccessMut = useMutation({
    mutationFn: ({ hostId, action }: { hostId: string; action: "revoke" | "restore" }) =>
      action === "revoke"
        ? revokeUserHostAccess(hostAccessUser!.id, hostId)
        : restoreUserHostAccess(hostAccessUser!.id, hostId),
    onSuccess: (_res, vars) => {
      setSnack(vars.action === "revoke" ? "Access removed" : "Access restored");
      qc.invalidateQueries({ queryKey: ["user-host-access", hostAccessUser?.id] });
    },
    onError: (_e, vars) => setSnack(vars.action === "revoke" ? "Failed to remove access" : "Failed to restore access"),
  });

  const { data: allRoles = [] } = useQuery({ queryKey: ["roles"], queryFn: listRoles });
  const roleMut = useMutation({
    mutationFn: ({ userId, roleId, assign }: { userId: string; roleId: string; assign: boolean }) =>
      assign ? assignUserRole(userId, roleId) : removeUserRole(userId, roleId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });

  const { data: globalMfa = false } = useQuery({ queryKey: ["global-require-mfa"], queryFn: getGlobalRequireMFA });
  const globalMfaMut = useMutation({
    mutationFn: (enabled: boolean) => setGlobalRequireMFA(enabled),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["global-require-mfa"] }),
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["users"] });

  const openMenu = (el: HTMLElement, u: User) => { setMenuEl(el); setMenuUser(u); };
  const closeMenu = () => { setMenuEl(null); setMenuUser(null); };

  // Run an admin action against the menu's user, show feedback, refresh.
  const runAction = async (label: string, fn: (id: string) => Promise<void>) => {
    if (!menuUser) return;
    const u = menuUser;
    closeMenu();
    try {
      await fn(u.id);
      setSnack(`${label}: ${u.username}`);
      invalidate();
    } catch {
      setSnack(`Failed: ${label}`);
    }
  };

  const createMut = useMutation({
    mutationFn: () => createUser(form),
    onSuccess: () => { setCreateOpen(false); setForm(EMPTY_CREATE); invalidate(); },
  });
  const updateMut = useMutation({
    mutationFn: async (u: User) => {
      await updateUser(u.id, { email: u.email ?? "", displayName: u.displayName, isDisabled: u.isDisabled });
      await setUserRequireMFA(u.id, u.requireMfa);
    },
    onSuccess: () => { setEditing(null); invalidate(); },
  });
  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteUser(id),
    onSuccess: invalidate,
  });

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }} spacing={2}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>User Management</Typography>
        <Tooltip title="When on, every user must enroll a second factor before a session is issued.">
          <FormControlLabel
            control={<Switch checked={globalMfa} disabled={globalMfaMut.isPending}
              onChange={(e) => globalMfaMut.mutate(e.target.checked)} />}
            label="Require MFA for all"
          />
        </Tooltip>
        <Button startIcon={<AddIcon />} variant="contained" onClick={() => setCreateOpen(true)}>
          New User
        </Button>
      </Stack>

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Username</TableCell>
              <TableCell>Display Name</TableCell>
              <TableCell>Email</TableCell>
              <TableCell>Roles</TableCell>
              <TableCell>Status</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {users.map((u) => (
              <TableRow key={u.id} hover>
                <TableCell>{u.username}{u.isSuperAdmin && (
                  <Chip label="super" size="small" color="secondary" sx={{ ml: 1 }} />
                )}</TableCell>
                <TableCell>{u.displayName}</TableCell>
                <TableCell>{u.email}</TableCell>
                <TableCell>{(u.roles ?? []).join(", ")}</TableCell>
                <TableCell>
                  <Chip
                    label={u.isDisabled ? "disabled" : "active"}
                    color={u.isDisabled ? "default" : "success"}
                    size="small"
                  />
                  {(u.requireMfa || globalMfa) && (
                    <Chip label="MFA" size="small" color="primary" variant="outlined" sx={{ ml: 1 }} />
                  )}
                </TableCell>
                <TableCell align="right">
                  <Tooltip title="Manage host access">
                    <IconButton size="small" onClick={() => setHostAccessUser(u)}>
                      <DnsIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Manage roles">
                    <IconButton size="small" onClick={() => setRolesUser(u)}><SecurityIcon fontSize="small" /></IconButton>
                  </Tooltip>
                  <Tooltip title="Edit">
                    <IconButton size="small" onClick={() => setEditing(u)}><EditIcon fontSize="small" /></IconButton>
                  </Tooltip>
                  <Tooltip title="Delete">
                    <IconButton size="small" onClick={() => deleteMut.mutate(u.id)}><DeleteIcon fontSize="small" /></IconButton>
                  </Tooltip>
                  <Tooltip title="More actions">
                    <IconButton size="small" onClick={(e) => openMenu(e.currentTarget, u)}>
                      <MoreVertIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {!isLoading && users.length === 0 && (
              <TableRow><TableCell colSpan={6}>
                <Typography color="text.secondary">No users yet.</Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>New User</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Username" value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })} required />
            <TextField label="Display Name" value={form.displayName}
              onChange={(e) => setForm({ ...form, displayName: e.target.value })} />
            <TextField label="Email" type="email" value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })} />
            <TextField label="Password" type="password" value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })} required />
            <FormControlLabel control={
              <Switch checked={form.isSuperAdmin}
                onChange={(e) => setForm({ ...form, isSuperAdmin: e.target.checked })} />
            } label="Super admin" />
            <FormControlLabel control={
              <Switch checked={form.mustChangePassword}
                onChange={(e) => setForm({ ...form, mustChangePassword: e.target.checked })} />
            } label="Must change password" />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button variant="contained" disabled={!form.username || !form.password || createMut.isPending}
            onClick={() => createMut.mutate()}>Create</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={editing !== null} onClose={() => setEditing(null)} fullWidth maxWidth="sm">
        <DialogTitle>Edit User</DialogTitle>
        <DialogContent>
          {editing && (
            <Stack spacing={2} sx={{ mt: 1 }}>
              <TextField label="Username" value={editing.username} disabled />
              <TextField label="Display Name" value={editing.displayName}
                onChange={(e) => setEditing({ ...editing, displayName: e.target.value })} />
              <TextField label="Email" type="email" value={editing.email ?? ""}
                onChange={(e) => setEditing({ ...editing, email: e.target.value })} />
              <FormControlLabel control={
                <Switch checked={editing.isDisabled}
                  onChange={(e) => setEditing({ ...editing, isDisabled: e.target.checked })} />
              } label="Disabled" />
              <FormControlLabel control={
                <Switch checked={editing.requireMfa}
                  onChange={(e) => setEditing({ ...editing, requireMfa: e.target.checked })} />
              } label="Require MFA (force enrollment at next sign-in)" />
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditing(null)}>Cancel</Button>
          <Button variant="contained" disabled={updateMut.isPending}
            onClick={() => editing && updateMut.mutate(editing)}>Save</Button>
        </DialogActions>
      </Dialog>

      <Menu anchorEl={menuEl} open={Boolean(menuEl)} onClose={closeMenu}>
        <MenuItem onClick={() => runAction(menuUser?.isDisabled ? "Enabled" : "Disabled",
          (id) => setUserDisabled(id, !menuUser?.isDisabled))}>
          {menuUser?.isDisabled ? "Enable account" : "Disable account"}
        </MenuItem>
        <MenuItem onClick={() => runAction("Unlocked", unlockUser)}>Unlock account</MenuItem>
        <Divider />
        <MenuItem onClick={() => {
          const pw = window.prompt("New password for " + menuUser?.username);
          if (pw) void runAction("Password reset", (id) => resetUserPassword(id, pw, true));
          else closeMenu();
        }}>Reset password…</MenuItem>
        <MenuItem onClick={() => runAction("MFA reset", resetUserMFA)}>Reset MFA</MenuItem>
        <MenuItem onClick={() => runAction("Sessions terminated", terminateUserSessions)}>
          Terminate sessions
        </MenuItem>
        <Divider />
        <MenuItem onClick={async () => {
          if (!menuUser) return;
          const u = menuUser; closeMenu();
          try { setHistory({ user: u, events: await userLoginHistory(u.id) }); }
          catch { setSnack("Failed to load history"); }
        }}>Login history…</MenuItem>
        <MenuItem onClick={() => { const u = menuUser; closeMenu(); setPolicyUser(u); }}>
          Access policy…
        </MenuItem>
      </Menu>

      <SessionPolicyDialog user={policyUser} onClose={() => setPolicyUser(null)} onSaved={setSnack} />

      <Dialog open={Boolean(history)} onClose={() => setHistory(null)} fullWidth maxWidth="sm">
        <DialogTitle>Login history — {history?.user.username}</DialogTitle>
        <DialogContent dividers>
          <List dense>
            {(history?.events ?? []).map((e) => (
              <ListItem key={e.id} disableGutters>
                <ListItemText
                  primary={`${e.event}${e.ip ? "  ·  " + e.ip : ""}`}
                  secondary={formatDateTime(e.createdAt)}
                />
              </ListItem>
            ))}
            {history && history.events.length === 0 && (
              <ListItem><ListItemText primary="No events" /></ListItem>
            )}
          </List>
        </DialogContent>
        <DialogActions><Button onClick={() => setHistory(null)}>Close</Button></DialogActions>
      </Dialog>

      <Dialog open={Boolean(hostAccessUser)} onClose={() => setHostAccessUser(null)} fullWidth maxWidth="md">
        <DialogTitle>Host access — {hostAccessUser?.username}</DialogTitle>
        <DialogContent dividers>
          <List dense>
            {hostAccess.map((h) => (
              <ListItem
                key={h.id}
                disableGutters
                secondaryAction={h.denied ? (
                  <Button size="small" color="primary" disabled={hostAccessMut.isPending}
                    onClick={() => hostAccessMut.mutate({ hostId: h.id, action: "restore" })}>
                    Restore
                  </Button>
                ) : (
                  <Button size="small" color="error" disabled={hostAccessMut.isPending}
                    onClick={() => {
                      if (window.confirm(`Remove access to ${h.hostname} for ${hostAccessUser?.username}?`))
                        hostAccessMut.mutate({ hostId: h.id, action: "revoke" });
                    }}>
                    Remove
                  </Button>
                )}
              >
                <ListItemText
                  primary={
                    <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                      <Typography variant="body2">{h.hostname}</Typography>
                      {h.viaDirect && <Chip label="Direct" size="small" variant="outlined" />}
                      {h.viaGroup && <Chip label="Group" size="small" variant="outlined" />}
                      {h.viaTemp && <Chip label="Temporary" size="small" variant="outlined" />}
                      {h.denied && <Chip label="Denied" size="small" color="warning" />}
                    </Stack>
                  }
                  secondary={[h.environment, h.owner, h.address].filter(Boolean).join("  ·  ")}
                />
              </ListItem>
            ))}
            {hostAccessUser && !hostAccessLoading && hostAccess.length === 0 && (
              <ListItem><ListItemText
                primary="No accessible hosts"
                secondary="Grant access via a group or directly from a host's Manage access dialog."
              /></ListItem>
            )}
          </List>
        </DialogContent>
        <DialogActions><Button onClick={() => setHostAccessUser(null)}>Close</Button></DialogActions>
      </Dialog>

      <Dialog open={Boolean(rolesUser)} onClose={() => setRolesUser(null)} fullWidth maxWidth="xs">
        <DialogTitle>Roles — {rolesUser?.username}</DialogTitle>
        <DialogContent dividers>
          {(() => {
            // Use live user data so checkboxes reflect assignments after toggling.
            const live = users.find((u) => u.id === rolesUser?.id) ?? rolesUser;
            const assigned = new Set(live?.roles ?? []);
            return (
              <FormGroup>
                {allRoles.map((r) => (
                  <FormControlLabel
                    key={r.id}
                    control={
                      <Checkbox
                        checked={assigned.has(r.name)}
                        disabled={roleMut.isPending}
                        onChange={(e) =>
                          rolesUser && roleMut.mutate({ userId: rolesUser.id, roleId: r.id, assign: e.target.checked })
                        }
                      />
                    }
                    label={r.name}
                  />
                ))}
                {allRoles.length === 0 && (
                  <Typography variant="body2" color="text.secondary">No roles defined.</Typography>
                )}
              </FormGroup>
            );
          })()}
        </DialogContent>
        <DialogActions><Button onClick={() => setRolesUser(null)}>Close</Button></DialogActions>
      </Dialog>

      <Snackbar
        open={Boolean(snack)} autoHideDuration={3000} onClose={() => setSnack(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      >
        <Alert severity="info" onClose={() => setSnack(null)}>{snack}</Alert>
      </Snackbar>
    </Box>
  );
}

// SessionPolicyDialog edits a user's per-user conditional-access override. Each
// dimension (IP allowlist, concurrent-session limit) can independently override
// the global policy or inherit it. Unchecking both and saving removes the
// override entirely so the user follows the fleet-wide defaults.
function SessionPolicyDialog({
  user, onClose, onSaved,
}: { user: User | null; onClose: () => void; onSaved: (msg: string) => void }) {
  const qc = useQueryClient();
  const { data } = useQuery({
    queryKey: ["user-session-policy", user?.id],
    queryFn: () => getUserSessionPolicy(user!.id),
    enabled: Boolean(user),
  });

  const [overrideIP, setOverrideIP] = useState(false);
  const [allowlist, setAllowlist] = useState("");
  const [overrideLimit, setOverrideLimit] = useState(false);
  const [limit, setLimit] = useState("0");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!data) return;
    const ov = data.override;
    setOverrideIP(ov?.ipAllowlist != null);
    setAllowlist((ov?.ipAllowlist ?? []).join("\n"));
    setOverrideLimit(ov?.maxConcurrentSessions != null);
    setLimit(String(ov?.maxConcurrentSessions ?? 0));
    setError(null);
  }, [data]);

  const parseAllowlist = () => allowlist.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);

  const save = useMutation({
    mutationFn: async () => {
      const ipAllowlist = overrideIP ? parseAllowlist() : null;
      const maxConcurrentSessions = overrideLimit ? Math.max(0, Number(limit) || 0) : null;
      if (ipAllowlist == null && maxConcurrentSessions == null) {
        await clearUserSessionPolicy(user!.id);
      } else {
        await setUserSessionPolicy(user!.id, { ipAllowlist, maxConcurrentSessions });
      }
    },
    onSuccess: () => {
      onSaved(`Access policy saved: ${user?.username}`);
      void qc.invalidateQueries({ queryKey: ["user-session-policy", user?.id] });
      onClose();
    },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setError(msg ?? "Could not save policy.");
    },
  });

  const g = data?.global;
  return (
    <Dialog open={Boolean(user)} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Access policy — {user?.username}</DialogTitle>
      <DialogContent dividers>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Override the fleet-wide conditional-access policy for this user. Each control below either
          overrides the global default or inherits it.
        </Typography>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        <Stack spacing={2}>
          <Box>
            <FormControlLabel
              control={<Switch checked={overrideIP} onChange={(e) => setOverrideIP(e.target.checked)} />}
              label="Override IP allowlist"
            />
            {overrideIP ? (
              <TextField
                fullWidth label="IP allowlist (one CIDR or IP per line)" multiline minRows={3}
                value={allowlist} onChange={(e) => setAllowlist(e.target.value)}
                sx={{ "& textarea": { fontFamily: "monospace" }, mt: 1 }}
                helperText="Leave empty to exempt this user from any global IP restriction."
              />
            ) : (
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", ml: 4 }}>
                Inherits global: {g && g.ipAllowlist.length > 0 ? g.ipAllowlist.join(", ") : "no IP restriction"}
              </Typography>
            )}
          </Box>
          <Box>
            <FormControlLabel
              control={<Switch checked={overrideLimit} onChange={(e) => setOverrideLimit(e.target.checked)} />}
              label="Override concurrent-session limit"
            />
            {overrideLimit ? (
              <TextField
                label="Max concurrent sessions" type="number" size="small" value={limit}
                onChange={(e) => setLimit(e.target.value)} inputProps={{ min: 0 }}
                sx={{ width: 240, ml: 4, mt: 1, display: "block" }}
                helperText="0 = unlimited"
              />
            ) : (
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", ml: 4 }}>
                Inherits global: {g ? (g.maxConcurrentSessions > 0 ? `${g.maxConcurrentSessions} sessions` : "unlimited") : "—"}
              </Typography>
            )}
          </Box>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>Save</Button>
      </DialogActions>
    </Dialog>
  );
}
