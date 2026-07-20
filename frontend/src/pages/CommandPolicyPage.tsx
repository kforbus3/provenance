import { useState } from "react";
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  FormControlLabel, IconButton, MenuItem, Paper, Stack, Switch, Table, TableBody,
  TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { formatDateTime } from "../lib/datetime";
import {
  listCommandPolicies, createCommandPolicy, updateCommandPolicy, deleteCommandPolicy,
  listCommandApprovals, approveCommand, denyCommand,
  type CommandPolicy, type CommandPolicyInput, type CommandAction,
} from "../api/commandPolicy";
import { listGroups } from "../api/admin";

const ACTION_COLOR: Record<CommandAction, "warning" | "error" | "info"> = {
  flag: "warning", block: "error", approval: "info",
};
const ACTION_LABEL: Record<CommandAction, string> = {
  flag: "Flag (audit + alert)", block: "Block", approval: "Approval-gated",
};

const EMPTY: CommandPolicyInput = {
  name: "", pattern: "", action: "flag", scopeKind: "global", scopeGroupId: null, enabled: true,
};

export function CommandPolicyPage() {
  const qc = useQueryClient();
  const { data: rules = [], isLoading } = useQuery({ queryKey: ["command-policies"], queryFn: listCommandPolicies });
  const { data: approvals = [] } = useQuery({
    queryKey: ["command-approvals"], queryFn: listCommandApprovals, refetchInterval: 15000,
  });
  const { data: groups = [] } = useQuery({ queryKey: ["groups"], queryFn: listGroups });

  const [editing, setEditing] = useState<CommandPolicy | null>(null);
  const [creating, setCreating] = useState(false);

  const invalidate = () => void qc.invalidateQueries({ queryKey: ["command-policies"] });
  const del = useMutation({ mutationFn: deleteCommandPolicy, onSuccess: invalidate });
  const decide = useMutation({
    mutationFn: ({ id, approve }: { id: string; approve: boolean }) => (approve ? approveCommand(id) : denyCommand(id)),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["command-approvals"] }),
  });

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h5">Command Control</Typography>
        <Box sx={{ flexGrow: 1 }} />
        <Button startIcon={<AddIcon />} variant="contained" onClick={() => setCreating(true)}>New rule</Button>
      </Stack>
      <Alert severity="info" sx={{ mb: 2 }}>
        Rules match typed command lines in interactive terminal sessions and can flag, block, or
        gate them on approval. Enforcement happens at the relay and is fully audited — it's a strong
        deterrent and complete record, but a determined insider can obfuscate (it is not an absolute
        barrier). Patterns are RE2 regular expressions matched against each command line.
      </Alert>

      {approvals.length > 0 && (
        <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
          <Typography variant="h6" sx={{ mb: 1 }}>Pending approvals ({approvals.length})</Typography>
          <Stack spacing={1}>
            {approvals.map((a) => (
              <Stack key={a.id} direction="row" alignItems="center" spacing={2}>
                <Box sx={{ flexGrow: 1 }}>
                  <Typography variant="body2">
                    <b>{a.username}</b> on <b>{a.hostname}</b> · <code>{a.command}</code>
                  </Typography>
                  <Typography variant="caption" color="text.secondary">{formatDateTime(a.requestedAt)}</Typography>
                </Box>
                <Button size="small" color="success" disabled={decide.isPending}
                  onClick={() => decide.mutate({ id: a.id, approve: true })}>Approve</Button>
                <Button size="small" color="error" disabled={decide.isPending}
                  onClick={() => decide.mutate({ id: a.id, approve: false })}>Deny</Button>
              </Stack>
            ))}
          </Stack>
          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
            Approving grants the requester a 10-minute waiver to re-run the command on that host. You
            cannot approve your own request.
          </Typography>
        </Paper>
      )}

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Pattern</TableCell>
              <TableCell>Action</TableCell>
              <TableCell>Scope</TableCell>
              <TableCell>Enabled</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {isLoading && <TableRow><TableCell colSpan={6}>Loading…</TableCell></TableRow>}
            {!isLoading && rules.length === 0 && (
              <TableRow><TableCell colSpan={6}>
                <Typography color="text.secondary">No rules yet. Add one to start enforcing command policy.</Typography>
              </TableCell></TableRow>
            )}
            {rules.map((r) => (
              <TableRow key={r.id} hover>
                <TableCell>{r.name}</TableCell>
                <TableCell sx={{ fontFamily: "monospace" }}>{r.pattern}</TableCell>
                <TableCell><Chip size="small" label={r.action} color={ACTION_COLOR[r.action]} /></TableCell>
                <TableCell>{r.scopeKind === "global" ? "All hosts" : `Group: ${r.scopeGroupName}`}</TableCell>
                <TableCell>{r.enabled ? "Yes" : "No"}</TableCell>
                <TableCell align="right">
                  <Tooltip title="Edit"><IconButton size="small" onClick={() => setEditing(r)}><EditIcon fontSize="small" /></IconButton></Tooltip>
                  <Tooltip title="Delete"><IconButton size="small" color="error"
                    onClick={() => { if (window.confirm(`Delete rule "${r.name}"?`)) del.mutate(r.id); }}>
                    <DeleteIcon fontSize="small" /></IconButton></Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <RuleDialog
        key={editing?.id ?? (creating ? "new" : "closed")}
        open={creating || editing !== null}
        rule={editing}
        groups={groups.map((g) => ({ id: g.id, name: g.name }))}
        onClose={() => { setCreating(false); setEditing(null); }}
        onSaved={() => { setCreating(false); setEditing(null); invalidate(); }}
      />
    </Box>
  );
}

function RuleDialog({
  open, rule, groups, onClose, onSaved,
}: {
  open: boolean; rule: CommandPolicy | null; groups: { id: string; name: string }[];
  onClose: () => void; onSaved: () => void;
}) {
  const [form, setForm] = useState<CommandPolicyInput>(
    rule
      ? { name: rule.name, pattern: rule.pattern, action: rule.action, scopeKind: rule.scopeKind, scopeGroupId: rule.scopeGroupId ?? null, enabled: rule.enabled }
      : EMPTY,
  );
  const [error, setError] = useState<string | null>(null);
  const set = <K extends keyof CommandPolicyInput>(k: K, v: CommandPolicyInput[K]) =>
    setForm((f) => ({ ...f, [k]: v }));

  const save = useMutation({
    mutationFn: () => (rule ? updateCommandPolicy(rule.id, form) : createCommandPolicy(form)),
    onSuccess: onSaved,
    onError: (e: unknown) =>
      setError((e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Could not save rule"),
  });

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{rule ? "Edit rule" : "New command rule"}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField label="Name" size="small" value={form.name} onChange={(e) => set("name", e.target.value)} fullWidth />
          <TextField
            label="Pattern (regular expression)" size="small" value={form.pattern}
            onChange={(e) => set("pattern", e.target.value)} fullWidth
            sx={{ "& input": { fontFamily: "monospace" } }}
            helperText="Matched against each command line, e.g. rm\\s+-rf\\s+/ or ^shutdown"
          />
          <TextField select label="Action" size="small" value={form.action}
            onChange={(e) => set("action", e.target.value as CommandAction)} fullWidth>
            {(["flag", "block", "approval"] as CommandAction[]).map((a) => (
              <MenuItem key={a} value={a}>{ACTION_LABEL[a]}</MenuItem>
            ))}
          </TextField>
          <TextField select label="Scope" size="small" value={form.scopeKind}
            onChange={(e) => set("scopeKind", e.target.value as "global" | "group")} fullWidth>
            <MenuItem value="global">All hosts (global)</MenuItem>
            <MenuItem value="group">A host group</MenuItem>
          </TextField>
          {form.scopeKind === "group" && (
            <TextField select label="Group" size="small" value={form.scopeGroupId ?? ""}
              onChange={(e) => set("scopeGroupId", e.target.value)} fullWidth>
              {groups.map((g) => <MenuItem key={g.id} value={g.id}>{g.name}</MenuItem>)}
            </TextField>
          )}
          <FormControlLabel
            control={<Switch checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} />}
            label="Enabled"
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={save.isPending} onClick={() => { setError(null); save.mutate(); }}>
          {save.isPending ? "Saving…" : "Save"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
