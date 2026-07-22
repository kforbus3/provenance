import { useState } from "react";
import {
  Alert, Box, Button, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  FormControlLabel, FormGroup, IconButton, Paper, Stack, Switch, Table, TableBody,
  TableCell, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import GavelIcon from "@mui/icons-material/Gavel";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listAccessPolicies, createAccessPolicy, updateAccessPolicy, deleteAccessPolicy,
  type AccessPolicy, type AccessPolicyInput,
} from "../api/accessPolicy";

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

const toHHMM = (min: number) => `${String(Math.floor(min / 60)).padStart(2, "0")}:${String(min % 60).padStart(2, "0")}`;
const fromHHMM = (s: string) => {
  const [h, m] = s.split(":").map(Number);
  return (h || 0) * 60 + (m || 0);
};
const csv = (a: string[]) => a.join(", ");
const parseCsv = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);

// AccessPolicyPage manages attribute-based access-control (ABAC) deny rules that apply
// on top of RBAC at connect time. Super administrators are always exempt.
export function AccessPolicyPage() {
  const qc = useQueryClient();
  const { data: policies = [], isLoading } = useQuery({ queryKey: ["access-policies"], queryFn: listAccessPolicies });
  const [editing, setEditing] = useState<AccessPolicy | null>(null);
  const [creating, setCreating] = useState(false);
  const invalidate = () => qc.invalidateQueries({ queryKey: ["access-policies"] });
  const del = useMutation({ mutationFn: (id: string) => deleteAccessPolicy(id), onSuccess: invalidate });

  return (
    <Box sx={{ maxWidth: 1150 }}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
        <Box>
          <Typography variant="h5">Access policies</Typography>
          <Typography variant="body2" color="text.secondary">
            Attribute-based rules that <b>deny</b> a host connection RBAC would otherwise allow — by
            environment, tag, protocol, and time of day. Policies only restrict; they never grant access.
            Super administrators are always exempt.
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreating(true)}>New policy</Button>
      </Stack>

      <Paper variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Priority</TableCell>
              <TableCell>Name</TableCell>
              <TableCell>Applies to</TableCell>
              <TableCell>When</TableCell>
              <TableCell>Enabled</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {policies.map((p) => (
              <TableRow key={p.id} hover>
                <TableCell>{p.priority}</TableCell>
                <TableCell>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>{p.name}</Typography>
                  {p.description && <Typography variant="caption" color="text.secondary">{p.description}</Typography>}
                </TableCell>
                <TableCell><Typography variant="caption">{appliesSummary(p)}</Typography></TableCell>
                <TableCell><Typography variant="caption">{whenSummary(p)}</Typography></TableCell>
                <TableCell>
                  <Chip size="small" label={p.enabled ? "enabled" : "disabled"} color={p.enabled ? "success" : "default"}
                    variant={p.enabled ? "filled" : "outlined"} />
                </TableCell>
                <TableCell align="right">
                  <Tooltip title="Edit"><IconButton size="small" onClick={() => setEditing(p)}><EditIcon fontSize="small" /></IconButton></Tooltip>
                  <Tooltip title="Delete"><IconButton size="small" color="error"
                    onClick={() => { if (window.confirm(`Delete policy "${p.name}"?`)) del.mutate(p.id); }}>
                    <DeleteIcon fontSize="small" /></IconButton></Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {policies.length === 0 && (
              <TableRow><TableCell colSpan={6}>
                <Stack alignItems="center" spacing={1} sx={{ py: 3 }} color="text.secondary">
                  <GavelIcon />
                  <Typography variant="body2">{isLoading ? "Loading…" : "No access policies. RBAC alone governs access."}</Typography>
                </Stack>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>

      {creating && <PolicyDialog onClose={() => setCreating(false)} onSaved={() => { setCreating(false); invalidate(); }} />}
      {editing && <PolicyDialog policy={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); invalidate(); }} />}
    </Box>
  );
}

function appliesSummary(p: AccessPolicy): string {
  const parts: string[] = [];
  if (p.environments.length) parts.push(`env: ${csv(p.environments)}`);
  if (p.tags.length) parts.push(`tags: ${csv(p.tags)}`);
  if (p.protocols.length) parts.push(csv(p.protocols));
  if (p.exemptRoles.length) parts.push(`except ${csv(p.exemptRoles)}`);
  return parts.length ? parts.join(" · ") : "all hosts";
}

function whenSummary(p: AccessPolicy): string {
  const days = p.activeDays.length ? p.activeDays.slice().sort().map((d) => DAYS[d]).join(",") : "every day";
  const time = p.activeStartMin === p.activeEndMin ? "all day" : `${toHHMM(p.activeStartMin)}–${toHHMM(p.activeEndMin)}`;
  return `${days}, ${time}`;
}

function PolicyDialog({ policy, onClose, onSaved }: { policy?: AccessPolicy; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState<AccessPolicyInput>({
    name: policy?.name ?? "",
    description: policy?.description ?? "",
    enabled: policy?.enabled ?? true,
    priority: policy?.priority ?? 100,
    environments: policy?.environments ?? [],
    tags: policy?.tags ?? [],
    protocols: policy?.protocols ?? [],
    exemptRoles: policy?.exemptRoles ?? [],
    activeDays: policy?.activeDays ?? [],
    activeStartMin: policy?.activeStartMin ?? 0,
    activeEndMin: policy?.activeEndMin ?? 0,
    denyMessage: policy?.denyMessage ?? "",
  });
  const set = <K extends keyof AccessPolicyInput>(k: K, v: AccessPolicyInput[K]) => setForm((f) => ({ ...f, [k]: v }));
  const toggleProto = (proto: string) =>
    set("protocols", form.protocols.includes(proto) ? form.protocols.filter((x) => x !== proto) : [...form.protocols, proto]);
  const toggleDay = (d: number) =>
    set("activeDays", form.activeDays.includes(d) ? form.activeDays.filter((x) => x !== d) : [...form.activeDays, d]);
  const save = useMutation({
    mutationFn: () => (policy ? updateAccessPolicy(policy.id, form) : createAccessPolicy(form)),
    onSuccess: onSaved,
  });

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{policy ? "Edit access policy" : "New access policy"}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          <TextField label="Name" value={form.name} onChange={(e) => set("name", e.target.value)} fullWidth autoFocus />
          <TextField label="Description" value={form.description} onChange={(e) => set("description", e.target.value)} fullWidth />
          <Stack direction="row" spacing={2}>
            <TextField label="Priority" type="number" value={form.priority}
              onChange={(e) => set("priority", Number(e.target.value))} sx={{ width: 130 }}
              helperText="lower first" />
            <FormControlLabel control={<Switch checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} />} label="Enabled" />
          </Stack>

          <Typography variant="subtitle2" sx={{ mt: 1 }}>Matches hosts (leave blank for any)</Typography>
          <TextField label="Environments (comma-separated)" value={csv(form.environments)}
            onChange={(e) => set("environments", parseCsv(e.target.value))} fullWidth placeholder="production, staging" />
          <TextField label="Tags — host has any (comma-separated)" value={csv(form.tags)}
            onChange={(e) => set("tags", parseCsv(e.target.value))} fullWidth placeholder="pci, sensitive" />
          <Box>
            <Typography variant="caption" color="text.secondary">Protocols</Typography>
            <FormGroup row>
              {["ssh", "rdp"].map((proto) => (
                <FormControlLabel key={proto}
                  control={<Checkbox size="small" checked={form.protocols.includes(proto)} onChange={() => toggleProto(proto)} />}
                  label={proto.toUpperCase()} />
              ))}
            </FormGroup>
          </Box>

          <Typography variant="subtitle2" sx={{ mt: 1 }}>Exemptions</Typography>
          <TextField label="Exempt roles — holders bypass this rule (comma-separated)" value={csv(form.exemptRoles)}
            onChange={(e) => set("exemptRoles", parseCsv(e.target.value))} fullWidth placeholder="SRE, On-Call" />

          <Typography variant="subtitle2" sx={{ mt: 1 }}>When (in the configured timezone)</Typography>
          <Box>
            <Typography variant="caption" color="text.secondary">Active days (none = every day)</Typography>
            <FormGroup row>
              {DAYS.map((d, i) => (
                <FormControlLabel key={d}
                  control={<Checkbox size="small" checked={form.activeDays.includes(i)} onChange={() => toggleDay(i)} />}
                  label={d} />
              ))}
            </FormGroup>
          </Box>
          <Stack direction="row" spacing={2} alignItems="center">
            <TextField label="From" type="time" value={toHHMM(form.activeStartMin)}
              onChange={(e) => set("activeStartMin", fromHHMM(e.target.value))} InputLabelProps={{ shrink: true }} />
            <TextField label="To" type="time" value={toHHMM(form.activeEndMin)}
              onChange={(e) => set("activeEndMin", fromHHMM(e.target.value))} InputLabelProps={{ shrink: true }} />
            <Typography variant="caption" color="text.secondary">
              Equal times = all day. From &gt; To wraps past midnight (e.g. 18:00–09:00 = after hours).
            </Typography>
          </Stack>

          <TextField label="Deny message (shown to the user)" value={form.denyMessage}
            onChange={(e) => set("denyMessage", e.target.value)} fullWidth
            placeholder="Production access is restricted outside business hours." />

          {save.isError && <Alert severity="error">Could not save the policy.</Alert>}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={save.isPending || !form.name.trim()} onClick={() => save.mutate()}>Save</Button>
      </DialogActions>
    </Dialog>
  );
}
