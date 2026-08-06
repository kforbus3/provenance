import { useMemo, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Checkbox, Chip, Dialog, DialogActions, DialogContent,
  DialogTitle, FormControlLabel, FormGroup, IconButton, Paper, Stack, Table, TableBody,
  TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import DnsIcon from "@mui/icons-material/Dns";
import PeopleIcon from "@mui/icons-material/People";
import TuneIcon from "@mui/icons-material/Tune";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  addHostToGroup, addUserToGroup, createGroup, deleteGroup, listGroupHosts, listGroups,
  listUsers, removeHostFromGroup, removeUserFromGroup, updateGroupRule,
  type Group, type GroupRule,
} from "../api/admin";
import { listHosts } from "../api/hosts";
import { useAuthStore } from "../store/auth";

const emptyRule: GroupRule = {};

function ruleIsEmpty(r: GroupRule): boolean {
  return !r.environment && !r.osContains && !r.hostnameContains &&
    !(r.tagsAll && r.tagsAll.length) && !(r.tagsAny && r.tagsAny.length);
}

function ruleSummary(r: GroupRule): string {
  const parts: string[] = [];
  if (r.environment) parts.push(`env=${r.environment}`);
  if (r.tagsAll?.length) parts.push(`all tags: ${r.tagsAll.join(", ")}`);
  if (r.tagsAny?.length) parts.push(`any tags: ${r.tagsAny.join(", ")}`);
  if (r.osContains) parts.push(`os~${r.osContains}`);
  if (r.hostnameContains) parts.push(`name~${r.hostnameContains}`);
  return parts.join(" · ");
}

// Group administration: shared host-authorization buckets. A user in a group can
// reach any host that is also in that group. Host membership is either manual or
// driven by a dynamic rule over host attributes.
export function GroupsPage() {
  const qc = useQueryClient();
  const { data: groups = [], isLoading } = useQuery({ queryKey: ["groups"], queryFn: listGroups });
  const { data: users = [] } = useQuery({ queryKey: ["users"], queryFn: listUsers });

  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [newRule, setNewRule] = useState<GroupRule>(emptyRule);
  const [membersGroup, setMembersGroup] = useState<Group | null>(null);
  const [ruleGroup, setRuleGroup] = useState<Group | null>(null);
  const [hostsGroup, setHostsGroup] = useState<Group | null>(null);

  const invalidate = () => qc.invalidateQueries({ queryKey: ["groups"] });

  const createMut = useMutation({
    mutationFn: () => createGroup(name, description, ruleIsEmpty(newRule) ? undefined : newRule),
    onSuccess: () => { setCreateOpen(false); setName(""); setDescription(""); setNewRule(emptyRule); invalidate(); },
  });
  const deleteMut = useMutation({ mutationFn: (id: string) => deleteGroup(id), onSuccess: invalidate });
  const memberMut = useMutation({
    mutationFn: ({ userId, groupId, add }: { userId: string; groupId: string; add: boolean }) =>
      add ? addUserToGroup(userId, groupId) : removeUserFromGroup(userId, groupId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });

  const memberCount = (g: Group) => users.filter((u) => (u.groups ?? []).includes(g.name)).length;

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>Group Management</Typography>
        <Button startIcon={<AddIcon />} variant="contained" onClick={() => setCreateOpen(true)}>
          New Group
        </Button>
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Put users in a group, then add hosts to it — manually, or with a dynamic rule so hosts join
        automatically by environment, tags, OS, or name. Every member reaches every host in the group.
      </Typography>

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Description</TableCell>
              <TableCell>Membership</TableCell>
              <TableCell>Hosts</TableCell>
              <TableCell>Users</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {groups.map((g) => (
              <TableRow key={g.id} hover>
                <TableCell>{g.name}</TableCell>
                <TableCell>{g.description}</TableCell>
                <TableCell>
                  {g.rule ? (
                    <Tooltip title={ruleSummary(g.rule)}>
                      <Chip size="small" color="info" label="Dynamic" icon={<TuneIcon />} />
                    </Tooltip>
                  ) : (
                    <Chip size="small" variant="outlined" label="Manual" />
                  )}
                </TableCell>
                <TableCell>
                  <Tooltip title="View host members">
                    <Chip
                      size="small" clickable label={g.hostCount ?? 0}
                      variant={g.hostCount ? "filled" : "outlined"}
                      onClick={() => setHostsGroup(g)}
                    />
                  </Tooltip>
                </TableCell>
                <TableCell><Chip size="small" label={memberCount(g)} /></TableCell>
                <TableCell align="right">
                  <Tooltip title="Membership rule">
                    <IconButton size="small" aria-label={`Membership rule for ${g.name}`} onClick={() => setRuleGroup(g)}><TuneIcon fontSize="small" /></IconButton>
                  </Tooltip>
                  <Tooltip title="Manage hosts">
                    <IconButton size="small" aria-label={`Manage hosts in ${g.name}`} onClick={() => setHostsGroup(g)}><DnsIcon fontSize="small" /></IconButton>
                  </Tooltip>
                  <Tooltip title="Manage users">
                    <IconButton size="small" aria-label={`Manage users in ${g.name}`} onClick={() => setMembersGroup(g)}><PeopleIcon fontSize="small" /></IconButton>
                  </Tooltip>
                  <Tooltip title="Delete">
                    <IconButton size="small" aria-label={`Delete ${g.name}`} onClick={() => deleteMut.mutate(g.id)}><DeleteIcon fontSize="small" /></IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {!isLoading && groups.length === 0 && (
              <TableRow><TableCell colSpan={6}>
                <Typography color="text.secondary">No groups yet.</Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>New Group</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} required />
            <TextField label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
            <Typography variant="subtitle2" sx={{ mt: 1 }}>Dynamic membership rule (optional)</Typography>
            <Typography variant="caption" color="text.secondary">
              Leave blank for a manual group. When set, matching hosts join automatically.
            </Typography>
            <RuleFields rule={newRule} onChange={setNewRule} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button variant="contained" disabled={!name || createMut.isPending} onClick={() => createMut.mutate()}>Create</Button>
        </DialogActions>
      </Dialog>

      {ruleGroup && (
        <RuleDialog
          group={ruleGroup}
          onClose={() => setRuleGroup(null)}
          onSaved={() => { setRuleGroup(null); invalidate(); }}
        />
      )}

      {hostsGroup && (
        <GroupHostsDialog
          group={hostsGroup}
          onClose={() => setHostsGroup(null)}
          onChanged={invalidate}
        />
      )}

      <Dialog open={Boolean(membersGroup)} onClose={() => setMembersGroup(null)} fullWidth maxWidth="xs">
        <DialogTitle>Users — {membersGroup?.name}</DialogTitle>
        <DialogContent dividers>
          <FormGroup>
            {users.map((u) => (
              <FormControlLabel
                key={u.id}
                control={
                  <Checkbox
                    checked={(u.groups ?? []).includes(membersGroup?.name ?? "")}
                    disabled={memberMut.isPending}
                    onChange={(e) =>
                      membersGroup && memberMut.mutate({ userId: u.id, groupId: membersGroup.id, add: e.target.checked })
                    }
                  />
                }
                label={u.username}
              />
            ))}
            {users.length === 0 && <Typography variant="body2" color="text.secondary">No users yet.</Typography>}
          </FormGroup>
        </DialogContent>
        <DialogActions><Button onClick={() => setMembersGroup(null)}>Close</Button></DialogActions>
      </Dialog>
    </Box>
  );
}

// apiError pulls the backend's error string off a failed request.
function apiError(e: unknown, fallback: string): string {
  return (e as { response?: { data?: { error?: string } } })?.response?.data?.error || fallback;
}

// GroupHostsDialog shows which hosts belong to a group and lets an administrator
// add or remove them without leaving the Groups page. Editing needs Host.Edit
// (the same gate as the host-side access dialog) and is refused outright on a
// dynamic group, where the rule owns membership.
function GroupHostsDialog({ group, onClose, onChanged }: {
  group: Group;
  onClose: () => void;
  onChanged: () => void;
}) {
  const qc = useQueryClient();
  const canEdit = useAuthStore((s) => s.has("Host.Edit"));
  const [toAdd, setToAdd] = useState<{ id: string; hostname: string } | null>(null);
  const [error, setError] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["group-hosts", group.id],
    queryFn: () => listGroupHosts(group.id),
  });
  const members = data?.hosts ?? [];
  const dynamic = data?.dynamic ?? Boolean(group.rule);
  const editable = canEdit && !dynamic;

  // Candidate hosts for the picker. Only fetched when adding is actually
  // possible, so a read-only viewer never pulls the whole inventory.
  const { data: allHosts } = useQuery({
    queryKey: ["hosts"],
    queryFn: listHosts,
    enabled: editable,
  });

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["group-hosts", group.id] });
    void qc.invalidateQueries({ queryKey: ["hosts"] });
    onChanged();
  };

  const addMut = useMutation({
    mutationFn: (hostId: string) => addHostToGroup(group.id, hostId),
    onSuccess: () => { setToAdd(null); setError(""); refresh(); },
    onError: (e) => setError(apiError(e, "Could not add the host to this group.")),
  });
  const removeMut = useMutation({
    mutationFn: (hostId: string) => removeHostFromGroup(group.id, hostId),
    onSuccess: () => { setError(""); refresh(); },
    onError: (e) => setError(apiError(e, "Could not remove the host from this group.")),
  });

  // Everything not already a member, as {id, hostname} options for the picker.
  const candidates = useMemo(() => {
    const inGroup = new Set((data?.hosts ?? []).map((h) => h.id));
    return (allHosts?.hosts ?? [])
      .filter((h) => !inGroup.has(h.id))
      .map((h) => ({ id: h.id, hostname: h.hostname }));
  }, [allHosts, data]);

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>Hosts — {group.name}</DialogTitle>
      <DialogContent dividers>
        {dynamic && (
          <Alert severity="info" sx={{ mb: 2 }}>
            Membership is rule-managed{group.rule ? ` — ${ruleSummary(group.rule)}` : ""}. Hosts
            join and leave automatically; edit the group's rule to change who is in it.
          </Alert>
        )}
        {!dynamic && !canEdit && (
          <Alert severity="info" sx={{ mb: 2 }}>
            You can view this group's hosts. Changing membership requires the Host.Edit permission.
          </Alert>
        )}
        {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError("")}>{error}</Alert>}

        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Hostname</TableCell>
                <TableCell>Environment</TableCell>
                <TableCell>Owner</TableCell>
                <TableCell>Tags</TableCell>
                {editable && <TableCell align="right">Remove</TableCell>}
              </TableRow>
            </TableHead>
            <TableBody>
              {members.map((h) => (
                <TableRow key={h.id} hover>
                  <TableCell>
                    {h.hostname}
                    {!h.enrolled && (
                      <Chip size="small" variant="outlined" label="not enrolled" sx={{ ml: 1 }} />
                    )}
                  </TableCell>
                  <TableCell>{h.environment}</TableCell>
                  <TableCell>{h.owner}</TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                      {(h.tags ?? []).map((t) => <Chip key={t} size="small" label={t} />)}
                    </Stack>
                  </TableCell>
                  {editable && (
                    <TableCell align="right">
                      <Tooltip title="Remove from group">
                        <span>
                          <IconButton
                            size="small" color="error" disabled={removeMut.isPending}
                            aria-label={`Remove ${h.hostname} from ${group.name}`}
                            onClick={() => removeMut.mutate(h.id)}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    </TableCell>
                  )}
                </TableRow>
              ))}
              {!isLoading && members.length === 0 && (
                <TableRow><TableCell colSpan={editable ? 5 : 4}>
                  <Typography color="text.secondary">
                    No hosts in this group{dynamic ? " — no host matches the rule." : " yet."}
                  </Typography>
                </TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>

        {editable && (
          <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
            <Autocomplete
              size="small" sx={{ minWidth: 320 }} value={toAdd} options={candidates}
              getOptionLabel={(o) => o.hostname}
              isOptionEqualToValue={(a, b) => a.id === b.id}
              onChange={(_, v) => setToAdd(v)}
              noOptionsText="Every host is already a member"
              renderInput={(params) => <TextField {...params} label="Add host" />}
            />
            <Button
              variant="outlined" disabled={!toAdd || addMut.isPending}
              onClick={() => toAdd && addMut.mutate(toAdd.id)}
            >
              Add
            </Button>
          </Stack>
        )}
      </DialogContent>
      <DialogActions><Button onClick={onClose}>Close</Button></DialogActions>
    </Dialog>
  );
}

// RuleFields edits a GroupRule. Tag lists are entered as comma-separated text.
function RuleFields({ rule, onChange }: { rule: GroupRule; onChange: (r: GroupRule) => void }) {
  const set = (patch: Partial<GroupRule>) => onChange({ ...rule, ...patch });
  const tags = (s: string) => s.split(",").map((t) => t.trim()).filter(Boolean);
  return (
    <Stack spacing={1.5}>
      <TextField size="small" label="Environment" value={rule.environment ?? ""}
        onChange={(e) => set({ environment: e.target.value })}
        helperText="Exact match, e.g. production" />
      <TextField size="small" label="Has ALL tags" value={(rule.tagsAll ?? []).join(", ")}
        onChange={(e) => set({ tagsAll: tags(e.target.value) })}
        helperText="Comma-separated; host must carry every tag" />
      <TextField size="small" label="Has ANY tag" value={(rule.tagsAny ?? []).join(", ")}
        onChange={(e) => set({ tagsAny: tags(e.target.value) })}
        helperText="Comma-separated; host must carry at least one" />
      <Stack direction="row" spacing={1.5}>
        <TextField size="small" label="OS contains" value={rule.osContains ?? ""}
          onChange={(e) => set({ osContains: e.target.value })} sx={{ flex: 1 }} />
        <TextField size="small" label="Hostname contains" value={rule.hostnameContains ?? ""}
          onChange={(e) => set({ hostnameContains: e.target.value })} sx={{ flex: 1 }} />
      </Stack>
    </Stack>
  );
}

function RuleDialog({ group, onClose, onSaved }: { group: Group; onClose: () => void; onSaved: () => void }) {
  const [rule, setRule] = useState<GroupRule>(group.rule ?? emptyRule);
  const save = useMutation({
    mutationFn: () => updateGroupRule(group.id, ruleIsEmpty(rule) ? null : rule),
    onSuccess: onSaved,
  });
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Membership rule — {group.name}</DialogTitle>
      <DialogContent>
        <Alert severity="info" sx={{ mb: 2 }}>
          {ruleIsEmpty(rule)
            ? "No rule set — this is a manual group; add hosts from each host's access dialog."
            : "Dynamic group — hosts matching the rule join automatically. Manual host edits are disabled."}
        </Alert>
        <RuleFields rule={rule} onChange={setRule} />
      </DialogContent>
      <DialogActions>
        {!ruleIsEmpty(rule) && (
          <Button color="warning" onClick={() => setRule(emptyRule)}>Clear rule (make manual)</Button>
        )}
        <Box sx={{ flexGrow: 1 }} />
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>Save</Button>
      </DialogActions>
    </Dialog>
  );
}
