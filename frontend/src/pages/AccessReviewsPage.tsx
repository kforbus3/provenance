import { useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  LinearProgress, MenuItem, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow,
  TextField, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import DownloadIcon from "@mui/icons-material/Download";
import FactCheckIcon from "@mui/icons-material/FactCheck";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { formatDateTime } from "../lib/datetime";
import { listGroups, listUsers } from "../api/admin";
import {
  listAccessReviews, createAccessReview, getAccessReview, decideReviewItem,
  completeAccessReview, downloadAccessReview, type AccessReview, type ReviewScope,
} from "../api/accessReviews";

// AccessReviewsPage: create access-certification campaigns, review each grant
// (keep or revoke), and export the evidence. Gated by AccessReview.Manage.
export function AccessReviewsPage() {
  const qc = useQueryClient();
  const { data: reviews = [], isLoading } = useQuery({ queryKey: ["access-reviews"], queryFn: listAccessReviews });
  const [creating, setCreating] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const invalidate = () => qc.invalidateQueries({ queryKey: ["access-reviews"] });

  return (
    <Box sx={{ maxWidth: 1100 }}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
        <Box>
          <Typography variant="h5">Access reviews</Typography>
          <Typography variant="body2" color="text.secondary">
            Certify who can reach what: snapshot the current access grants, keep or revoke each, and
            export the sign-off as audit evidence.
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreating(true)}>New review</Button>
      </Stack>

      <Paper variant="outlined" sx={{ overflowX: "auto", mt: 1 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Scope</TableCell>
              <TableCell>Progress</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Created</TableCell>
              <TableCell>Due</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {reviews.map((r) => (
              <TableRow key={r.id} hover>
                <TableCell>{r.name}</TableCell>
                <TableCell><Chip size="small" variant="outlined" label={r.scope.type} /></TableCell>
                <TableCell sx={{ minWidth: 160 }}>
                  <ProgressCell r={r} />
                </TableCell>
                <TableCell>
                  <Chip size="small" label={r.status} color={r.status === "completed" ? "success" : "warning"} />
                </TableCell>
                <TableCell>{formatDateTime(r.createdAt)}</TableCell>
                <TableCell>{r.dueAt ? formatDateTime(r.dueAt) : "—"}</TableCell>
                <TableCell align="right">
                  <Button size="small" startIcon={<FactCheckIcon />} onClick={() => setOpenId(r.id)}>Review</Button>
                  <Tooltip title="Export CSV evidence">
                    <Button size="small" startIcon={<DownloadIcon />} onClick={() => void downloadAccessReview(r.id)}>CSV</Button>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {reviews.length === 0 && (
              <TableRow><TableCell colSpan={7}>
                <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                  {isLoading ? "Loading…" : "No access reviews yet. Create one to certify current access."}
                </Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>

      {creating && <CreateDialog onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); invalidate(); setOpenId(id); }} />}
      {openId && <ReviewDialog id={openId} onClose={() => { setOpenId(null); invalidate(); }} />}
    </Box>
  );
}

function ProgressCell({ r }: { r: AccessReview }) {
  const done = r.kept + r.revoked;
  const pct = r.total ? Math.round((done / r.total) * 100) : 0;
  return (
    <Box>
      <LinearProgress variant="determinate" value={pct} sx={{ height: 6, borderRadius: 1, mb: 0.25 }} />
      <Typography variant="caption" color="text.secondary">
        {done}/{r.total} reviewed{r.revoked > 0 ? ` · ${r.revoked} revoked` : ""}
      </Typography>
    </Box>
  );
}

function CreateDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const { data: groups = [] } = useQuery({ queryKey: ["groups"], queryFn: listGroups });
  const { data: users = [] } = useQuery({ queryKey: ["users"], queryFn: listUsers });
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [type, setType] = useState<ReviewScope["type"]>("all");
  const [groupId, setGroupId] = useState<string>("");
  const [userIds, setUserIds] = useState<string[]>([]);
  const [dueInDays, setDueInDays] = useState(14);
  const [err, setErr] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => createAccessReview({
      name: name.trim(), description: description.trim(),
      scope: { type, groupId: type === "group" ? groupId : undefined, userIds: type === "user" ? userIds : undefined },
      dueInDays,
    }),
    onSuccess: (r) => onCreated(r.id),
    onError: () => setErr("Could not create the review (check the scope selection)."),
  });

  const valid = name.trim() && (type === "all" || (type === "group" && groupId) || (type === "user" && userIds.length));

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>New access review</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error">{err}</Alert>}
          <TextField label="Name" size="small" value={name} onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Q3 access recertification" autoFocus />
          <TextField label="Description" size="small" value={description} onChange={(e) => setDescription(e.target.value)} />
          <TextField select size="small" label="What to review" value={type}
            onChange={(e) => setType(e.target.value as ReviewScope["type"])}>
            <MenuItem value="all">All access (every user's group memberships + direct host grants)</MenuItem>
            <MenuItem value="group">One group's membership</MenuItem>
            <MenuItem value="user">Specific users' access</MenuItem>
          </TextField>
          {type === "group" && (
            <Autocomplete size="small" options={groups} getOptionLabel={(g) => g.name}
              onChange={(_, v) => setGroupId(v?.id ?? "")}
              renderInput={(p) => <TextField {...p} label="Group" />} />
          )}
          {type === "user" && (
            <Autocomplete multiple size="small" options={users} getOptionLabel={(u) => u.username}
              onChange={(_, v) => setUserIds(v.map((u) => u.id))}
              renderInput={(p) => <TextField {...p} label="Users" />} />
          )}
          <TextField type="number" size="small" label="Due in (days)" value={dueInDays}
            onChange={(e) => setDueInDays(Math.max(0, Number(e.target.value) || 0))} sx={{ width: 160 }} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={!valid || create.isPending} onClick={() => create.mutate()}>
          Create &amp; snapshot
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function ReviewDialog({ id, onClose }: { id: string; onClose: () => void }) {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ["access-review", id], queryFn: () => getAccessReview(id) });
  const review = data?.review;
  const items = data?.items ?? [];
  const refresh = () => qc.invalidateQueries({ queryKey: ["access-review", id] });

  const decide = useMutation({
    mutationFn: ({ itemId, decision }: { itemId: string; decision: "keep" | "revoke" }) =>
      decideReviewItem(id, itemId, decision),
    onSuccess: refresh,
  });
  const complete = useMutation({ mutationFn: () => completeAccessReview(id), onSuccess: refresh });

  const done = review ? review.kept + review.revoked : 0;
  const open = review?.status === "open";

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="lg">
      <DialogTitle>
        {review?.name}
        {review && (
          <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
            {done}/{review.total} reviewed · {review.revoked} revoked · {review.status}
          </Typography>
        )}
      </DialogTitle>
      <DialogContent>
        <Paper variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell>User</TableCell>
                <TableCell>Grant</TableCell>
                <TableCell>Resource</TableCell>
                <TableCell>Decision</TableCell>
                <TableCell align="right">Action</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map((it) => (
                <TableRow key={it.id}>
                  <TableCell>
                    {it.subjectUser}
                    {it.subjectIsServiceAccount && <Chip size="small" label="service" sx={{ ml: 0.5 }} />}
                  </TableCell>
                  <TableCell>{it.grantKind === "group_membership" ? "group member" : "direct host"}</TableCell>
                  <TableCell>{it.resourceName}</TableCell>
                  <TableCell>
                    {it.decision === "pending" ? <Chip size="small" variant="outlined" label="pending" />
                      : it.decision === "keep" ? <Chip size="small" color="success" label="kept" />
                        : <Chip size="small" color="error" label="revoked" />}
                    {it.decidedBy && <Typography variant="caption" color="text.secondary" sx={{ ml: 0.5 }}>by {it.decidedBy}</Typography>}
                  </TableCell>
                  <TableCell align="right">
                    {open && it.decision === "pending" && (
                      <>
                        <Button size="small" color="success" disabled={decide.isPending}
                          onClick={() => decide.mutate({ itemId: it.id, decision: "keep" })}>Keep</Button>
                        <Button size="small" color="error" disabled={decide.isPending}
                          onClick={() => { if (window.confirm(`Revoke ${it.subjectUser}'s access to ${it.resourceName}?`)) decide.mutate({ itemId: it.id, decision: "revoke" }); }}>Revoke</Button>
                      </>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {items.length === 0 && (
                <TableRow><TableCell colSpan={5}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>No grants in scope.</Typography>
                </TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </Paper>
      </DialogContent>
      <DialogActions>
        <Button startIcon={<DownloadIcon />} onClick={() => void downloadAccessReview(id)}>Export CSV</Button>
        <Box sx={{ flexGrow: 1 }} />
        <Button onClick={onClose}>Close</Button>
        {open && (
          <Button variant="contained" disabled={complete.isPending}
            onClick={() => { if (window.confirm(review && review.pending > 0 ? `${review.pending} item(s) are still pending. Complete anyway?` : "Complete this review?")) complete.mutate(); }}>
            Complete review
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}
