import { useMemo, useState } from "react";
import { PickList } from "../components/PickList";
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  IconButton, Paper, Snackbar, Stack, Tab, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, Tabs, TextField, Tooltip, Typography,
} from "@mui/material";
import HistoryIcon from "@mui/icons-material/History";
import PublishIcon from "@mui/icons-material/Publish";
import UndoIcon from "@mui/icons-material/Undo";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listStacks, saveStack, deployStack, rollbackStack, deleteStack, stackHistory,
  deployRefusal, type DeployRefusal, type DeployWaivers,
  type ContainerStack, type StackRevision,
} from "../api/stacks";
import { listHosts } from "../api/hosts";
import { formatDateTime } from "../lib/datetime";
import { useAuthStore } from "../store/auth";
import { ContainerUpdatesTab } from "./ContainerUpdatesTab";
import { RolloutsTab } from "./RolloutsTab";
import { DiscoveredProjectsPanel } from "./DiscoveredProjectsPanel";
import { TabErrorBoundary } from "../components/TabErrorBoundary";

// Container stacks: what each host should be running.
//
// Provenance holds the desired state, and the host holds a rendered copy — so a
// stack keeps running when Provenance is not. The two numbers on every row say
// which is which: `revision` is what should be deployed, `deployedRevision` is
// what the host last confirmed. A tool that showed only the first would report
// success for a deploy that never landed.

const errMsg = (e: unknown, fallback: string) =>
  (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? fallback;

function DeployState({ s }: { s: ContainerStack }) {
  // In flight. Shown before anything else, because until this existed a deploy
  // that was still pulling looked exactly like one that had never started.
  if (s.deployState === "deploying") {
    return (
      <Tooltip title="Pulling images and recreating containers. This can take several minutes; the row updates when it finishes.">
        <Chip label={`deploying r${s.revision}…`} size="small" color="info" />
      </Tooltip>
    );
  }
  if (s.deployedRevision == null) {
    return <Chip label="never deployed" size="small" variant="outlined" />;
  }
  if (s.deployState === "failed") {
    return (
      <Tooltip title={s.deployDetail?.slice(-400) || "the last deploy failed"}>
        <Chip label={`failed at r${s.deployedRevision}`} size="small" color="error" />
      </Tooltip>
    );
  }
  if (s.deployedRevision !== s.revision) {
    return (
      <Tooltip title={`the host is running r${s.deployedRevision}; r${s.revision} has not been deployed`}>
        <Chip label={`behind (r${s.deployedRevision})`} size="small" color="warning" />
      </Tooltip>
    );
  }
  if (s.deployState === "rolled_back") {
    return <Chip label={`rolled back to r${s.deployedRevision}`} size="small" color="warning" />;
  }
  return <Chip label={`deployed r${s.deployedRevision}`} size="small" color="success" variant="outlined" />;
}

export function StacksPage() {
  const qc = useQueryClient();
  const canEdit = useAuthStore((s) => s.has("Host.Edit"));
  const canRun = useAuthStore((s) => s.has("Command.Run"));
  const [editing, setEditing] = useState<ContainerStack | null>(null);
  const [creating, setCreating] = useState(false);
  const [historyOf, setHistoryOf] = useState<ContainerStack | null>(null);
  const [output, setOutput] = useState<{ title: string; body: string } | null>(null);
  const [snack, setSnack] = useState("");
  const [tab, setTab] = useState<"discovered" | "stacks" | "updates" | "rollouts">("discovered");

  const { data: stacks = [], isLoading } = useQuery({
    queryKey: ["stacks"],
    queryFn: () => listStacks(),
    placeholderData: keepPreviousData,
    // A deploy in flight finishes on its own schedule, so the page follows it
    // rather than making the operator guess when to reload.
    refetchInterval: (q) =>
      (q.state.data ?? []).some((st) => st.deployState === "deploying") ? 5000 : false,
  });
  const { data: hostList } = useQuery({ queryKey: ["hosts"], queryFn: () => listHosts() });
  const hosts = hostList?.hosts ?? [];

  const refresh = () => qc.invalidateQueries({ queryKey: ["stacks"] });

  // A deploy the backend refused and wants an answer to. Held here so the operator is
  // shown what it found rather than a snackbar that scrolls away; see DeployRefusal.
  const [ask, setAsk] = useState<{ id: string; waive: DeployWaivers; r: DeployRefusal } | null>(null);

  const deploy = useMutation({
    mutationFn: (v: { id: string; waive?: DeployWaivers }) => deployStack(v.id, v.waive ?? {}),
    // Accepted, not finished. The row reports the outcome when there is one.
    onSuccess: (r) => { setSnack(r.note ?? "Deploying — the row updates when it finishes."); refresh(); },
    onError: (e, v) => {
      const refusal = deployRefusal(e);
      if (refusal) {
        // Carry the waivers already given: answering the second question must not
        // silently un-answer the first, or the two dialogs bounce off each other.
        setAsk({ id: v.id, waive: v.waive ?? {}, r: refusal });
        return;
      }
      setSnack(errMsg(e, "The deploy could not be started."));
    },
  });
  const rollback = useMutation({
    mutationFn: rollbackStack,
    onSuccess: (r) => { setOutput({ title: "Rolled back", body: r.output }); refresh(); },
    onError: (e) => setSnack(errMsg(e, "The rollback failed.")),
  });
  const remove = useMutation({
    mutationFn: deleteStack,
    onSuccess: () => { setSnack("Definition removed — the containers are still running"); refresh(); },
    onError: (e) => setSnack(errMsg(e, "Could not remove that definition.")),
  });

  const drifted = useMemo(
    () => stacks.filter((s) => s.enabled && (s.deployedRevision == null
      || s.deployedRevision !== s.revision || s.deployState === "failed")),
    [stacks]);

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h5" sx={{ flex: 1 }}>Containers</Typography>
        {canEdit && tab === "stacks" && (
          <Button startIcon={<AddIcon />} variant="contained" onClick={() => setCreating(true)}>
            New stack
          </Button>
        )}
      </Stack>

      {/* Two halves of one job: what a host SHOULD run, and what is available to
          run. Separate tabs rather than separate pages because deciding to take
          an update and applying it are the same visit. */}
      {/* Discovered first, and the default. It is the answer to "what can I keep
          up to date here", it needs no setup, and it is true the moment
          Provenance is deployed — where an empty Stacks list read as a product
          with a configuration task attached. */}
      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        <Tab label="Discovered" value="discovered" />
        <Tab label="Managed stacks" value="stacks" />
        <Tab label="Updates" value="updates" />
        <Tab label="Rollouts" value="rollouts" />
      </Tabs>

      {tab === "discovered" && (
        <TabErrorBoundary name="Discovered"><DiscoveredProjectsPanel /></TabErrorBoundary>
      )}
      {tab === "updates" && (
        <TabErrorBoundary name="Updates"><ContainerUpdatesTab /></TabErrorBoundary>
      )}
      {tab === "rollouts" && (
        <TabErrorBoundary name="Rollouts"><RolloutsTab /></TabErrorBoundary>
      )}

      {tab === "stacks" && <>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Compose files Provenance holds a copy of. A project appears here once
        something needed the file changed — a version update, or an edit you made —
        and from then on every change is a revision with an author, a note and a
        rollback. <b>An empty list is not a setup step.</b> Everything discovered is
        already updatable; see the Discovered tab.
      </Typography>

      {drifted.length > 0 && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          {drifted.length} stack{drifted.length > 1 ? "s are" : " is"} not running the
          revision {drifted.length > 1 ? "they" : "it"} should be.
        </Alert>
      )}

      {isLoading && <Typography variant="body2">Loading…</Typography>}
      {!isLoading && stacks.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          No stacks defined yet. Add one to put a host's compose file under Provenance.
        </Typography>
      )}

      {stacks.length > 0 && (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Host</TableCell>
                <TableCell>Stack</TableCell>
                <TableCell>Path</TableCell>
                <TableCell>State</TableCell>
                <TableCell>Updated</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {stacks.map((s) => (
                <TableRow key={s.id} hover>
                  <TableCell>{s.hostname || s.hostId}</TableCell>
                  <TableCell>{s.name} <Typography variant="caption" color="text.secondary">r{s.revision}</Typography></TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>{s.path}</TableCell>
                  <TableCell><DeployState s={s} /></TableCell>
                  <TableCell>{formatDateTime(s.updatedAt)}</TableCell>
                  <TableCell align="right">
                    <Tooltip title="History">
                      <IconButton size="small" onClick={() => setHistoryOf(s)}><HistoryIcon fontSize="small" /></IconButton>
                    </Tooltip>
                    {canEdit && (
                      <Button size="small" onClick={() => setEditing(s)}>Edit</Button>
                    )}
                    {canRun && (
                      <Tooltip title="Write this revision to the host and bring it up">
                        <span>
                          <Button size="small" startIcon={<PublishIcon />} disabled={deploy.isPending}
                                  onClick={() => deploy.mutate({ id: s.id })}>Deploy</Button>
                        </span>
                      </Tooltip>
                    )}
                    {canRun && s.deployedRevision != null && (
                      <Tooltip title="Restore the previous compose file kept on the host">
                        <span>
                          <IconButton size="small" disabled={rollback.isPending}
                                      onClick={() => rollback.mutate(s.id)}><UndoIcon fontSize="small" /></IconButton>
                        </span>
                      </Tooltip>
                    )}
                    {canEdit && (
                      <Tooltip title="Forget this definition (the containers keep running)">
                        <IconButton size="small" color="error" onClick={() => remove.mutate(s.id)}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <StackEditor
        open={creating || editing !== null}
        stack={editing}
        hosts={hosts.map((h) => ({ id: h.id, hostname: h.hostname }))}
        onClose={() => { setCreating(false); setEditing(null); }}
        onSaved={(msg) => { setCreating(false); setEditing(null); setSnack(msg); refresh(); }}
      />
      <HistoryDialog stack={historyOf} onClose={() => setHistoryOf(null)} />

      {/* A deploy the backend refused, and the question it wants answered.

          Not a snackbar. Each of these is a deploy that takes a service DOWN rather
          than failing cleanly, so the operator gets what was found and decides. Both
          have a way through, because both describe something a person can legitimately
          mean: a database whose data directory has already been migrated, or a retry
          after fixing something that is not in the compose file. */}
      <Dialog open={ask !== null} onClose={() => setAsk(null)} maxWidth="sm" fullWidth>
        <DialogTitle>
          {ask?.r.code === "stateful_major_bump"
            ? "This deploy would change a database major version"
            : "This revision already failed on this host"}
        </DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>{ask?.r.error}</Alert>
          <Table size="small">
            <TableBody>
              {ask?.r.code === "stateful_major_bump" && <>
                <TableRow>
                  <TableCell>Service</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>{ask.r.service}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>Image</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>{ask.r.repository}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>Running now</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>{ask.r.from}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>This deploy pins</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>{ask.r.to}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>Needs</TableCell>
                  <TableCell>{ask.r.migration}</TableCell>
                </TableRow>
              </>}
              {ask?.r.code === "revision_already_failed" && <>
                <TableRow>
                  <TableCell>Revision</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>r{ask.r.revision}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>Host</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>{ask.r.hostname}</TableCell>
                </TableRow>
                {ask.r.when && <TableRow>
                  <TableCell>Failed</TableCell>
                  <TableCell>{formatDateTime(ask.r.when)}</TableCell>
                </TableRow>}
                {ask.r.detail && <TableRow>
                  <TableCell>It said</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>{ask.r.detail}</TableCell>
                </TableRow>}
              </>}
            </TableBody>
          </Table>
          <Typography variant="body2" sx={{ mt: 2 }}>
            {ask?.r.code === "stateful_major_bump"
              ? `Edit the compose file to pin the version the data directory holds, or — if the data has already been migrated with ${ask.r.migration} — deploy anyway.`
              : "Nothing in the definition has changed since it failed, so this sends the same file again. Edit the compose file, or deploy anyway if you have fixed something off the host."}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAsk(null)}>Cancel</Button>
          <Button color="warning" onClick={() => {
            const a = ask;
            setAsk(null);
            if (!a) return;
            // The previous waivers plus this one: answering the second question must
            // not un-answer the first.
            const waive: DeployWaivers = { ...a.waive };
            if (a.r.code === "stateful_major_bump") waive.statefulMajor = true;
            else waive.failedRevision = true;
            deploy.mutate({ id: a.id, waive });
          }}>
            {ask?.r.code === "stateful_major_bump"
              ? "The data is migrated — deploy anyway"
              : "Deploy it again anyway"}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={output !== null} onClose={() => setOutput(null)} maxWidth="md" fullWidth>
        <DialogTitle>{output?.title}</DialogTitle>
        <DialogContent>
          <Box component="pre" sx={{
            fontFamily: "monospace", fontSize: 12, whiteSpace: "pre-wrap",
            maxHeight: 420, overflow: "auto", m: 0,
          }}>{output?.body || "(no output)"}</Box>
        </DialogContent>
        <DialogActions><Button onClick={() => setOutput(null)}>Close</Button></DialogActions>
      </Dialog>
      </>}

      <Snackbar open={snack !== ""} autoHideDuration={5000} onClose={() => setSnack("")} message={snack} />
    </Box>
  );
}

// Exported for the test that saving an existing stack does not move it: the
// path is the thing this dialog quietly dropped.
export function StackEditor({ open, stack, hosts, onClose, onSaved }: {
  open: boolean;
  stack: ContainerStack | null;
  hosts: { id: string; hostname: string }[];
  onClose: () => void;
  onSaved: (msg: string) => void;
}) {
  const [hostId, setHostId] = useState("");
  const [name, setName] = useState("");
  const [compose, setCompose] = useState("");
  const [path, setPath] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");

  // Reset when the dialog opens on a different stack.
  const key = stack?.id ?? "new";
  const [lastKey, setLastKey] = useState(key);
  if (key !== lastKey) {
    setLastKey(key);
    setHostId(stack?.hostId ?? "");
    setName(stack?.name ?? "");
    setCompose(stack?.compose ?? "");
    setPath(stack?.path ?? "");
    setNote("");
    setErr("");
  }

  const save = useMutation({
    // The path travels with the save. Leaving it out used to mean "no opinion",
    // which the server read as "put it under /opt/stacks" — quietly relocating an
    // adopted stack away from the directory holding its .env.
    mutationFn: () => saveStack({ hostId, name, compose, path, note }),
    onSuccess: (s) => onSaved(`Saved ${s.name} (r${s.revision}) — not yet deployed`),
    onError: (e) => setErr(errMsg(e, "Could not save that stack.")),
  });

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{stack ? `Edit ${stack.name}` : "New stack"}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error" onClose={() => setErr("")}>{err}</Alert>}
          {/* Saving records the definition and nothing else. Editing a compose
              file should not restart somebody's database because the editor hit
              save — deploying is a separate, deliberate act. */}
          <Alert severity="info">
            Saving records the definition. It does not deploy — use Deploy when you want
            the host to pick it up.
          </Alert>
          <PickList label="Host" value={hostId} onChange={setHostId}
                    disabled={stack !== null}
                    options={hosts.map((h) => ({ value: h.id, label: h.hostname }))} />
          <TextField size="small" label="Stack name" value={name} disabled={stack !== null}
                     onChange={(e) => setName(e.target.value)}
                     helperText="The compose project name" />
          <TextField size="small" label="Directory on the host" value={path}
                     onChange={(e) => setPath(e.target.value)}
                     placeholder={name ? `/opt/stacks/${name}` : "/opt/stacks/<name>"}
                     helperText={
                       "Where the compose file is written and `docker compose` is run. " +
                       "For a stack adopted from a host this is the project's existing " +
                       "directory — the .env and any bind mounts beside it are why it matters. " +
                       "Leave blank on a new stack to use /opt/stacks."
                     } />
          <TextField
            label="docker-compose.yml" value={compose} multiline minRows={14}
            onChange={(e) => setCompose(e.target.value)}
            InputProps={{ style: { fontFamily: "monospace", fontSize: 13 } }}
          />
          <TextField size="small" label="What changed, and why" value={note}
                     onChange={(e) => setNote(e.target.value)}
                     helperText="Recorded with the revision — this is what replaces a commit message" />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={save.isPending || !hostId || !name}
                onClick={() => save.mutate()}>Save</Button>
      </DialogActions>
    </Dialog>
  );
}

function HistoryDialog({ stack, onClose }: { stack: ContainerStack | null; onClose: () => void }) {
  const { data: revisions = [] } = useQuery<StackRevision[]>({
    queryKey: ["stack-history", stack?.id],
    queryFn: () => stackHistory(stack!.id),
    enabled: stack !== null,
  });
  return (
    <Dialog open={stack !== null} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{stack?.name} — history</DialogTitle>
      <DialogContent>
        {revisions.length === 0 && <Typography variant="body2">No revisions recorded.</Typography>}
        <Stack spacing={1}>
          {revisions.map((r) => (
            <Paper key={r.revision} variant="outlined" sx={{ p: 1 }}>
              <Stack direction="row" spacing={1} alignItems="center">
                <Chip label={`r${r.revision}`} size="small" />
                <Typography variant="body2" sx={{ flex: 1 }}>{r.note || "(no note)"}</Typography>
                <Typography variant="caption" color="text.secondary">
                  {r.authorName} · {formatDateTime(r.createdAt)}
                </Typography>
              </Stack>
            </Paper>
          ))}
        </Stack>
      </DialogContent>
      <DialogActions><Button onClick={onClose}>Close</Button></DialogActions>
    </Dialog>
  );
}
