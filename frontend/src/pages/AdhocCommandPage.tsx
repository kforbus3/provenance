import { useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, MenuItem, Paper, Stack, Table, TableBody,
  TableCell, TableContainer, TableHead, TableRow, TextField, ToggleButton,
  ToggleButtonGroup, Typography,
} from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { formatDateTime } from "../lib/datetime";
import { listHosts, type Host } from "../api/hosts";
import { listGroups } from "../api/admin";
import { runCommand, listCommandRuns, getCommandRun, type CommandRun } from "../api/commands";

const STATUS_COLOR: Record<string, "default" | "success" | "error" | "info"> = {
  pending: "info", running: "info", completed: "success", failed: "error",
};

// AdhocCommandPage runs a one-off shell command on Linux hosts. It's governed by
// the command-control policy (a blocked/approval-gated command is refused per host
// with a note in the output), so it never bypasses the terminal's command rules.
export function AdhocCommandPage() {
  const qc = useQueryClient();
  const { data: hostResp } = useQuery({ queryKey: ["hosts"], queryFn: listHosts });
  const hosts = hostResp?.hosts ?? [];
  const { data: groups = [] } = useQuery({ queryKey: ["groups"], queryFn: listGroups });
  const { data: runs = [] } = useQuery({
    queryKey: ["command-runs"], queryFn: listCommandRuns, refetchInterval: 5000,
  });

  const linuxHosts = hosts.filter((h) => h.protocol !== "rdp");
  const [command, setCommand] = useState("");
  const [mode, setMode] = useState<"host" | "group">("host");
  const [selHosts, setSelHosts] = useState<Host[]>([]);
  const [groupId, setGroupId] = useState("");
  const [activeRunId, setActiveRunId] = useState<string | null>(null);

  const run = useMutation({
    mutationFn: () =>
      runCommand({
        command: command.trim(),
        targetKind: mode,
        hostIds: mode === "host" ? selHosts.map((h) => h.id) : undefined,
        groupId: mode === "group" ? groupId : undefined,
      }),
    onSuccess: (rec) => { setActiveRunId(rec.id); void qc.invalidateQueries({ queryKey: ["command-runs"] }); },
  });

  const targetReady = mode === "host" ? selHosts.length > 0 : groupId !== "";

  return (
    <Box>
      <Alert severity="warning" sx={{ mb: 2 }}>
        Runs a shell command on the selected Linux hosts as each host's configured SSH user, over the
        jump host. It is governed by the command-control policy (flagged / blocked / approval-gated
        commands are handled per host) and fully audited. Output is capped at 4&nbsp;MiB per host.
      </Alert>

      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Stack spacing={2}>
          <TextField
            label="Command" value={command} onChange={(e) => setCommand(e.target.value)}
            multiline minRows={2} fullWidth placeholder="e.g. systemctl status nginx"
            sx={{ "& textarea": { fontFamily: "monospace" } }}
          />
          <Stack direction="row" spacing={2} alignItems="center">
            <ToggleButtonGroup size="small" exclusive value={mode} onChange={(_, v) => v && setMode(v)}>
              <ToggleButton value="host">Hosts</ToggleButton>
              <ToggleButton value="group">Group</ToggleButton>
            </ToggleButtonGroup>
            {mode === "host" ? (
              <Autocomplete
                multiple sx={{ flexGrow: 1 }} options={linuxHosts} value={selHosts}
                onChange={(_, v) => setSelHosts(v)} getOptionLabel={(h) => h.hostname}
                isOptionEqualToValue={(a, b) => a.id === b.id}
                renderInput={(params) => <TextField {...params} label="Linux hosts" size="small" />}
              />
            ) : (
              <TextField select size="small" label="Group" value={groupId}
                onChange={(e) => setGroupId(e.target.value)} sx={{ flexGrow: 1 }}>
                {groups.map((g) => <MenuItem key={g.id} value={g.id}>{g.name}</MenuItem>)}
              </TextField>
            )}
            <Button
              variant="contained"
              disabled={!command.trim() || !targetReady || run.isPending}
              onClick={() => run.mutate()}
            >
              {run.isPending ? "Starting…" : "Run"}
            </Button>
          </Stack>
          {run.isError && <Alert severity="error">{(run.error as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Run failed"}</Alert>}
        </Stack>
      </Paper>

      {activeRunId && <RunOutput runId={activeRunId} />}

      <Typography variant="h6" sx={{ mb: 1 }}>Recent runs</Typography>
      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>When</TableCell>
              <TableCell>Command</TableCell>
              <TableCell>Target</TableCell>
              <TableCell>By</TableCell>
              <TableCell>Status</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {runs.map((r) => (
              <TableRow key={r.id} hover sx={{ cursor: "pointer" }} onClick={() => setActiveRunId(r.id)}>
                <TableCell>{formatDateTime(r.createdAt)}</TableCell>
                <TableCell sx={{ fontFamily: "monospace", maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.command}</TableCell>
                <TableCell>{r.targetName}</TableCell>
                <TableCell>{r.requester}</TableCell>
                <TableCell><Chip size="small" label={r.status} color={STATUS_COLOR[r.status] ?? "default"} /></TableCell>
              </TableRow>
            ))}
            {runs.length === 0 && (
              <TableRow><TableCell colSpan={5}><Typography color="text.secondary">No runs yet.</Typography></TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}

// RunOutput polls a run until it finishes, showing the aggregated per-host output.
function RunOutput({ runId }: { runId: string }) {
  const { data } = useQuery({
    queryKey: ["command-run", runId],
    queryFn: () => getCommandRun(runId),
    refetchInterval: (q) => {
      const s = (q.state.data as CommandRun | undefined)?.status;
      return s === "completed" || s === "failed" ? false : 1500;
    },
  });
  if (!data) return null;
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
        <Typography variant="subtitle1" sx={{ fontFamily: "monospace" }}>{data.command}</Typography>
        <Box sx={{ flexGrow: 1 }} />
        <Chip size="small" label={data.status} color={STATUS_COLOR[data.status] ?? "default"} />
      </Stack>
      <Box
        sx={{
          fontFamily: "monospace", fontSize: 13, whiteSpace: "pre-wrap", bgcolor: "action.hover",
          p: 1.5, borderRadius: 1, maxHeight: 420, overflow: "auto",
        }}
      >
        {data.output || (data.status === "running" || data.status === "pending" ? "Running…" : "(no output)")}
      </Box>
      {data.error && <Alert severity="error" sx={{ mt: 1 }}>{data.error}</Alert>}
    </Paper>
  );
}
