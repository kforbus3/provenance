import { useEffect, useState } from "react";
import {
  Autocomplete, Box, Button, Chip, CircularProgress, MenuItem, Paper, Stack, Tab,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Tabs, TextField,
  Typography,
} from "@mui/material";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createApproval, decideApproval, listApprovals, listMyApprovals, searchRequestTargets,
  type ApprovalRequest, type RequestTarget,
} from "../api/approvals";
import { formatDateTime } from "../lib/datetime";

// Duration presets for both requests and decisions. "custom" reveals a minutes
// field; every other option maps directly to a fixed number of seconds.
const DURATIONS: { label: string; secs: number | "custom" }[] = [
  { label: "30m", secs: 30 * 60 },
  { label: "1h", secs: 60 * 60 },
  { label: "4h", secs: 4 * 60 * 60 },
  { label: "8h", secs: 8 * 60 * 60 },
  { label: "24h", secs: 24 * 60 * 60 },
  { label: "7d", secs: 7 * 24 * 60 * 60 },
  { label: "Custom", secs: "custom" },
];

function statusColor(status: string): "default" | "success" | "error" | "warning" {
  if (status === "approved") return "success";
  if (status === "denied") return "error";
  if (status === "pending") return "warning";
  return "default";
}

function ApprovalTable({
  rows, onDecide,
}: {
  rows: ApprovalRequest[];
  onDecide?: (r: ApprovalRequest) => React.ReactNode;
}) {
  return (
    <TableContainer component={Paper} variant="outlined">
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Requester</TableCell>
            <TableCell>Target</TableCell>
            <TableCell>Reason</TableCell>
            <TableCell>Requested</TableCell>
            <TableCell>Status</TableCell>
            {onDecide && <TableCell align="right">Decision</TableCell>}
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.map((r) => (
            <TableRow key={r.id} hover>
              <TableCell>{r.requester || r.requesterId}</TableCell>
              <TableCell>{r.targetKind}: {r.targetName || r.hostId || r.groupId}</TableCell>
              <TableCell>{r.reason}</TableCell>
              <TableCell>{Math.round(r.requestedSecs / 60)}m</TableCell>
              <TableCell>
                <Chip label={r.status} size="small" color={statusColor(r.status)} />
                {r.decidedByName && (
                  <Typography variant="caption" display="block" color="text.secondary">
                    by {r.decidedByName}{r.decidedAt ? ` · ${formatDateTime(r.decidedAt)}` : ""}
                  </Typography>
                )}
                {r.decisionNote && (
                  <Typography variant="caption" display="block" color="text.secondary" sx={{ fontStyle: "italic" }}>
                    “{r.decisionNote}”
                  </Typography>
                )}
              </TableCell>
              {onDecide && <TableCell align="right">{onDecide(r)}</TableCell>}
            </TableRow>
          ))}
          {rows.length === 0 && (
            <TableRow>
              <TableCell colSpan={onDecide ? 6 : 5}>
                <Typography color="text.secondary">Nothing here yet.</Typography>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

function DurationSelect({
  value, custom, onValue, onCustom,
}: {
  value: string;
  custom: string;
  onValue: (v: string) => void;
  onCustom: (v: string) => void;
}) {
  return (
    <Stack direction="row" spacing={2}>
      <TextField select size="small" label="Duration" value={value}
        onChange={(e) => onValue(e.target.value)} sx={{ minWidth: 140 }}>
        {DURATIONS.map((d) => (
          <MenuItem key={d.label} value={d.label}>{d.label}</MenuItem>
        ))}
      </TextField>
      {value === "Custom" && (
        <TextField size="small" type="number" label="Minutes" value={custom}
          onChange={(e) => onCustom(e.target.value)} sx={{ width: 120 }} />
      )}
    </Stack>
  );
}

function durationToSecs(label: string, customMinutes: string): number {
  const preset = DURATIONS.find((d) => d.label === label);
  if (preset && preset.secs !== "custom") return preset.secs;
  const mins = Number(customMinutes);
  return Number.isFinite(mins) && mins > 0 ? Math.round(mins * 60) : 0;
}

// Approvals workspace: requesters file time-boxed access requests on the "My
// requests" tab; deciders triage pending requests with approve/deny on "Queue".
export function ApprovalsPage() {
  const qc = useQueryClient();
  const [tab, setTab] = useState(0);

  const { data: mine = [] } = useQuery({ queryKey: ["approvals", "mine"], queryFn: () => listMyApprovals() });
  const { data: queue = [] } = useQuery({ queryKey: ["approvals", "queue"], queryFn: () => listApprovals("pending") });

  // Request form state.
  const [targetKind, setTargetKind] = useState<"host" | "group">("host");
  const [selected, setSelected] = useState<RequestTarget[]>([]);
  const [reason, setReason] = useState("");
  const [ticketRef, setTicketRef] = useState("");
  const [reqDuration, setReqDuration] = useState("1h");
  const [reqCustom, setReqCustom] = useState("60");

  // Targets are searched server-side as the user types (debounced), so this
  // scales to large fleets. Already-reachable targets are excluded by the API.
  const [search, setSearch] = useState("");
  const [debounced, setDebounced] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setDebounced(search), 250);
    return () => clearTimeout(t);
  }, [search]);
  const { data: options = [], isFetching: targetsLoading } = useQuery({
    queryKey: ["approval-targets", targetKind, debounced],
    queryFn: () => searchRequestTargets(targetKind, debounced),
    enabled: tab === 0,
    placeholderData: keepPreviousData,
  });

  // Per-row decision duration in the queue.
  const [decideDuration, setDecideDuration] = useState<Record<string, string>>({});
  const [decideCustom, setDecideCustom] = useState<Record<string, string>>({});

  const refresh = () => qc.invalidateQueries({ queryKey: ["approvals"] });

  // One request is filed per selected target (the backend models a request as a
  // single host or group), so picking several files several requests at once.
  const createMut = useMutation({
    mutationFn: async () => {
      const requestedSecs = durationToSecs(reqDuration, reqCustom);
      await Promise.all(selected.map((t) =>
        createApproval({
          targetKind, reason, ticketRef: ticketRef || undefined, requestedSecs,
          ...(targetKind === "host" ? { hostId: t.id } : { groupId: t.id }),
        }),
      ));
    },
    onSuccess: () => { setReason(""); setSelected([]); setTicketRef(""); refresh(); },
  });

  const decideMut = useMutation({
    mutationFn: (args: { id: string; decision: "approve" | "deny"; grantedSecs?: number }) =>
      decideApproval(args.id, { decision: args.decision, grantedSecs: args.grantedSecs }),
    onSuccess: refresh,
  });

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 2 }}>Approvals</Typography>
      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        <Tab label="My requests" />
        <Tab label="Queue" />
      </Tabs>

      {tab === 0 && (
        <Stack spacing={3}>
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Typography variant="subtitle1" sx={{ mb: 2 }}>New access request</Typography>
            <Stack spacing={2}>
              <Stack direction="row" spacing={2}>
                <TextField select size="small" label="Target kind" value={targetKind}
                  onChange={(e) => { setTargetKind(e.target.value as "host" | "group"); setSelected([]); }}
                  sx={{ minWidth: 140 }}>
                  <MenuItem value="host">Host</MenuItem>
                  <MenuItem value="group">Group</MenuItem>
                </TextField>
                <Autocomplete
                  multiple size="small" sx={{ flexGrow: 1, minWidth: 320 }}
                  options={options} value={selected}
                  onChange={(_, v) => setSelected(v)}
                  inputValue={search}
                  onInputChange={(_, v) => setSearch(v)}
                  filterOptions={(x) => x}
                  loading={targetsLoading}
                  getOptionLabel={(o) => o.name}
                  isOptionEqualToValue={(a, b) => a.id === b.id}
                  renderOption={(props, o) => (
                    <li {...props} key={o.id}>
                      {o.name}{o.environment ? ` · ${o.environment}` : ""}
                    </li>
                  )}
                  renderInput={(params) => (
                    <TextField {...params} label={targetKind === "host" ? "Hosts" : "Groups"}
                      placeholder={selected.length ? "" : "Search by name…"}
                      InputProps={{
                        ...params.InputProps,
                        endAdornment: (
                          <>
                            {targetsLoading ? <CircularProgress size={16} /> : null}
                            {params.InputProps.endAdornment}
                          </>
                        ),
                      }} />
                  )}
                  noOptionsText={debounced
                    ? `No ${targetKind === "host" ? "hosts" : "groups"} match "${debounced}"`
                    : "Type to search"}
                />
              </Stack>
              <TextField size="small" label="Reason" value={reason}
                onChange={(e) => setReason(e.target.value)} />
              <TextField size="small" label="Ticket reference" value={ticketRef}
                onChange={(e) => setTicketRef(e.target.value)} />
              <DurationSelect value={reqDuration} custom={reqCustom}
                onValue={setReqDuration} onCustom={setReqCustom} />
              <Box>
                <Button variant="contained"
                  disabled={selected.length === 0 || !reason || createMut.isPending}
                  onClick={() => createMut.mutate()}>
                  {selected.length > 1 ? `Submit ${selected.length} requests` : "Submit request"}
                </Button>
              </Box>
            </Stack>
          </Paper>
          <ApprovalTable rows={mine} />
        </Stack>
      )}

      {tab === 1 && (
        <ApprovalTable rows={queue} onDecide={(r) => {
          const dur = decideDuration[r.id] ?? "1h";
          const cust = decideCustom[r.id] ?? "60";
          return (
            <Stack direction="row" spacing={1} alignItems="center" justifyContent="flex-end">
              <DurationSelect value={dur} custom={cust}
                onValue={(v) => setDecideDuration({ ...decideDuration, [r.id]: v })}
                onCustom={(v) => setDecideCustom({ ...decideCustom, [r.id]: v })} />
              <Button size="small" variant="contained" color="success" disabled={decideMut.isPending}
                onClick={() => decideMut.mutate({ id: r.id, decision: "approve", grantedSecs: durationToSecs(dur, cust) })}>
                Approve
              </Button>
              <Button size="small" variant="outlined" color="error" disabled={decideMut.isPending}
                onClick={() => decideMut.mutate({ id: r.id, decision: "deny" })}>
                Deny
              </Button>
            </Stack>
          );
        }} />
      )}
    </Box>
  );
}
