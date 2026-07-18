import { useEffect, useRef, useState } from "react";
import { formatDateTime } from "../lib/datetime";
import {
  Alert, Box, Button, Chip, CircularProgress, Link, Paper, Stack, Table, TableBody,
  TableCell, TableHead, TableRow, TextField, Typography, useTheme,
} from "@mui/material";
import SendIcon from "@mui/icons-material/Send";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import BoltIcon from "@mui/icons-material/Bolt";
import { Link as RouterLink } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "../store/auth";
import {
  assistantStatus, askAssistant, askResult, executeAssistantAction, cancelAssistantAction,
  requestApprovalAssistantAction, listAssistantApprovals, approveAssistantAction, denyAssistantAction,
  listAssistantActions,
  type AskResult, type AssistantAction, type AssistantHost, type AssistantSession, type AssistantTable,
  type DocSource, type MetricHistory, type MetricHistoryPoint,
} from "../api/assistant";
import type { Host } from "../api/hosts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface Turn {
  q: string;
  result?: AskResult;
}

// Persist the visible conversation per browser tab so a refresh doesn't wipe it.
const STORE_KEY = "ask-fleet-session";
function loadStored(): { turns: Turn[]; conversationId?: string } {
  try {
    const raw = sessionStorage.getItem(STORE_KEY);
    if (raw) return JSON.parse(raw) as { turns: Turn[]; conversationId?: string };
  } catch { /* ignore corrupt/oversized storage */ }
  return { turns: [] };
}

// Ask Fleet: read-only natural-language queries over fleet data, grounded in the
// real host rows returned by the backend (shown beneath each answer).
export function AssistantPage() {
  const { data: status } = useQuery({ queryKey: ["assistant-status"], queryFn: assistantStatus });
  const canApprove = useAuthStore((s) => s.has)("Assistant.Approve");
  const stored = useRef(loadStored());
  const [turns, setTurns] = useState<Turn[]>(stored.current.turns);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const convoRef = useRef<string | undefined>(stored.current.conversationId);
  const mounted = useRef(true);
  const ready = status?.ready;

  // Stop the in-flight poll loop when the page unmounts.
  useEffect(() => () => { mounted.current = false; }, []);

  // Persist the conversation (turns + thread id) on every change.
  useEffect(() => {
    try {
      sessionStorage.setItem(STORE_KEY, JSON.stringify({ turns, conversationId: convoRef.current }));
    } catch { /* storage full or unavailable — non-fatal */ }
  }, [turns]);

  function newConversation() {
    if (busy) return;
    convoRef.current = undefined;
    setTurns([]);
    try { sessionStorage.removeItem(STORE_KEY); } catch { /* ignore */ }
  }

  async function submit() {
    const q = input.trim();
    if (!q || busy) return;
    setInput("");
    setBusy(true);
    const idx = turns.length;
    setTurns((t) => [...t, { q }]);
    try {
      const { id, conversationId } = await askAssistant(q, convoRef.current);
      convoRef.current = conversationId; // continue this thread on the next question
      for (let i = 0; i < 160; i++) {
        await sleep(1500);
        if (!mounted.current) return; // page left — stop polling
        const r = await askResult(id);
        if (r.status !== "pending") {
          setTurns((t) => t.map((x, j) => (j === idx ? { ...x, result: r } : x)));
          break;
        }
      }
    } catch {
      if (!mounted.current) return;
      setTurns((t) => t.map((x, j) => (j === idx ? { ...x, result: { status: "error", error: "Request failed." } } : x)));
    } finally {
      if (mounted.current) setBusy(false);
    }
  }

  return (
    <Box sx={{ maxWidth: 1000 }}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
        <Typography variant="h5">Ask Fleet</Typography>
        {turns.length > 0 && (
          <Button size="small" onClick={newConversation} disabled={busy}>New conversation</Button>
        )}
      </Stack>

      {canApprove && <ApprovalsInbox />}

      {status && !ready && (
        <Alert severity="info" sx={{ mb: 2 }}>
          The assistant isn't ready yet. An administrator can enable it and point it at a local
          Ollama instance under <b>Settings → AI assistant</b>.
        </Alert>
      )}

      <Stack spacing={2} sx={{ mb: 2 }}>
        {turns.length === 0 && ready && (
          <Box sx={{ color: "text.secondary" }}>
            <Typography variant="body2" sx={{ mb: 1 }}>
              Ask about your fleet in plain language. The assistant can answer from each host's
              inventory and live metrics, usage history, SSH session and file-transfer records,
              scan/playbook history and schedules, and the audit trail. It remembers earlier
              questions in the same conversation, so you can ask follow-ups like “and db-02?”.
              For example:
            </Typography>
            <Box component="ul" sx={{ m: 0, pl: 3 }}>
              <li>“Which hosts have less than 20% disk free?”</li>
              <li>“What is the disk usage trend on web-01 over the past week?”</li>
              <li>“Who connected to db-02 yesterday?”</li>
              <li>“Any failed scans or playbook runs recently?”</li>
              <li>“What changed in the audit log today?”</li>
              <li>“What runs on a schedule, and when does it fire next?”</li>
              <li>“Which hosts have security updates pending?”</li>
            </Box>
          </Box>
        )}
        {turns.map((t, i) => <TurnView key={i} turn={t} />)}
      </Stack>

      <Paper variant="outlined" sx={{ p: 1.5 }}>
        <Stack direction="row" spacing={1}>
          <TextField
            fullWidth size="small" placeholder="Ask about your fleet…" value={input}
            disabled={!ready || busy}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void submit(); } }}
          />
          <Button
            variant="contained"
            endIcon={busy ? <CircularProgress size={16} color="inherit" /> : <SendIcon />}
            disabled={!ready || busy || !input.trim()} onClick={() => void submit()}
          >
            Ask
          </Button>
        </Stack>
      </Paper>
      {status?.model && (
        <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
          Model: {status.model} · answers are generated from live Fleet data — verify before acting.
        </Typography>
      )}

      <HistoryPanel />
    </Box>
  );
}

function TurnView({ turn }: { turn: Turn }) {
  const r = turn.result;
  return (
    <Box>
      <Paper variant="outlined" sx={{ p: 1.5, mb: 1, bgcolor: "action.hover" }}>
        <Typography variant="body2"><b>You:</b> {turn.q}</Typography>
      </Paper>
      {!r && (
        <Stack direction="row" spacing={1} alignItems="center" sx={{ pl: 1 }}>
          <CircularProgress size={16} /><Typography variant="body2" color="text.secondary">Thinking…</Typography>
        </Stack>
      )}
      {r?.status === "error" && <Alert severity="error">{r.error || "Failed."}</Alert>}
      {r?.status === "done" && (
        <Box sx={{ pl: 1 }}>
          {r.answer && <Typography variant="body2" sx={{ whiteSpace: "pre-wrap", mb: 1 }}>{r.answer}</Typography>}
          {r.actions && r.actions.map((a) => <ActionCard key={a.id} action={a} />)}
          {r.hosts && r.hosts.length > 0 && <HostResults hosts={r.hosts} />}
          {r.sessions && r.sessions.length > 0 && <SessionResults sessions={r.sessions} />}
          {r.host && <HostDetailPanel host={r.host} />}
          {r.history && r.history.points.length > 0 && <MetricHistoryPanel history={r.history} />}
          {r.table && r.table.rows.length > 0 && <TablePanel table={r.table} />}
          {r.sources && r.sources.length > 0 && <SourcesPanel sources={r.sources} />}
        </Box>
      )}
    </Box>
  );
}

// ActionCard renders a single proposed action with Confirm / Dismiss. The
// assistant only PROPOSES; the action runs solely when the user confirms here,
// and the backend re-authorizes at execution.
function ActionCard({ action }: { action: AssistantAction }) {
  const [state, setState] = useState<AssistantAction>(action);
  const [err, setErr] = useState<string | null>(null);
  const errMsg = (e: unknown) =>
    ((e as { response?: { data?: { error?: string } } })?.response?.data?.error) || "Something went wrong.";
  const guarded = state.risk !== "safe";

  // For safe actions Confirm runs it; for guarded actions it requests approval.
  const confirm = useMutation({
    mutationFn: () => (guarded ? requestApprovalAssistantAction(action.id) : executeAssistantAction(action.id)),
    onSuccess: (a) => { setErr(null); setState(a); },
    onError: (e) => setErr(errMsg(e)),
  });
  const dismiss = useMutation({
    mutationFn: () => cancelAssistantAction(action.id),
    onSuccess: () => { setErr(null); setState({ ...state, status: "cancelled" }); },
    onError: (e) => setErr(errMsg(e)),
  });

  const pending = state.status === "proposed";
  const busy = confirm.isPending || dismiss.isPending;
  const statusColor = state.status === "executed" ? "success"
    : (state.status === "failed" || state.status === "denied") ? "error" : "default";

  return (
    <Paper variant="outlined" sx={{ p: 1.5, my: 1, borderColor: pending ? "warning.main" : "divider" }}>
      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }}>
        <BoltIcon fontSize="small" color={pending ? "warning" : "disabled"} />
        <Typography variant="subtitle2">Proposed action</Typography>
        <Chip size="small" variant="outlined" label={state.risk} color={guarded ? "warning" : "default"} />
      </Stack>
      <Typography variant="body2" sx={{ mb: 1 }}>{state.preview}</Typography>
      {guarded && pending && (
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
          This action needs a second person to approve it before it runs.
        </Typography>
      )}
      {err && <Alert severity="error" sx={{ mb: 1 }}>{err}</Alert>}
      {pending ? (
        <Stack direction="row" spacing={1}>
          <Button size="small" variant="contained" color={guarded ? "warning" : "primary"} disabled={busy} onClick={() => confirm.mutate()}>
            {confirm.isPending ? "…" : guarded ? "Request approval" : "Confirm"}
          </Button>
          <Button size="small" color="inherit" disabled={busy} onClick={() => dismiss.mutate()}>Dismiss</Button>
        </Stack>
      ) : state.status === "pending_approval" ? (
        <Chip size="small" color="warning" variant="outlined" label="Awaiting approval" />
      ) : (
        <Chip size="small" color={statusColor}
          label={
            state.status === "executed" ? (state.outcome || "Done")
              : state.status === "failed" ? (state.outcome || "Failed")
                : state.status === "denied" ? "Denied"
                  : state.status === "cancelled" ? "Dismissed" : state.status
          } />
      )}
    </Paper>
  );
}

// HistoryPanel is a collapsible list of the user's recent assistant actions.
function HistoryPanel() {
  const { data: actions = [] } = useQuery({ queryKey: ["assistant-actions-history"], queryFn: listAssistantActions });
  const [open, setOpen] = useState(false);
  if (actions.length === 0) return null;
  const color = (s: string): "success" | "error" | "warning" | "default" =>
    s === "executed" ? "success" : (s === "failed" || s === "denied") ? "error" : s === "pending_approval" ? "warning" : "default";
  return (
    <Box sx={{ mt: 3 }}>
      <Button size="small" onClick={() => setOpen((o) => !o)}>
        {open ? "Hide" : "Show"} recent actions ({actions.length})
      </Button>
      {open && (
        <Paper variant="outlined" sx={{ mt: 1, p: 1 }}>
          <Stack spacing={0.75}>
            {actions.map((a) => (
              <Box key={a.id} sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                <Chip size="small" color={color(a.status)} label={a.status.replace("_", " ")} />
                <Typography variant="body2" sx={{ flexGrow: 1, minWidth: 180 }}>{a.preview}</Typography>
                {a.outcome && <Typography variant="caption" color="text.secondary">{a.outcome}</Typography>}
              </Box>
            ))}
          </Stack>
        </Paper>
      )}
    </Box>
  );
}

// ApprovalsInbox shows guarded actions awaiting the current user's approval. Only
// rendered for users with Assistant.Approve.
function ApprovalsInbox() {
  const qc = useQueryClient();
  const { data: pending = [] } = useQuery({ queryKey: ["assistant-approvals"], queryFn: listAssistantApprovals });
  const [err, setErr] = useState<string | null>(null);
  const errMsg = (e: unknown) =>
    ((e as { response?: { data?: { error?: string } } })?.response?.data?.error) || "Something went wrong.";
  const refresh = () => qc.invalidateQueries({ queryKey: ["assistant-approvals"] });
  const approve = useMutation({ mutationFn: (id: string) => approveAssistantAction(id), onSuccess: refresh, onError: (e) => setErr(errMsg(e)) });
  const deny = useMutation({ mutationFn: (id: string) => denyAssistantAction(id), onSuccess: refresh, onError: (e) => setErr(errMsg(e)) });

  if (pending.length === 0) return null;
  const busy = approve.isPending || deny.isPending;
  return (
    <Paper variant="outlined" sx={{ p: 1.5, mb: 2, borderColor: "warning.main" }}>
      <Typography variant="subtitle2" sx={{ mb: 1 }}>Awaiting your approval ({pending.length})</Typography>
      {err && <Alert severity="error" sx={{ mb: 1 }}>{err}</Alert>}
      <Stack spacing={1}>
        {pending.map((a) => (
          <Box key={a.id} sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
            <Chip size="small" variant="outlined" color="warning" label={a.risk} />
            <Typography variant="body2" sx={{ flexGrow: 1, minWidth: 200 }}>
              {a.preview}{a.requester ? ` — requested by ${a.requester}` : ""}
            </Typography>
            <Button size="small" color="success" disabled={busy}
              onClick={() => { if (window.confirm(`Approve and run: ${a.preview}`)) approve.mutate(a.id); }}>Approve</Button>
            <Button size="small" color="error" disabled={busy} onClick={() => deny.mutate(a.id)}>Deny</Button>
          </Box>
        ))}
      </Stack>
    </Paper>
  );
}

// SourcesPanel lists the documentation sections the assistant cited, each linking
// into the in-app help at the exact heading.
function SourcesPanel({ sources }: { sources: DocSource[] }) {
  return (
    <Box sx={{ mt: 1.5 }}>
      <Stack direction="row" spacing={0.5} alignItems="center" sx={{ mb: 0.5 }}>
        <MenuBookIcon fontSize="small" sx={{ opacity: 0.6 }} />
        <Typography variant="caption" color="text.secondary">Sources</Typography>
      </Stack>
      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
        {sources.map((s, i) => (
          <Link key={`${s.slug}-${s.anchor}-${i}`} component={RouterLink}
            to={`/help/${s.slug}${s.anchor ? `#${s.anchor}` : ""}`} underline="hover">
            <Chip size="small" variant="outlined" clickable
              label={`${s.docTitle}${s.heading && s.heading !== s.docTitle ? ` → ${s.heading}` : ""}`} />
          </Link>
        ))}
      </Stack>
    </Box>
  );
}

function HostResults({ hosts }: { hosts: AssistantHost[] }) {
  return (
    <Paper variant="outlined" sx={{ overflowX: "auto" }}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Host</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>OS</TableCell>
            <TableCell>IP</TableCell>
            <TableCell align="right">Disk free</TableCell>
            <TableCell align="right">Mem used</TableCell>
            <TableCell align="right">Load/core</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {hosts.map((h) => (
            <TableRow key={h.hostname}>
              <TableCell>{h.hostname}</TableCell>
              <TableCell>
                <Chip size="small" label={h.status}
                  color={h.status === "online" ? "success" : h.status === "offline" ? "error" : "default"} />
              </TableCell>
              <TableCell>{h.os || "—"}</TableCell>
              <TableCell>{h.primaryIp || "—"}</TableCell>
              <TableCell align="right">{h.diskFreePct != null ? `${Math.round(h.diskFreePct)}%` : "—"}</TableCell>
              <TableCell align="right">{h.memUsedPct != null ? `${Math.round(h.memUsedPct)}%` : "—"}</TableCell>
              <TableCell align="right">{h.loadPerCore != null ? h.loadPerCore.toFixed(2) : "—"}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Paper>
  );
}

const fmtTime = (iso?: string): string => formatDateTime(iso);

function fmtBytes(b: number): string {
  if (!b) return "0";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let v = b, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}

function SessionResults({ sessions }: { sessions: AssistantSession[] }) {
  return (
    <Paper variant="outlined" sx={{ overflowX: "auto" }}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>User</TableCell>
            <TableCell>Host</TableCell>
            <TableCell>Client IP</TableCell>
            <TableCell>Connected since</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {sessions.map((s, i) => (
            <TableRow key={i}>
              <TableCell>{s.username}</TableCell>
              <TableCell>{s.hostname}</TableCell>
              <TableCell>{s.clientIp || "—"}</TableCell>
              <TableCell>{fmtTime(s.startedAt)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Paper>
  );
}

// TablePanel renders a generic tabular tool result (audit events, schedules,
// past sessions, file transfers). Column kinds tell it how to format values.
function TablePanel({ table }: { table: AssistantTable }) {
  const cell = (v: string, kind?: string): string => {
    if (!v) return "—";
    if (kind === "time") return fmtTime(v);
    if (kind === "bytes") return fmtBytes(Number(v) || 0);
    return v;
  };
  return (
    <Paper variant="outlined" sx={{ overflowX: "auto" }}>
      <Typography variant="subtitle2" sx={{ px: 1.5, pt: 1 }}>{table.title}</Typography>
      <Table size="small">
        <TableHead>
          <TableRow>
            {table.columns.map((c) => (
              <TableCell key={c.label} align={c.kind === "bytes" ? "right" : "left"}>{c.label}</TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {table.rows.map((row, i) => (
            <TableRow key={i}>
              {row.map((v, j) => {
                const kind = table.columns[j]?.kind;
                return (
                  <TableCell key={j} align={kind === "bytes" ? "right" : "left"}
                    sx={kind === "time" ? { whiteSpace: "nowrap" } : undefined}>
                    {cell(v, kind)}
                  </TableCell>
                );
              })}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Paper>
  );
}

function HostDetailPanel({ host }: { host: Host }) {
  const inv = host.inventory;
  const st = host.status;
  const met = host.metrics;
  return (
    <Paper variant="outlined" sx={{ p: 1.5 }}>
      <Typography variant="subtitle2" sx={{ mb: 1 }}>
        {host.hostname}{host.environment ? ` · ${host.environment}` : ""}
        {st && <Chip size="small" sx={{ ml: 1 }} label={st.status}
          color={st.status === "online" ? "success" : st.status === "offline" ? "error" : "default"} />}
      </Typography>
      <Stack direction="row" flexWrap="wrap" gap={2} sx={{ mb: met?.disk?.length ? 1.5 : 0 }}>
        <Fact label="OS" value={[inv?.osName, inv?.osVersion].filter(Boolean).join(" ")} />
        <Fact label="Kernel" value={inv?.kernelVersion} />
        <Fact label="Arch" value={inv?.architecture} />
        <Fact label="CPUs" value={inv?.cpuCount ? String(inv.cpuCount) : ""} />
        <Fact label="Memory" value={inv?.memoryMb ? `${(inv.memoryMb / 1024).toFixed(1)} GB` : ""} />
        <Fact label="Primary IP" value={met?.primaryIp} />
        <Fact label="Gateway" value={met?.network?.defaultGateway} />
      </Stack>

      {met?.disk && met.disk.length > 0 && (
        <>
          <Typography variant="caption" color="text.secondary">Filesystems</Typography>
          <Table size="small" sx={{ mb: met.network?.interfaces?.length ? 1.5 : 0 }}>
            <TableHead><TableRow>
              <TableCell>Mount</TableCell><TableCell align="right">Used</TableCell>
              <TableCell align="right">Size</TableCell><TableCell align="right">Used %</TableCell>
            </TableRow></TableHead>
            <TableBody>
              {met.disk.map((d) => (
                <TableRow key={d.mount}>
                  <TableCell>{d.mount}</TableCell>
                  <TableCell align="right">{fmtBytes(d.usedBytes)}</TableCell>
                  <TableCell align="right">{fmtBytes(d.sizeBytes)}</TableCell>
                  <TableCell align="right">{Math.round(d.usePct)}%</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </>
      )}

      {met?.network?.interfaces && met.network.interfaces.length > 0 && (
        <>
          <Typography variant="caption" color="text.secondary">Interfaces</Typography>
          <Stack spacing={0.25} sx={{ mt: 0.5 }}>
            {met.network.interfaces.map((ni) => (
              <Typography key={ni.name} variant="body2" sx={{ fontFamily: "monospace" }}>
                {ni.name}: {ni.addrs?.join(", ") || "—"}
              </Typography>
            ))}
          </Stack>
        </>
      )}
    </Paper>
  );
}

function Fact({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return (
    <Box>
      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{label}</Typography>
      <Typography variant="body2">{value}</Typography>
    </Box>
  );
}

// One metric's trend: how to pull the average + worst-case extreme out of a bucket,
// and how to read/colour the change.
interface Series {
  key: string;          // metric name the backend uses in history.metrics
  label: string;
  color: string;
  avgKey: keyof MetricHistoryPoint;
  extremeKey: keyof MetricHistoryPoint;
  extremeLabel: string; // "low" (disk free) or "peak" (mem/load)
  worseWhenUp: boolean;  // direction of a "bad" change, for delta colouring
  fmt: (v: number) => string;
}

// MetricHistoryPanel renders a small line chart per metric that has data, so a
// trend answer ("disk usage over 48h") is backed by a visible graph. Dependency-free
// inline SVG — no charting library.
function MetricHistoryPanel({ history }: { history: MetricHistory }) {
  const theme = useTheme();
  const pct = (v: number) => `${v.toFixed(0)}%`;
  const num = (v: number) => v.toFixed(2);
  const series: Series[] = [
    { key: "disk", label: "Disk free", color: theme.palette.primary.main, avgKey: "diskFreePctAvg", extremeKey: "diskFreePctMin", extremeLabel: "low", worseWhenUp: false, fmt: pct },
    { key: "memory", label: "Memory used", color: theme.palette.warning.main, avgKey: "memUsedPctAvg", extremeKey: "memUsedPctMax", extremeLabel: "peak", worseWhenUp: true, fmt: pct },
    { key: "load", label: "Load per core", color: theme.palette.info.main, avgKey: "loadPerCoreAvg", extremeKey: "loadPerCoreMax", extremeLabel: "peak", worseWhenUp: true, fmt: num },
  ];
  // Show only the series the question was about (backend sends the selection);
  // no selection = all series with data.
  const want = history.metrics?.length ? new Set(history.metrics) : null;
  const active = series.filter((s) =>
    (!want || want.has(s.key)) && history.points.some((p) => p[s.avgKey] != null));
  if (active.length === 0) return null;
  const windowLabel = history.windowHours % 24 === 0
    ? `${history.windowHours / 24}d`
    : `${history.windowHours}h`;
  return (
    <Paper variant="outlined" sx={{ p: 1.5 }}>
      <Typography variant="subtitle2" sx={{ mb: 1 }}>
        {history.hostname} · last {windowLabel}
        <Typography component="span" variant="caption" color="text.secondary" sx={{ ml: 1 }}>
          ({history.bucketMinutes}-min buckets)
        </Typography>
      </Typography>
      <Stack spacing={2}>
        {active.map((s) => <TrendChart key={s.label} points={history.points} s={s} />)}
      </Stack>
    </Paper>
  );
}

function TrendChart({ points, s }: { points: MetricHistoryPoint[]; s: Series }) {
  const theme = useTheme();
  const data = points
    .map((p) => ({ t: new Date(p.t).getTime(), v: p[s.avgKey] as number | undefined, e: p[s.extremeKey] as number | undefined }))
    .filter((d) => d.v != null && Number.isFinite(d.t)) as { t: number; v: number; e?: number }[];
  if (data.length === 0) return null;

  const first = data[0].v;
  const last = data[data.length - 1].v;
  const delta = last - first;
  const extreme = data.reduce<number | undefined>((acc, d) => {
    if (d.e == null) return acc;
    if (acc == null) return d.e;
    return s.worseWhenUp ? Math.max(acc, d.e) : Math.min(acc, d.e);
  }, undefined);

  const worse = s.worseWhenUp ? delta > 0 : delta < 0;
  const deltaColor = Math.abs(delta) < 1e-9
    ? theme.palette.text.secondary
    : worse ? theme.palette.error.main : theme.palette.success.main;
  const arrow = delta > 0 ? "▲" : delta < 0 ? "▼" : "→";

  // Geometry. The viewBox stretches horizontally to fill width (preserveAspectRatio
  // none); vertical scale is 1:1 (height matches viewBox height) and non-scaling
  // strokes keep the line crisp regardless of the horizontal stretch.
  const W = 600, H = 96, padX = 6, padY = 10;
  const t0 = data[0].t, t1 = data[data.length - 1].t;
  const tSpan = t1 - t0 || 1;
  let lo = Math.min(...data.map((d) => d.v));
  let hi = Math.max(...data.map((d) => d.v));
  if (hi - lo < 1e-9) { lo -= 1; hi += 1; } // flat series: give it a visible band
  const vSpan = hi - lo;
  const px = (t: number) => padX + ((t - t0) / tSpan) * (W - 2 * padX);
  const py = (v: number) => padY + (1 - (v - lo) / vSpan) * (H - 2 * padY);
  const line = data.map((d) => `${px(d.t).toFixed(1)},${py(d.v).toFixed(1)}`).join(" ");
  const area = `${padX},${H - padY} ${line} ${W - padX},${H - padY}`;
  const lp = data[data.length - 1];

  return (
    <Box>
      <Stack direction="row" alignItems="baseline" spacing={1} sx={{ mb: 0.5, flexWrap: "wrap" }}>
        <Box sx={{ width: 10, height: 10, borderRadius: "2px", bgcolor: s.color, alignSelf: "center" }} />
        <Typography variant="body2" sx={{ fontWeight: 600 }}>{s.label}</Typography>
        <Typography variant="body2" color="text.secondary">{s.fmt(first)} → {s.fmt(last)}</Typography>
        <Typography variant="body2" sx={{ color: deltaColor, fontWeight: 600 }}>{arrow} {s.fmt(Math.abs(delta))}</Typography>
        {extreme != null && (
          <Typography variant="caption" color="text.secondary">{s.extremeLabel} {s.fmt(extreme)}</Typography>
        )}
      </Stack>
      <Box sx={{ position: "relative" }}>
        <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none"
          style={{ display: "block" }}>
          <polygon points={area} fill={s.color} opacity={0.1} />
          <polyline points={line} fill="none" stroke={s.color} strokeWidth={2}
            strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
          <circle cx={px(lp.t)} cy={py(lp.v)} r={2.5} fill={s.color} vectorEffect="non-scaling-stroke" />
        </svg>
        <Typography variant="caption" color="text.secondary"
          sx={{ position: "absolute", top: 0, left: 2, lineHeight: 1, pointerEvents: "none" }}>{s.fmt(hi)}</Typography>
        <Typography variant="caption" color="text.secondary"
          sx={{ position: "absolute", bottom: 0, left: 2, lineHeight: 1, pointerEvents: "none" }}>{s.fmt(lo)}</Typography>
      </Box>
      <Stack direction="row" justifyContent="space-between" sx={{ mt: 0.25 }}>
        <Typography variant="caption" color="text.secondary">{formatDateTime(new Date(t0).toISOString())}</Typography>
        <Typography variant="caption" color="text.secondary">{formatDateTime(new Date(t1).toISOString())}</Typography>
      </Stack>
    </Box>
  );
}
