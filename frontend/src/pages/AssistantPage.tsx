import { useState } from "react";
import {
  Alert, Box, Button, Chip, CircularProgress, Paper, Stack, Table, TableBody,
  TableCell, TableHead, TableRow, TextField, Typography,
} from "@mui/material";
import SendIcon from "@mui/icons-material/Send";
import { useQuery } from "@tanstack/react-query";
import {
  assistantStatus, askAssistant, askResult,
  type AskResult, type AssistantHost, type AssistantSession,
} from "../api/assistant";
import type { Host } from "../api/hosts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface Turn {
  q: string;
  result?: AskResult;
}

// Ask Fleet: read-only natural-language queries over fleet data, grounded in the
// real host rows returned by the backend (shown beneath each answer).
export function AssistantPage() {
  const { data: status } = useQuery({ queryKey: ["assistant-status"], queryFn: assistantStatus });
  const [turns, setTurns] = useState<Turn[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const ready = status?.ready;

  async function submit() {
    const q = input.trim();
    if (!q || busy) return;
    setInput("");
    setBusy(true);
    const idx = turns.length;
    setTurns((t) => [...t, { q }]);
    try {
      const id = await askAssistant(q);
      for (let i = 0; i < 160; i++) {
        await sleep(1500);
        const r = await askResult(id);
        if (r.status !== "pending") {
          setTurns((t) => t.map((x, j) => (j === idx ? { ...x, result: r } : x)));
          break;
        }
      }
    } catch {
      setTurns((t) => t.map((x, j) => (j === idx ? { ...x, result: { status: "error", error: "Request failed." } } : x)));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Box sx={{ maxWidth: 1000 }}>
      <Typography variant="h5" sx={{ mb: 2 }}>Ask Fleet</Typography>

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
              Ask about your fleet in plain language. The assistant can answer using each host's
              status, OS &amp; kernel version, CPU/memory specs, uptime, disk/memory/load, IP &amp;
              VPN health, groups, tags, and owner. For example:
            </Typography>
            <Box component="ul" sx={{ m: 0, pl: 3 }}>
              <li>“Which hosts have less than 20% disk free?”</li>
              <li>“List the kernel versions of all hosts.”</li>
              <li>“What production hosts are under heavy load?”</li>
              <li>“Which hosts have their WireGuard tunnel down?”</li>
              <li>“Show offline Debian hosts in the dba group.”</li>
              <li>“How much memory does each host have?”</li>
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
          {r.hosts && r.hosts.length > 0 && <HostResults hosts={r.hosts} />}
          {r.sessions && r.sessions.length > 0 && <SessionResults sessions={r.sessions} />}
          {r.host && <HostDetailPanel host={r.host} />}
        </Box>
      )}
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

function fmtTime(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

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
