import { useEffect, useRef, useState } from "react";
import { formatDateTime } from "../lib/datetime";
import {
  Alert, Box, Button, Checkbox, Chip, Drawer, FormControlLabel, IconButton, MenuItem, Paper,
  Snackbar, Stack, Tab, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Tabs,
  TextField, Tooltip, Typography, Divider, CircularProgress,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import DownloadIcon from "@mui/icons-material/Download";
import DeleteIcon from "@mui/icons-material/Delete";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import VisibilityIcon from "@mui/icons-material/Visibility";
import FullscreenIcon from "@mui/icons-material/Fullscreen";
import FullscreenExitIcon from "@mui/icons-material/FullscreenExit";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  deleteRecording, downloadRecording, getRecording, listSessions, pruneRecordings,
  recordingStats, searchSessionContent, searchSessionCommands,
  type SSHSession, type SessionSearchResult, type SessionCommand,
} from "../api/sessions";
import { useAuthStore } from "../store/auth";
import { RdpRecordingsPanel } from "../components/RdpRecordingsPanel";

// One parsed asciicast v2 output frame: absolute time offset (seconds) + bytes.
interface CastFrame {
  time: number;
  data: string;
}

interface ParsedCast {
  width: number;
  height: number;
  frames: CastFrame[];
}

// Parse an asciicast v2 stream: a JSON header line followed by one JSON event
// array ([time, type, data]) per line. Only "o" (output) events are replayed.
function parseCast(cast: string): ParsedCast {
  const lines = cast.split("\n").filter((l) => l.trim() !== "");
  const result: ParsedCast = { width: 80, height: 24, frames: [] };
  if (lines.length === 0) return result;
  try {
    const header = JSON.parse(lines[0]) as { width?: number; height?: number };
    if (header.width) result.width = header.width;
    if (header.height) result.height = header.height;
  } catch {
    // No valid header; fall through and treat all lines as events.
  }
  for (const line of lines.slice(1)) {
    try {
      const [time, type, data] = JSON.parse(line) as [number, string, string];
      if (type === "o") result.frames.push({ time, data });
    } catch {
      // Skip malformed event lines.
    }
  }
  return result;
}

function ReplayTerminal({ sessionId }: { sessionId: string }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const { data, isLoading, isError } = useQuery({
    queryKey: ["recording", sessionId],
    queryFn: () => getRecording(sessionId),
    retry: false,
  });

  useEffect(() => {
    if (!data || !containerRef.current) return;
    const parsed = parseCast(data.cast);
    const term = new Terminal({
      cols: parsed.width, rows: parsed.height,
      fontSize: 13, convertEol: true, disableStdin: true, scrollback: 5000,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(containerRef.current);
    termRef.current = term;
    fitRef.current = fit;
    try { fit.fit(); } catch { /* container may not be laid out yet */ }

    // Schedule each output frame at its asciicast timestamp (seconds -> ms).
    const timers: ReturnType<typeof setTimeout>[] = [];
    for (const frame of parsed.frames) {
      timers.push(setTimeout(() => term.write(frame.data), frame.time * 1000));
    }

    return () => {
      timers.forEach(clearTimeout);
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [data]);

  // Re-fit (and bump the font size) when toggling full screen or on window resize, so
  // the recording fills the larger area and stays legible. The grid grows to fit — the
  // recorded content keeps its geometry and simply gets more room around it.
  useEffect(() => {
    const refit = () => {
      const term = termRef.current, fit = fitRef.current;
      if (!term || !fit) return;
      term.options.fontSize = fullscreen ? 16 : 13;
      requestAnimationFrame(() => { try { fit.fit(); } catch { /* not laid out */ } });
    };
    refit();
    window.addEventListener("resize", refit);
    return () => window.removeEventListener("resize", refit);
  }, [fullscreen]);

  // Esc exits full screen. Use the CAPTURE phase: the xterm terminal can call
  // stopPropagation on keydown (so a bubble-phase window listener was missed when the
  // terminal had focus — the "sometimes Esc doesn't work"), but a capture-phase listener
  // runs first.
  useEffect(() => {
    if (!fullscreen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.stopPropagation(); setFullscreen(false); }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [fullscreen]);

  if (isLoading) {
    return <Box sx={{ p: 3, textAlign: "center" }}><CircularProgress size={24} /></Box>;
  }
  if (isError || !data) {
    return (
      <Typography color="text.secondary" sx={{ p: 2 }}>
        No recording is available for this session.
      </Typography>
    );
  }
  return (
    <Box
      sx={fullscreen
        // Clear the AppBar (dense toolbar ~48px) at the top so the caption and the first
        // line of recorded output aren't hidden behind it while expanded.
        ? { position: "fixed", inset: 0, zIndex: 1400, bgcolor: "#000", p: 2, pt: 7, display: "flex", flexDirection: "column" }
        : undefined}
    >
      <Stack direction="row" alignItems="center" spacing={1}>
        <Typography variant="caption" sx={{ color: fullscreen ? "grey.400" : "text.secondary" }}>
          {data.recording.format} · {(data.recording.sizeBytes / 1024).toFixed(1)} KiB ·
          {" "}{Math.round(data.recording.durationMs / 1000)}s
        </Typography>
        <Box sx={{ flexGrow: 1 }} />
        {!fullscreen && (
          <Tooltip title="Full screen">
            <IconButton size="small" onClick={() => setFullscreen(true)}>
              <FullscreenIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        )}
      </Stack>
      <Box
        ref={containerRef}
        sx={{
          mt: 1, bgcolor: "#000", p: 1, borderRadius: 1, overflow: "hidden",
          ...(fullscreen ? { flexGrow: 1, minHeight: 0 } : { height: 480 }),
        }}
      />
      {fullscreen && (
        // Floating, always-visible exit. Anchored bottom-right: the player renders inside a
        // right-anchored Drawer (a Modal portal whose stacking context tops out below the
        // AppBar at zIndex appBar+1), so a top-right button would be painted over by the app
        // bar. The bottom-right corner is always clear of the app bar and stays clickable.
        <Button
          variant="contained" startIcon={<FullscreenExitIcon />}
          onClick={() => setFullscreen(false)}
          sx={{ position: "fixed", bottom: 24, right: 24, zIndex: 1401, boxShadow: 6, bgcolor: "grey.100", color: "#000", "&:hover": { bgcolor: "grey.300" } }}
        >
          Exit full screen (Esc)
        </Button>
      )}
    </Box>
  );
}

// Recorded SSH session browser. Selecting a row opens a replay drawer that
// streams the asciicast recording back through an xterm.js terminal, honoring
// the original frame timing.
export function SessionsPage() {
  const qc = useQueryClient();
  const { data: sessions = [], isLoading } = useQuery({ queryKey: ["sessions"], queryFn: listSessions });
  const { data: stats } = useQuery({ queryKey: ["recording-stats"], queryFn: recordingStats });
  const [active, setActive] = useState<SSHSession | null>(null);
  const [tab, setTab] = useState(0);
  const [pruneDays, setPruneDays] = useState("30");
  const [snack, setSnack] = useState<string | null>(null);
  const canManage = useAuthStore((s) => s.has("System.Configure"));
  const canWatch = useAuthStore((s) => s.has("Session.Watch"));

  // Client-side filters over the loaded sessions (search matches user/host/IP).
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [recordingsOnly, setRecordingsOnly] = useState(false);

  const statuses = Array.from(new Set(sessions.map((s) => s.status))).sort();
  const q = search.trim().toLowerCase();
  const filtered = sessions.filter((s) => {
    if (recordingsOnly && !s.hasRecording) return false;
    if (statusFilter && s.status !== statusFilter) return false;
    if (q && !(
      s.username.toLowerCase().includes(q) ||
      s.hostname.toLowerCase().includes(q) ||
      (s.clientIp ?? "").toLowerCase().includes(q)
    )) return false;
    return true;
  });

  const exportRec = async (s: SSHSession) => {
    try {
      await downloadRecording(s);
      setSnack("Recording exported — open the .html file to watch offline.");
    } catch {
      setSnack("Could not export this recording.");
    }
  };

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["sessions"] });
    void qc.invalidateQueries({ queryKey: ["recording-stats"] });
  };
  const delMut = useMutation({ mutationFn: deleteRecording, onSuccess: invalidate });
  const pruneMut = useMutation({
    mutationFn: () => pruneRecordings(Number(pruneDays) || 30),
    onSuccess: invalidate,
  });

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 2 }}>Session Replay</Typography>
      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        <Tab label="Terminal (SSH)" />
        <Tab label="Desktop (RDP)" />
        <Tab label="Content search" />
        <Tab label="Commands" />
      </Tabs>

      {tab === 1 && <RdpRecordingsPanel />}
      {tab === 2 && <ContentSearchPanel />}
      {tab === 3 && <CommandSearchPanel />}

      {tab === 0 && (
      <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }} spacing={2}>
        <Box sx={{ flexGrow: 1 }} />
        {stats && (
          <Typography variant="body2" color="text.secondary">
            {stats.count} recordings · {formatBytes(stats.bytes)}
          </Typography>
        )}
        {canManage && (
          <Stack direction="row" spacing={1} alignItems="center">
            <TextField
              size="small" label="Delete older than (days)" type="number" value={pruneDays}
              onChange={(e) => setPruneDays(e.target.value)} sx={{ width: 180 }}
            />
            <Button
              variant="outlined" color="warning" size="medium"
              disabled={pruneMut.isPending || !(Number(pruneDays) > 0)}
              onClick={() => {
                if (window.confirm(`Permanently delete recordings older than ${pruneDays} days?`)) pruneMut.mutate();
              }}
            >
              {pruneMut.isPending ? "Pruning…" : "Prune"}
            </Button>
          </Stack>
        )}
      </Stack>
      {pruneMut.isSuccess && (
        <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: "block" }}>
          Pruned {pruneMut.data.deleted} recordings, reclaimed {formatBytes(pruneMut.data.bytesReclaimed)}.
        </Typography>
      )}

      <Stack
        direction={{ xs: "column", sm: "row" }} spacing={2}
        alignItems={{ sm: "center" }} sx={{ mb: 2 }}
      >
        <TextField
          size="small" label="Search user, host, or IP" value={search}
          onChange={(e) => setSearch(e.target.value)} sx={{ minWidth: 260 }}
        />
        <TextField
          select size="small" label="Status" value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)} sx={{ minWidth: 160 }}
        >
          <MenuItem value="">All statuses</MenuItem>
          {statuses.map((st) => <MenuItem key={st} value={st}>{st}</MenuItem>)}
        </TextField>
        <FormControlLabel
          control={<Checkbox checked={recordingsOnly} onChange={(e) => setRecordingsOnly(e.target.checked)} />}
          label="With recordings only"
        />
        <Box sx={{ flexGrow: 1 }} />
        <Typography variant="body2" color="text.secondary">
          {filtered.length} of {sessions.length}
        </Typography>
      </Stack>

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Started</TableCell>
              <TableCell>User</TableCell>
              <TableCell>Host</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Bytes (in/out)</TableCell>
              <TableCell>Client IP</TableCell>
              <TableCell align="right">Recording</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filtered.map((s) => (
              <TableRow
                key={s.id} hover
                sx={{ cursor: s.hasRecording ? "pointer" : "default" }}
                onClick={() => s.hasRecording && setActive(s)}
              >
                <TableCell>{formatDateTime(s.startedAt)}</TableCell>
                <TableCell>{s.username}</TableCell>
                <TableCell>{s.hostname}</TableCell>
                <TableCell><Chip label={s.status} size="small" /></TableCell>
                <TableCell>{s.bytesIn} / {s.bytesOut}</TableCell>
                <TableCell>{s.clientIp}</TableCell>
                <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                  {s.status === "active" && canWatch && (
                    <Tooltip title="Watch live (read-only)">
                      <IconButton size="small" color="primary"
                        onClick={() => window.open(`/sessions/${s.id}/watch`, "_blank", "noopener")}>
                        <VisibilityIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  )}
                  {s.hasRecording ? (
                    <>
                      <Tooltip title="Watch (replay)">
                        <IconButton size="small" onClick={() => setActive(s)}>
                          <PlayArrowIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Download playable recording (.html) to watch later">
                        <IconButton size="small" onClick={() => void exportRec(s)}>
                          <DownloadIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      {canManage && (
                        <Tooltip title="Delete recording">
                          <IconButton
                            size="small" color="error"
                            onClick={() => { if (window.confirm("Delete this recording?")) delMut.mutate(s.id); }}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                    </>
                  ) : (
                    <Typography variant="caption" color="text.secondary">no recording</Typography>
                  )}
                </TableCell>
              </TableRow>
            ))}
            {!isLoading && filtered.length === 0 && (
              <TableRow><TableCell colSpan={7}>
                <Typography color="text.secondary">
                  {sessions.length === 0 ? "No recorded sessions." : "No sessions match the filters."}
                </Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Drawer anchor="right" open={active !== null} onClose={() => setActive(null)}
        PaperProps={{ sx: { width: { xs: "100%", md: 760 }, p: 2 } }}>
        {active && (
          <Box>
            <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
              <Typography variant="h6" sx={{ flexGrow: 1 }}>
                {active.username}@{active.hostname}
              </Typography>
              <IconButton onClick={() => setActive(null)}><CloseIcon /></IconButton>
            </Stack>
            <Stack direction="row" spacing={2} sx={{ mb: 1 }}>
              <Typography variant="caption" color="text.secondary">
                Started {formatDateTime(active.startedAt)}
              </Typography>
              {active.endedAt && (
                <Typography variant="caption" color="text.secondary">
                  Ended {formatDateTime(active.endedAt)}
                </Typography>
              )}
              {active.exitCode !== undefined && (
                <Typography variant="caption" color="text.secondary">
                  Exit {active.exitCode}
                </Typography>
              )}
            </Stack>
            <Divider sx={{ mb: 2 }} />
            <ReplayTerminal sessionId={active.id} />
          </Box>
        )}
      </Drawer>
      </Box>
      )}

      <Snackbar
        open={Boolean(snack)} autoHideDuration={4000} onClose={() => setSnack(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      >
        <Alert severity="info" onClose={() => setSnack(null)}>{snack}</Alert>
      </Snackbar>
    </Box>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
}

// highlightMatch wraps every case-insensitive occurrence of `term` in `text` with a
// marked span, so the searched keyword stands out in the content-search snippets.
function highlightMatch(text: string, term?: string): React.ReactNode {
  const needle = (term ?? "").toLowerCase();
  if (!needle) return text;
  const lower = text.toLowerCase();
  const out: React.ReactNode[] = [];
  let from = 0;
  let key = 0;
  for (;;) {
    const i = lower.indexOf(needle, from);
    if (i < 0) { out.push(text.slice(from)); break; }
    if (i > from) out.push(text.slice(from, i));
    out.push(
      <Box component="mark" key={key++} sx={{ bgcolor: "warning.light", color: "#000", px: 0.25, borderRadius: 0.5 }}>
        {text.slice(i, i + term!.length)}
      </Box>,
    );
    from = i + needle.length;
  }
  return out;
}

// ContentSearchPanel searches across recorded SSH session content (what was typed
// and shown) — "who ran `X`, where, when" — and links each hit to its replay.
function ContentSearchPanel() {
  const [q, setQ] = useState("");
  const [replay, setReplay] = useState<SessionSearchResult | null>(null);
  const search = useMutation({
    mutationFn: (query: string) => searchSessionContent(query),
  });
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (q.trim().length >= 2) search.mutate(q.trim());
  };
  const data = search.data;
  return (
    <Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Search the content of recorded terminal sessions — commands typed and output shown — across
        the most recent recordings. Every search is audited.
      </Typography>
      <form onSubmit={submit}>
        <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
          <TextField
            size="small" fullWidth autoFocus
            label="Search recorded sessions (e.g. a command, path, or hostname)"
            value={q} onChange={(e) => setQ(e.target.value)}
          />
          <Button type="submit" variant="contained" disabled={q.trim().length < 2 || search.isPending}>
            {search.isPending ? "Searching…" : "Search"}
          </Button>
        </Stack>
      </form>

      {search.isError && <Alert severity="error" sx={{ mb: 2 }}>{(search.error as Error).message}</Alert>}

      {data && (
        <>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            {data.results.length} matching session(s) · scanned {data.scanned} of {data.recordingsInSet} recent recordings
            {data.capped ? " (capped — narrow by a more specific term)" : ""}
          </Typography>
          {data.results.length === 0 ? (
            <Paper variant="outlined" sx={{ p: 3, textAlign: "center" }}>
              <Typography color="text.secondary">No recorded session content matched.</Typography>
            </Paper>
          ) : (
            <Stack spacing={1.5}>
              {data.results.map((res: SessionSearchResult) => (
                <Paper key={res.sessionId} variant="outlined" sx={{ p: 1.5 }}>
                  <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
                    <Typography variant="subtitle2">{res.username || "—"}</Typography>
                    <Typography variant="body2" color="text.secondary">on {res.hostname || "—"}</Typography>
                    <Typography variant="caption" color="text.secondary">{formatDateTime(res.startedAt)}</Typography>
                    <Chip size="small" label={`${res.matchCount} match${res.matchCount === 1 ? "" : "es"}`} />
                    <Box sx={{ flexGrow: 1 }} />
                    <Button size="small" startIcon={<PlayArrowIcon />} onClick={() => setReplay(res)}>
                      Replay
                    </Button>
                  </Stack>
                  <Stack spacing={0.5}>
                    {res.snippets.map((s, i) => (
                      <Typography
                        key={i} variant="caption"
                        sx={{ fontFamily: "monospace", color: "text.secondary", wordBreak: "break-all" }}
                      >
                        …{highlightMatch(s, search.variables)}…
                      </Typography>
                    ))}
                  </Stack>
                </Paper>
              ))}
            </Stack>
          )}
        </>
      )}

      <Drawer anchor="right" open={replay !== null} onClose={() => setReplay(null)}
        PaperProps={{ sx: { width: { xs: "100%", md: 760 }, p: 2 } }}>
        {replay && (
          <Box>
            <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
              <Typography variant="h6" sx={{ flexGrow: 1 }}>{replay.username}@{replay.hostname}</Typography>
              <IconButton onClick={() => setReplay(null)}><CloseIcon /></IconButton>
            </Stack>
            <Typography variant="caption" color="text.secondary">Started {formatDateTime(replay.startedAt)}</Typography>
            <Divider sx={{ my: 2 }} />
            <ReplayTerminal sessionId={replay.sessionId} />
          </Box>
        )}
      </Drawer>
    </Box>
  );
}

// CommandSearchPanel searches the INDEXED commands users TYPED in recorded terminal
// sessions ("who ran X") — fast and across all history, unlike the on-the-fly content
// search. Best-effort reconstruction; each hit links to its replay.
function CommandSearchPanel() {
  const [q, setQ] = useState("");
  const [hostname, setHostname] = useState("");
  const [replayId, setReplayId] = useState<string | null>(null);
  const search = useMutation({
    mutationFn: ({ query, host }: { query: string; host: string }) => searchSessionCommands(query, host || undefined),
  });
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (q.trim().length >= 2) search.mutate({ query: q.trim(), host: hostname.trim() });
  };
  const results = search.data;
  return (
    <Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Search the commands users <b>typed</b> in recorded terminal sessions, across all history.
        Reconstructed from the recordings (best-effort — tab-completion and history-recalled commands
        may be partial), and only recorded sessions are covered. Every search is audited.
      </Typography>
      <form onSubmit={submit}>
        <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ mb: 2 }}>
          <TextField
            size="small" fullWidth autoFocus
            label="Command contains (e.g. systemctl, rm -rf)"
            value={q} onChange={(e) => setQ(e.target.value)}
          />
          <TextField
            size="small" label="Host (optional)" value={hostname}
            onChange={(e) => setHostname(e.target.value)} sx={{ minWidth: 180 }}
          />
          <Button type="submit" variant="contained" disabled={q.trim().length < 2 || search.isPending}>
            {search.isPending ? "Searching…" : "Search"}
          </Button>
        </Stack>
      </form>

      {search.isError && <Alert severity="error" sx={{ mb: 2 }}>{(search.error as Error).message}</Alert>}

      {results && (
        results.length === 0 ? (
          <Paper variant="outlined" sx={{ p: 3, textAlign: "center" }}>
            <Typography color="text.secondary">No typed commands matched.</Typography>
          </Paper>
        ) : (
          <>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              {results.length} match{results.length === 1 ? "" : "es"}{results.length >= 200 ? " (showing the 200 most recent — narrow your query)" : ""}
            </Typography>
            <TableContainer component={Paper} variant="outlined">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Time</TableCell><TableCell>User</TableCell><TableCell>Host</TableCell>
                    <TableCell>Command (typed)</TableCell><TableCell />
                  </TableRow>
                </TableHead>
                <TableBody>
                  {results.map((r: SessionCommand, i) => (
                    <TableRow key={i} hover>
                      <TableCell sx={{ whiteSpace: "nowrap", color: "text.secondary" }}>{formatDateTime(r.at)}</TableCell>
                      <TableCell>{r.username || "—"}</TableCell>
                      <TableCell>{r.hostname || "—"}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>{r.command}</TableCell>
                      <TableCell align="right">
                        <Button size="small" startIcon={<PlayArrowIcon />} onClick={() => setReplayId(r.sshSessionId)}>
                          Replay
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </>
        )
      )}

      <Drawer anchor="right" open={replayId !== null} onClose={() => setReplayId(null)}
        PaperProps={{ sx: { width: { xs: "100%", md: 760 }, p: 2 } }}>
        {replayId && (
          <Box>
            <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
              <Typography variant="h6" sx={{ flexGrow: 1 }}>Session replay</Typography>
              <IconButton onClick={() => setReplayId(null)}><CloseIcon /></IconButton>
            </Stack>
            <Divider sx={{ my: 2 }} />
            <ReplayTerminal sessionId={replayId} />
          </Box>
        )}
      </Drawer>
    </Box>
  );
}
