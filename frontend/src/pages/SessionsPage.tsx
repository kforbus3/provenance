import { useEffect, useRef, useState } from "react";
import { formatDateTime } from "../lib/datetime";
import {
  Alert, Box, Button, Checkbox, Chip, Drawer, FormControlLabel, IconButton, MenuItem, Paper,
  Snackbar, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField,
  Tooltip, Typography, Divider, CircularProgress,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import DownloadIcon from "@mui/icons-material/Download";
import DeleteIcon from "@mui/icons-material/Delete";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import VisibilityIcon from "@mui/icons-material/Visibility";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  deleteRecording, downloadRecording, getRecording, listSessions, pruneRecordings,
  recordingStats, type SSHSession,
} from "../api/sessions";
import { useAuthStore } from "../store/auth";

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
      fontSize: 12, convertEol: true, disableStdin: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(containerRef.current);
    try { fit.fit(); } catch { /* container may not be laid out yet */ }

    // Schedule each output frame at its asciicast timestamp (seconds -> ms).
    const timers: ReturnType<typeof setTimeout>[] = [];
    for (const frame of parsed.frames) {
      timers.push(setTimeout(() => term.write(frame.data), frame.time * 1000));
    }

    return () => {
      timers.forEach(clearTimeout);
      term.dispose();
    };
  }, [data]);

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
    <Box>
      <Typography variant="caption" color="text.secondary">
        {data.recording.format} · {(data.recording.sizeBytes / 1024).toFixed(1)} KiB ·
        {" "}{Math.round(data.recording.durationMs / 1000)}s
      </Typography>
      <Box ref={containerRef} sx={{ mt: 1, height: 480, bgcolor: "#000", p: 1, borderRadius: 1 }} />
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
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }} spacing={2}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>Session Replay</Typography>
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
