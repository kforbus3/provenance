import { useCallback, useEffect, useRef, useState } from "react";
import {
  Box, Button, Chip, CircularProgress, Divider, Drawer, IconButton, Slider, Stack,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField,
  Tooltip, Typography, Paper,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import DeleteIcon from "@mui/icons-material/Delete";
import DownloadIcon from "@mui/icons-material/Download";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import PauseIcon from "@mui/icons-material/Pause";
import FullscreenIcon from "@mui/icons-material/Fullscreen";
import FullscreenExitIcon from "@mui/icons-material/FullscreenExit";
import Guacamole from "guacamole-common-js";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { formatDateTime } from "../lib/datetime";
import {
  deleteRdpRecording, downloadRdpRecordingBlob, listRdpRecordings, rdpRecordingStats,
  type RDPRecording,
} from "../api/rdpRecordings";
import { getAccessToken } from "../api/client";
import { useAuthStore } from "../store/auth";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
}

function formatDuration(ms: number): string {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${m}:${String(rem).padStart(2, "0")}`;
}

// RdpPlayer replays a Guacamole RDP recording in-app. It downloads the raw recording
// as a Blob and feeds it to Guacamole.SessionRecording, which renders to a canvas and
// exposes play/pause/seek.
function RdpPlayer({ id }: { id: string }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const recRef = useRef<Guacamole.SessionRecording | null>(null);
  const displayRef = useRef<Guacamole.Display | null>(null);
  const fullscreenRef = useRef(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [playing, setPlaying] = useState(false);
  const [position, setPosition] = useState(0);
  const [duration, setDuration] = useState(0);
  const [fullscreen, setFullscreen] = useState(false);

  // rescale fits the Guacamole canvas to its container: to the container WIDTH normally
  // (never upscaling past 1×), and to fit BOTH width and height in full screen so the
  // desktop fills the viewport.
  const rescale = useCallback(() => {
    const box = containerRef.current, display = displayRef.current;
    if (!box || !display) return;
    const w = display.getWidth(), h = display.getHeight();
    if (w <= 0) return;
    if (fullscreenRef.current && h > 0) {
      display.scale(Math.min(box.clientWidth / w, box.clientHeight / h));
    } else {
      display.scale(Math.min(1, box.clientWidth / w));
    }
  }, []);

  useEffect(() => {
    if (!containerRef.current) return;
    const token = getAccessToken();
    if (!token) { setError("Not authenticated."); setLoading(false); return; }

    // Stream the recording through a Guacamole tunnel (rather than downloading a Blob
    // and using the library's block-sliced Blob parser, which mis-parses the stream).
    // The tunnel XHR can't set an auth header, so authenticate via ?token=.
    const url = `/api/v1/rdp/recordings/${id}/stream?token=${encodeURIComponent(token)}`;
    const tunnel = new Guacamole.StaticHTTPTunnel(url);
    const recording = new Guacamole.SessionRecording(tunnel);
    recRef.current = recording;

    const display = recording.getDisplay();
    displayRef.current = display;
    containerRef.current.innerHTML = "";
    containerRef.current.appendChild(display.getElement());
    display.onresize = rescale;

    recording.onprogress = (dur: number) => { setDuration(dur); setLoading(false); };
    recording.onload = () => { setLoading(false); setDuration(recording.getDuration()); rescale(); };
    recording.onerror = (msg: string) => { setError(msg || "Could not load the recording."); setLoading(false); };
    recording.onplay = () => setPlaying(true);
    recording.onpause = () => setPlaying(false);
    recording.onseek = (pos: number) => setPosition(pos);
    recording.connect(); // begin streaming the recording

    return () => {
      try { recording.pause(); recording.disconnect(); recording.abort(); } catch { /* already gone */ }
      recRef.current = null;
      displayRef.current = null;
    };
  }, [id, rescale]);

  // Full-screen: rescale to fit, Esc (capture phase) exits, re-fit on window resize.
  useEffect(() => {
    fullscreenRef.current = fullscreen;
    requestAnimationFrame(rescale);
    if (!fullscreen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { e.stopPropagation(); setFullscreen(false); } };
    window.addEventListener("keydown", onKey, true);
    window.addEventListener("resize", rescale);
    return () => { window.removeEventListener("keydown", onKey, true); window.removeEventListener("resize", rescale); };
  }, [fullscreen, rescale]);

  const toggle = () => {
    const rec = recRef.current;
    if (!rec) return;
    if (rec.isPlaying()) rec.pause();
    else rec.play();
  };

  const onSeek = (_: Event, value: number | number[]) => {
    const rec = recRef.current;
    if (!rec) return;
    const pos = Array.isArray(value) ? value[0] : value;
    setPosition(pos);
    rec.seek(pos);
  };

  return (
    <Box sx={fullscreen ? { position: "fixed", inset: 0, zIndex: 1400, bgcolor: "black", display: "flex", flexDirection: "column", p: 1 } : undefined}>
      {error && <Typography color="error" sx={{ mb: 1 }}>{error}</Typography>}
      <Box sx={{ position: "relative", bgcolor: "black", borderRadius: fullscreen ? 0 : 1, overflow: "auto",
        ...(fullscreen ? { flexGrow: 1, minHeight: 0 } : { minHeight: 240 }) }}>
        {/* Guacamole appends its canvas here; this node has NO React children so
            React never reconciles against the manually-inserted canvas. */}
        <Box
          ref={containerRef}
          sx={{ display: "flex", justifyContent: "center", alignItems: "center",
            height: fullscreen ? "100%" : "auto", "& canvas": { display: "block" } }}
        />
        {loading && !error && (
          <Box sx={{ position: "absolute", inset: 0, display: "flex", justifyContent: "center", alignItems: "center" }}>
            <CircularProgress sx={{ color: "grey.500" }} />
          </Box>
        )}
        {/* Full-screen toggle: a floating control that's always visible over the canvas. */}
        <Box sx={{ position: "absolute", top: 8, right: 8, zIndex: 2 }}>
          {fullscreen ? (
            <Button
              size="small" variant="contained" startIcon={<FullscreenExitIcon />}
              onClick={() => setFullscreen(false)}
              sx={{ bgcolor: "grey.100", color: "#000", "&:hover": { bgcolor: "grey.300" } }}
            >
              Exit full screen (Esc)
            </Button>
          ) : (
            <Tooltip title="Full screen">
              <IconButton
                size="small" onClick={() => setFullscreen(true)}
                sx={{ bgcolor: "rgba(0,0,0,0.55)", color: "#fff", "&:hover": { bgcolor: "rgba(0,0,0,0.75)" } }}
              >
                <FullscreenIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
        </Box>
      </Box>
      <Stack direction="row" spacing={2} alignItems="center" sx={{ mt: 1, ...(fullscreen ? { color: "grey.300" } : {}) }}>
        <IconButton onClick={toggle} disabled={!!error} color="primary">
          {playing ? <PauseIcon /> : <PlayArrowIcon />}
        </IconButton>
        <Typography variant="caption" sx={{ minWidth: 44, color: fullscreen ? "grey.300" : undefined }}>{formatDuration(position)}</Typography>
        <Slider
          size="small" min={0} max={Math.max(duration, 1)} value={Math.min(position, duration)}
          onChange={onSeek} disabled={!!error || duration === 0}
        />
        <Typography variant="caption" sx={{ minWidth: 44, color: fullscreen ? "grey.300" : undefined }}>{formatDuration(duration)}</Typography>
      </Stack>
    </Box>
  );
}

export function RdpRecordingsPanel() {
  const qc = useQueryClient();
  const { data: recordings = [], isLoading } = useQuery({ queryKey: ["rdp-recordings"], queryFn: listRdpRecordings });
  const { data: stats } = useQuery({ queryKey: ["rdp-recording-stats"], queryFn: rdpRecordingStats });
  const [active, setActive] = useState<RDPRecording | null>(null);
  const [search, setSearch] = useState("");
  const canManage = useAuthStore((s) => s.has("System.Configure"));

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["rdp-recordings"] });
    void qc.invalidateQueries({ queryKey: ["rdp-recording-stats"] });
  };
  const delMut = useMutation({ mutationFn: deleteRdpRecording, onSuccess: invalidate });

  // Download the raw Guacamole recording (.guac) for archival / external playback.
  const download = async (r: RDPRecording) => {
    const blob = await downloadRdpRecordingBlob(r.id);
    const d = new Date(r.startedAt);
    const p = (n: number) => String(n).padStart(2, "0");
    const ts = `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
    const safe = (s: string) => (s || "x").replace(/[^a-zA-Z0-9_.-]/g, "_");
    const name = `rdp-${safe(r.rdpUser)}-${safe(r.hostname)}-${ts}.guac`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const q = search.trim().toLowerCase();
  const filtered = recordings.filter((r) =>
    !q ||
    r.hostname.toLowerCase().includes(q) ||
    r.fleetUser.toLowerCase().includes(q) ||
    r.rdpUser.toLowerCase().includes(q),
  );

  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }}>
        <TextField
          size="small" label="Search host or user" value={search}
          onChange={(e) => setSearch(e.target.value)} sx={{ minWidth: 260 }}
        />
        <Tooltip title="A self-contained HTML player for downloaded .guac recordings — works offline in any browser, on any OS. Downloads never leave your machine.">
          <Button
            size="small" variant="outlined" startIcon={<DownloadIcon />}
            component="a" href="/guac-player.html" download="fleet-guac-player.html"
          >
            Offline player
          </Button>
        </Tooltip>
        <Box sx={{ flexGrow: 1 }} />
        {stats && (
          <Typography variant="body2" color="text.secondary">
            {stats.count} recordings · {formatBytes(stats.bytes)}
          </Typography>
        )}
      </Stack>

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Started</TableCell>
              <TableCell>Fleet user</TableCell>
              <TableCell>Windows user</TableCell>
              <TableCell>Host</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Duration</TableCell>
              <TableCell>Size</TableCell>
              <TableCell align="right">Replay</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filtered.map((r) => {
              const replayable = r.status === "ended";
              return (
                <TableRow
                  key={r.id} hover
                  sx={{ cursor: replayable ? "pointer" : "default" }}
                  onClick={() => replayable && setActive(r)}
                >
                  <TableCell>{formatDateTime(r.startedAt)}</TableCell>
                  <TableCell>{r.fleetUser}</TableCell>
                  <TableCell>{r.rdpUser}</TableCell>
                  <TableCell>{r.hostname}</TableCell>
                  <TableCell><Chip label={r.status} size="small" color={r.status === "active" ? "info" : "default"} /></TableCell>
                  <TableCell>{r.durationMs ? formatDuration(r.durationMs) : "—"}</TableCell>
                  <TableCell>{r.sizeBytes ? formatBytes(r.sizeBytes) : "—"}</TableCell>
                  <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                    {replayable ? (
                      <>
                        <Tooltip title="Watch (replay)">
                          <IconButton size="small" onClick={() => setActive(r)}>
                            <PlayArrowIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Download recording (.guac)">
                          <IconButton size="small" onClick={() => void download(r)}>
                            <DownloadIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        {canManage && (
                          <Tooltip title="Delete recording">
                            <IconButton
                              size="small" color="error"
                              onClick={() => { if (window.confirm("Delete this recording?")) delMut.mutate(r.id); }}
                            >
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                      </>
                    ) : (
                      <Typography variant="caption" color="text.secondary">in progress</Typography>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
            {!isLoading && filtered.length === 0 && (
              <TableRow><TableCell colSpan={8}>
                <Typography color="text.secondary">
                  {recordings.length === 0 ? "No RDP recordings yet." : "No recordings match the search."}
                </Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Drawer anchor="right" open={active !== null} onClose={() => setActive(null)}
        PaperProps={{ sx: { width: { xs: "100%", md: 900 }, p: 2 } }}>
        {active && (
          <Box>
            <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
              <Typography variant="h6" sx={{ flexGrow: 1 }}>
                {active.rdpUser}@{active.hostname}
              </Typography>
              <IconButton onClick={() => setActive(null)}><CloseIcon /></IconButton>
            </Stack>
            <Stack direction="row" spacing={2} sx={{ mb: 1 }}>
              <Typography variant="caption" color="text.secondary">
                By {active.fleetUser} · started {formatDateTime(active.startedAt)}
              </Typography>
              {active.endedAt && (
                <Typography variant="caption" color="text.secondary">
                  Ended {formatDateTime(active.endedAt)}
                </Typography>
              )}
            </Stack>
            <Divider sx={{ mb: 2 }} />
            <RdpPlayer id={active.id} />
          </Box>
        )}
      </Drawer>
    </Box>
  );
}
