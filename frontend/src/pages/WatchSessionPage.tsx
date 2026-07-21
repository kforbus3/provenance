import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Box, Button, Chip, Stack, Typography } from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import VisibilityIcon from "@mui/icons-material/Visibility";
import { Terminal } from "@xterm/xterm";
import { useAuthStore } from "../store/auth";

type Status = "connecting" | "watching" | "ended" | "closed" | "error";

// Read-only live view of an active SSH session for four-eyes oversight. Renders
// the operator's terminal output in real time at their dimensions; the watcher
// sends no input. Backed by the /sessions/{id}/watch WebSocket.
export function WatchSessionPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const accessToken = useAuthStore((s) => s.accessToken);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [status, setStatus] = useState<Status>("connecting");

  useEffect(() => {
    if (!containerRef.current || !id || !accessToken) return;

    const term = new Terminal({
      fontFamily: "monospace",
      fontSize: 13,
      scrollback: 100000,
      disableStdin: true, // read-only: no input reaches the session
      cursorBlink: false,
      theme: { background: "#0d1117" },
    });
    term.open(containerRef.current);

    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    // Token via subprotocol (see events.ts) so it stays out of the URL / proxy logs.
    const url = `${proto}://${window.location.host}/api/v1/sessions/${id}/watch`;
    const ws = new WebSocket(url, ["fleet-bearer", accessToken]);
    ws.binaryType = "arraybuffer";

    ws.onopen = () => setStatus("watching");
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === "resize" && msg.cols && msg.rows) {
            term.resize(msg.cols, msg.rows); // match the operator's dimensions exactly
          } else if (msg.type === "ended") {
            setStatus("ended");
            term.write(`\r\n\x1b[33m— ${msg.data} —\x1b[0m\r\n`);
          } else if (msg.type === "info") {
            term.write(`\x1b[90m${msg.data}\x1b[0m\r\n`);
          }
        } catch {
          /* ignore malformed control frame */
        }
      } else {
        term.write(new Uint8Array(ev.data));
      }
    };
    ws.onclose = () => setStatus((s) => (s === "ended" ? s : "closed"));
    ws.onerror = () => setStatus("error");

    return () => {
      ws.close();
      term.dispose();
    };
  }, [id, accessToken]);

  const color =
    status === "watching" ? "success" : status === "connecting" ? "warning" : "default";

  return (
    <Box sx={{ height: "100vh", display: "flex", flexDirection: "column", bgcolor: "#0d1117" }}>
      <Stack
        direction="row" spacing={2} alignItems="center"
        sx={{ px: 2, py: 1, bgcolor: "#161b22", borderBottom: "1px solid #30363d" }}
      >
        <Button
          size="small" startIcon={<ArrowBackIcon />} onClick={() => navigate("/sessions")}
          sx={{ color: "#c9d1d9", borderColor: "#30363d" }} variant="outlined"
        >
          Sessions
        </Button>
        <VisibilityIcon sx={{ color: "#8b949e" }} fontSize="small" />
        <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#e6edf3" }}>
          Watching session (read-only)
        </Typography>
        <Chip size="small" label={status} color={color} />
        <Box sx={{ flexGrow: 1 }} />
        <Typography variant="caption" sx={{ color: "#8b949e" }}>
          Live oversight · your view is not sending input
        </Typography>
      </Stack>
      <Box ref={containerRef} sx={{ flexGrow: 1, p: 1, overflow: "auto" }} />
    </Box>
  );
}
