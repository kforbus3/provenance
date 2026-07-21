import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Box, Button, Chip, Stack, Typography } from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { useQuery } from "@tanstack/react-query";
import { useAuthStore } from "../store/auth";
import { getHost } from "../api/hosts";
import { useDocumentTitle } from "../api/branding";

type Status = "connecting" | "connected" | "closed" | "error";

// Live browser SSH terminal. Connects to the backend WebSocket gateway, which is
// the sole SSH client. Terminal output arrives as binary frames; keystrokes are
// sent as binary; resize is sent as a JSON control message. The browser never
// holds SSH keys or certificates.
export function TerminalPage() {
  const { hostId } = useParams<{ hostId: string }>();
  const navigate = useNavigate();
  const accessToken = useAuthStore((s) => s.accessToken);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [status, setStatus] = useState<Status>("connecting");

  const { data: host } = useQuery({
    queryKey: ["host", hostId],
    queryFn: () => getHost(hostId!),
    enabled: !!hostId,
  });
  const hostname = host?.hostname ?? "";

  // Reflect the host in the browser tab title.
  useDocumentTitle(hostname || undefined);

  useEffect(() => {
    if (!containerRef.current || !hostId || !accessToken) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: "monospace",
      fontSize: 13,
      scrollback: 100000,
      theme: { background: "#0d1117" },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(containerRef.current);
    fit.fit();

    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    // Token via subprotocol (see events.ts) so it stays out of the URL / proxy logs.
    const url = `${proto}://${window.location.host}/api/v1/terminal/${hostId}`;
    const ws = new WebSocket(url, ["fleet-bearer", accessToken]);
    ws.binaryType = "arraybuffer";

    const sendResize = () => {
      fit.fit();
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    };

    ws.onopen = () => {
      setStatus("connected");
      sendResize();
    };
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === "error") term.write(`\r\n\x1b[31m${msg.data}\x1b[0m\r\n`);
        } catch {
          term.write(ev.data);
        }
      } else {
        term.write(new Uint8Array(ev.data));
      }
    };
    ws.onclose = () => setStatus("closed");
    ws.onerror = () => setStatus("error");

    const dataSub = term.onData((d) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(d));
    });
    window.addEventListener("resize", sendResize);

    return () => {
      window.removeEventListener("resize", sendResize);
      dataSub.dispose();
      ws.close();
      term.dispose();
    };
  }, [hostId, accessToken]);

  const color =
    status === "connected" ? "success" : status === "connecting" ? "warning" : "error";

  return (
    <Box sx={{ height: "100vh", display: "flex", flexDirection: "column", bgcolor: "#0d1117" }}>
      <Stack
        direction="row" spacing={2} alignItems="center"
        sx={{ px: 2, py: 1, bgcolor: "#161b22", borderBottom: "1px solid #30363d" }}
      >
        <Button
          size="small" startIcon={<ArrowBackIcon />} onClick={() => navigate("/hosts")}
          sx={{ color: "#c9d1d9", borderColor: "#30363d" }} variant="outlined"
        >
          Hosts
        </Button>
        <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#e6edf3" }}>
          {hostname || "Terminal"}
        </Typography>
        <Chip size="small" label={status} color={color} />
        <Box sx={{ flexGrow: 1 }} />
        <Typography variant="caption" sx={{ color: "#8b949e" }}>
          SSH via jump host · per-user certificate
        </Typography>
      </Stack>
      <Box ref={containerRef} sx={{ flexGrow: 1, p: 1, overflow: "hidden" }} />
    </Box>
  );
}
