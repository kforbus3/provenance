import { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { Box, CircularProgress, Fab, Tooltip, Typography } from "@mui/material";
import FolderOpenIcon from "@mui/icons-material/FolderOpen";
import Guacamole from "guacamole-common-js";
import { getAccessToken } from "../api/client";
import { RdpFilesDrawer } from "../components/RdpFilesDrawer";

// RdpPage renders a live RDP (Windows) desktop in a Guacamole canvas, brokered by
// the backend + guacd. Opened in its own tab (like the terminal). The credential
// is injected server-side; it never reaches the browser.
export function RdpPage() {
  const { hostId } = useParams<{ hostId: string }>();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [status, setStatus] = useState<"connecting" | "connected" | "disconnected">("connecting");
  const [error, setError] = useState<string | null>(null);
  const [fs, setFs] = useState<Guacamole.Object | null>(null);
  const [filesOpen, setFilesOpen] = useState(false);

  useEffect(() => {
    if (!hostId || !containerRef.current) return;
    const token = getAccessToken();
    if (!token) {
      setError("Not authenticated.");
      setStatus("disconnected");
      return;
    }

    const wsProto = window.location.protocol === "https:" ? "wss" : "ws";
    const tunnelUrl = `${wsProto}://${window.location.host}/api/v1/rdp/${hostId}`;
    const width = Math.max(640, Math.floor(window.innerWidth));
    const height = Math.max(480, Math.floor(window.innerHeight));

    const tunnel = new Guacamole.WebSocketTunnel(tunnelUrl);
    const client = new Guacamole.Client(tunnel);

    const display = client.getDisplay().getElement();
    containerRef.current.innerHTML = "";
    containerRef.current.appendChild(display);

    client.onstatechange = (state: number) => {
      // 3 = CONNECTED, 5 = DISCONNECTED (Guacamole.Client.State)
      if (state === 3) setStatus("connected");
      if (state === 5) setStatus("disconnected");
    };
    client.onerror = (e: { message?: string }) => {
      setError(e?.message || "The desktop connection failed.");
      setStatus("disconnected");
    };

    // Drive redirection: guacd advertises a filesystem when the host enables the
    // drive. Capture it so the Files drawer can browse/transfer.
    client.onfilesystem = (object: Guacamole.Object) => setFs(object);

    // Clipboard: remote → local. Fires only if the host allows copy (guacd gates it
    // with disable-copy). Text is written to the browser clipboard best-effort.
    client.onclipboard = (stream: Guacamole.InputStream, mimetype: string) => {
      if (!mimetype.startsWith("text/")) return;
      const reader = new Guacamole.StringReader(stream);
      let text = "";
      reader.ontext = (t: string) => { text += t; };
      reader.onend = () => { void navigator.clipboard?.writeText(text).catch(() => {}); };
    };

    const query = new URLSearchParams({ token, width: String(width), height: String(height) }).toString();
    client.connect(query);

    // Clipboard: local → remote. When the tab regains focus, push the browser
    // clipboard to the remote so Ctrl+V inside the desktop pastes it. Only takes
    // effect if the host allows paste (guacd gates it with disable-paste).
    const pushLocalClipboard = () => {
      navigator.clipboard?.readText().then((text) => {
        if (!text) return;
        const stream = client.createClipboardStream("text/plain");
        const writer = new Guacamole.StringWriter(stream);
        writer.sendText(text);
        writer.sendEnd();
      }).catch(() => {});
    };
    window.addEventListener("focus", pushLocalClipboard);

    // Dynamic resize: keep the remote desktop sized to the browser window.
    let resizeTimer: ReturnType<typeof setTimeout> | undefined;
    const onResize = () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        client.sendSize(Math.floor(window.innerWidth), Math.floor(window.innerHeight));
      }, 300);
    };
    window.addEventListener("resize", onResize);

    // Mouse and keyboard wiring.
    const mouse = new Guacamole.Mouse(display);
    const mouseTypes = ["mousedown", "mouseup", "mousemove"];
    const onMouse = (e: Guacamole.Event) => client.sendMouseState((e as Guacamole.Mouse.Event).state, true);
    mouse.onEach(mouseTypes, onMouse);

    const keyboard = new Guacamole.Keyboard(document);
    keyboard.onkeydown = (keysym: number) => client.sendKeyEvent(1, keysym);
    keyboard.onkeyup = (keysym: number) => client.sendKeyEvent(0, keysym);

    return () => {
      keyboard.onkeydown = null;
      keyboard.onkeyup = null;
      mouse.offEach(mouseTypes, onMouse);
      window.removeEventListener("focus", pushLocalClipboard);
      window.removeEventListener("resize", onResize);
      clearTimeout(resizeTimer);
      setFs(null);
      try { client.disconnect(); } catch { /* already gone */ }
    };
  }, [hostId]);

  return (
    <Box sx={{ position: "fixed", inset: 0, bgcolor: "black", overflow: "hidden" }}>
      <Box ref={containerRef} sx={{ width: "100%", height: "100%", "& canvas": { display: "block" } }} />
      {status !== "connected" && (
        <Box sx={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column",
          alignItems: "center", justifyContent: "center", color: "grey.300", gap: 2 }}>
          {status === "connecting" && !error && <><CircularProgress color="inherit" /><Typography>Connecting to the desktop…</Typography></>}
          {error && <Typography color="error">{error}</Typography>}
          {status === "disconnected" && !error && <Typography>Desktop session ended. You can close this tab.</Typography>}
        </Box>
      )}
      {fs && status === "connected" && (
        <Tooltip title="Files (drive)">
          <Fab size="small" color="default" onClick={() => setFilesOpen(true)}
            sx={{ position: "absolute", bottom: 16, right: 16, opacity: 0.85 }}>
            <FolderOpenIcon />
          </Fab>
        </Tooltip>
      )}
      {fs && <RdpFilesDrawer fs={fs} open={filesOpen} onClose={() => setFilesOpen(false)} />}
    </Box>
  );
}
