import { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { Box, CircularProgress, Typography } from "@mui/material";
import Guacamole from "guacamole-common-js";
import { getAccessToken } from "../api/client";

// RdpPage renders a live RDP (Windows) desktop in a Guacamole canvas, brokered by
// the backend + guacd. Opened in its own tab (like the terminal). The credential
// is injected server-side; it never reaches the browser.
export function RdpPage() {
  const { hostId } = useParams<{ hostId: string }>();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [status, setStatus] = useState<"connecting" | "connected" | "disconnected">("connecting");
  const [error, setError] = useState<string | null>(null);

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

    const query = new URLSearchParams({ token, width: String(width), height: String(height) }).toString();
    client.connect(query);

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
    </Box>
  );
}
