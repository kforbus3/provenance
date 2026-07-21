import { useEffect, useRef } from "react";
import { useAuthStore } from "../store/auth";

export interface FleetEvent {
  type: string;
  data: unknown;
}

// useFleetEvents subscribes to the backend live-events WebSocket and invokes the
// handler for each event. Reconnects with backoff while authenticated.
export function useFleetEvents(onEvent: (e: FleetEvent) => void) {
  const accessToken = useAuthStore((s) => s.accessToken);
  const handlerRef = useRef(onEvent);
  handlerRef.current = onEvent;

  useEffect(() => {
    if (!accessToken) return;
    let closed = false;
    let ws: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      if (closed) return;
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      // Carry the access token in the Sec-WebSocket-Protocol subprotocol rather than
      // the URL query, so it never lands in reverse-proxy access logs. The server
      // reads the value after the "fleet-bearer" marker and echoes the marker back.
      ws = new WebSocket(
        `${proto}://${window.location.host}/api/v1/events/ws`,
        ["fleet-bearer", accessToken],
      );
      ws.onmessage = (ev) => {
        try {
          handlerRef.current(JSON.parse(ev.data) as FleetEvent);
        } catch {
          /* ignore malformed frames */
        }
      };
      ws.onclose = () => {
        if (!closed) retry = setTimeout(connect, 3000);
      };
    };
    connect();

    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      ws?.close();
    };
  }, [accessToken]);
}
