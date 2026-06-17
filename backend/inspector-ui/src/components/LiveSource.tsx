import { useEffect, useRef, useState } from "react";
import { type InspectorEvent } from "../types/events";

export type LiveStatus = "idle" | "connecting" | "open" | "closed" | "error";

interface Props {
  onEvent: (ev: InspectorEvent) => void;
  onClear: () => void;
}

function defaultWsUrl(): string {
  if (typeof window === "undefined") return "ws://localhost:8080/_inspect/ws";
  const { protocol, hostname, port } = window.location;
  const wsProto = protocol === "https:" ? "wss:" : "ws:";
  // Vite dev server runs at :5174 (see vite.config.ts); backend WS lives on
  // :8080 by default. When loaded via the dev server, point WS at the backend.
  const backendPort = port === "5174" || port === "5173" ? "8080" : port;
  const hostPart = backendPort ? `${hostname}:${backendPort}` : hostname;
  return `${wsProto}//${hostPart}/_inspect/ws`;
}

export function LiveSource({ onEvent, onClear }: Props) {
  const [url, setUrl] = useState(defaultWsUrl());
  const [status, setStatus] = useState<LiveStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const onEventRef = useRef(onEvent);

  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  // Close socket on unmount so we don't leak connections during HMR.
  useEffect(() => {
    return () => {
      wsRef.current?.close();
    };
  }, []);

  const connect = () => {
    if (wsRef.current) wsRef.current.close();
    onClear();
    setError(null);
    setStatus("connecting");
    let ws: WebSocket;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      setStatus("error");
      setError(String(e));
      return;
    }
    wsRef.current = ws;
    ws.onopen = () => setStatus("open");
    ws.onclose = () => setStatus((s) => (s === "error" ? s : "closed"));
    ws.onerror = () => {
      setStatus("error");
      setError("WebSocket error (see browser console)");
    };
    ws.onmessage = (ev) => {
      try {
        const parsed = JSON.parse(ev.data as string) as InspectorEvent;
        onEventRef.current(parsed);
      } catch (e) {
        console.warn("inspector live: bad event", ev.data, e);
      }
    };
  };

  const disconnect = () => {
    wsRef.current?.close();
    wsRef.current = null;
    setStatus("idle");
  };

  return (
    <div className="live-source">
      <input
        type="text"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        disabled={status === "open" || status === "connecting"}
        style={{ minWidth: "22rem" }}
      />
      {status === "open" || status === "connecting" ? (
        <button onClick={disconnect}>Disconnect</button>
      ) : (
        <button onClick={connect}>Connect</button>
      )}
      <span className={`live-status live-status-${status}`}>{status}</span>
      {error && <span className="live-error">{error}</span>}
    </div>
  );
}
