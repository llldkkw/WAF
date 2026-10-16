import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, type WafEvent } from "./api";

export interface Tick {
  ts: number;
  requests: number;
  blocked: number;
}

interface LiveState {
  connected: boolean;
  ticks: Tick[]; // last 120 seconds
  events: WafEvent[]; // most recent first
  subscribe: (fn: (e: WafEvent) => void) => () => void;
}

const LiveCtx = createContext<LiveState>({ connected: false, ticks: [], events: [], subscribe: () => () => {} });

/** Keeps one websocket open while logged in and fans messages out. */
export function LiveProvider({ children }: { children: ReactNode }) {
  const [connected, setConnected] = useState(false);
  const [ticks, setTicks] = useState<Tick[]>([]);
  const [events, setEvents] = useState<WafEvent[]>([]);
  const subs = useRef(new Set<(e: WafEvent) => void>());

  useEffect(() => {
    api.events({ limit: 30 }).then((r) => setEvents((cur) => (cur.length ? cur : r.events))).catch(() => {});
  }, []);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout>;
    let stopped = false;
    let backoff = 1000;

    const connect = () => {
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      ws = new WebSocket(`${proto}//${location.host}/api/ws`);
      ws.onopen = () => {
        setConnected(true);
        backoff = 1000;
      };
      ws.onclose = () => {
        setConnected(false);
        if (!stopped) {
          retry = setTimeout(connect, backoff);
          backoff = Math.min(backoff * 2, 30000);
        }
      };
      ws.onmessage = (m) => {
        const msg = JSON.parse(m.data) as { type: string; data: unknown };
        if (msg.type === "tick") {
          setTicks((t) => [...t.slice(-119), msg.data as Tick]);
        } else if (msg.type === "event") {
          const e = msg.data as WafEvent;
          setEvents((list) => [e, ...list].slice(0, 100));
          subs.current.forEach((f) => f(e));
        }
      };
    };
    connect();
    return () => {
      stopped = true;
      clearTimeout(retry);
      ws?.close();
    };
  }, []);

  const subscribe = (fn: (e: WafEvent) => void) => {
    subs.current.add(fn);
    return () => {
      subs.current.delete(fn);
    };
  };

  return <LiveCtx.Provider value={{ connected, ticks, events, subscribe }}>{children}</LiveCtx.Provider>;
}

export function useLive() {
  return useContext(LiveCtx);
}
