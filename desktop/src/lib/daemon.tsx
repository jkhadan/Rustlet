// The app's connection to rustletd: one `daemon_watch` stream, opened when
// the app starts (src-tauri/src/streams.rs, `watch_daemon`). It says
// whether the daemon is there, and carries its events, which keep every
// cached query current (`applyEvents`) and feed the activity list.

import { useQueryClient } from "@tanstack/react-query";
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";

import type { Event, Version } from "@/bindings";

import { applyEvents } from "./events";
import { api, type CommandError, type DaemonMessage } from "./ipc";

/** How many events the activity list keeps. */
const RECENT = 200;

export type Connection =
  | { state: "connecting" }
  | { state: "connected"; socket: string; version: Version }
  | { state: "disconnected"; socket: string; error: CommandError };

export interface Daemon {
  connection: Connection;
  /** How many times the app has connected: a view whose stream ended with
   * the connection (a daemon restart) opens it again when this changes. */
  generation: number;
  /** The latest events, newest first. */
  events: Event[];
}

const DaemonContext = createContext<Daemon>({ connection: { state: "connecting" }, generation: 0, events: [] });

export function DaemonProvider({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const [connection, setConnection] = useState<Connection>({ state: "connecting" });
  const [generation, setGeneration] = useState(0);
  const [events, setEvents] = useState<Event[]>([]);

  useEffect(() => {
    let closed = false;
    let handle: { cancel(): void } | undefined;
    const onMessage = (m: DaemonMessage) => {
      if (closed) return;
      switch (m.type) {
        case "connected":
          setConnection({ state: "connected", socket: m.socket, version: m.version });
          setGeneration((g) => g + 1);
          // Anything may have changed while nobody listened.
          void client.invalidateQueries();
          break;
        case "disconnected":
          setConnection({ state: "disconnected", socket: m.socket, error: m.error });
          break;
        case "events":
          applyEvents(client, m.events);
          setEvents((old) => [...m.events.slice().reverse(), ...old].slice(0, RECENT));
          break;
      }
    };
    api.daemon
      .watch(onMessage)
      .then((h) => {
        // React's development mode mounts twice: the first watch may
        // only start after its effect was cleaned up.
        if (closed) h.cancel();
        else handle = h;
      })
      .catch((e: unknown) => {
        if (!closed) {
          setConnection({ state: "disconnected", socket: "", error: { kind: "failed", message: String(e) } });
        }
      });
    return () => {
      closed = true;
      handle?.cancel();
    };
  }, [client]);

  const value = useMemo(() => ({ connection, generation, events }), [connection, generation, events]);
  return <DaemonContext.Provider value={value}>{children}</DaemonContext.Provider>;
}

export function useDaemon(): Daemon {
  return useContext(DaemonContext);
}

/** A clock for "5 minutes ago" texts, ticking every `ms`. */
export function useNow(ms = 15_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [ms]);
  return now;
}
