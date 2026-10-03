// The frontend's side of the Rust commands (desktop/src-tauri/src/commands.rs).
//
// `invoke(name, args)` sends `args` as JSON to the command of that name and
// resolves with its result; a command that fails rejects with a
// `CommandError` (`{kind, message}`, src-tauri/src/error.rs), which `call`
// turns into a `CommandFailed` so that it is a real `Error` with a stack.
//
// The API's own types come from Rust (src/bindings, `cargo xtask gen-ts`).
// The few defined by the desktop crate itself (errors and the shapes of its
// channel messages) are written out below; their Rust tests pin the same
// JSON.

import { Channel, invoke } from "@tauri-apps/api/core";

import type {
  ContainerConfig,
  ContainerInspect,
  ContainerSummary,
  CreateResponse,
  ErrorKind,
  Event,
  ImageDeleteResponse,
  ImageInspect,
  ImageSummary,
  Info,
  Isolation,
  LogEntry,
  LogsQuery,
  MountSpec,
  Network,
  NetworkConnect,
  NetworkCreate,
  NetworkCreateResponse,
  NetworkDisconnect,
  PortMapping,
  PruneResponse,
  PullEvent,
  PullPolicy,
  StatsSample,
  Version,
  Volume,
  VolumeCreate,
} from "@/bindings";

/** `unreachable`: nothing listens on the socket; `denied`: the socket isn't
 * this user's; `failed`: anything else; or the daemon's own kind
 * (`invalid` also comes from `parse_run_options`). */
export type CommandErrorKind = "unreachable" | "denied" | "failed" | ErrorKind;

/** What a failed command rejects with. */
export interface CommandError {
  kind: CommandErrorKind;
  message: string;
}

/** A failed command, as an `Error`. */
export class CommandFailed extends Error {
  readonly kind: CommandErrorKind;
  constructor(e: CommandError) {
    super(e.message);
    this.name = "CommandFailed";
    this.kind = e.kind;
  }
}

/** The daemon can't be used at all (stopped, or not ours to use). */
export function isConnectionError(e: unknown): boolean {
  return e instanceof CommandFailed && (e.kind === "unreachable" || e.kind === "denied");
}

function asCommandError(e: unknown): CommandError {
  if (typeof e === "object" && e !== null && "kind" in e && "message" in e) {
    return e as CommandError;
  }
  return { kind: "failed", message: typeof e === "string" ? e : String(e) };
}

/** `invoke`, rejecting with a `CommandFailed`. */
export async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (e) {
    throw new CommandFailed(asCommandError(e));
  }
}

/** A message of a stream (src-tauri/src/streams.rs, `StreamMessage`). */
export type StreamMessage<T> =
  | { type: "items"; items: T[] }
  | { type: "end" }
  | { type: "error"; error: CommandError };

/** A message of the daemon watch (`DaemonMessage`). */
export type DaemonMessage =
  | { type: "connected"; socket: string; version: Version }
  | { type: "disconnected"; socket: string; error: CommandError }
  | { type: "events"; events: Event[] };

/** `-p` and `-v` values, parsed as `rustlet run` parses them
 * (`RunOptions`). */
export interface RunOptions {
  ports: PortMapping[];
  mounts: MountSpec[];
}

/** The JSON messages of a terminal's output channel (`TerminalMessage`);
 * its data arrives as `ArrayBuffer`s. */
export type TerminalMessage = { type: "exit"; code: number } | { type: "error"; error: CommandError };

/** A running stream; `cancel` stops it (idempotent). */
export interface StreamHandle {
  id: number;
  cancel(): void;
}

/** Starts a streaming command: `onMessage` gets each message, in order. */
export async function openStream<T>(
  command: string,
  args: Record<string, unknown>,
  onMessage: (message: StreamMessage<T>) => void,
): Promise<StreamHandle> {
  const channel = new Channel<StreamMessage<T>>(onMessage);
  const id = await call<number>(command, { ...args, channel });
  return streamHandle(id);
}

function streamHandle(id: number): StreamHandle {
  let cancelled = false;
  return {
    id,
    cancel() {
      if (cancelled) return;
      cancelled = true;
      call<boolean>("stream_cancel", { stream: id }).catch(() => {});
    },
  };
}

/** Every command, typed. */
export const api = {
  daemon: {
    socket: () => call<string>("daemon_socket"),
    version: () => call<Version>("daemon_version"),
    info: () => call<Info>("daemon_info"),
    start: () => call<void>("daemon_start"),
    watch: async (onMessage: (m: DaemonMessage) => void) => {
      const channel = new Channel<DaemonMessage>(onMessage);
      return streamHandle(await call<number>("daemon_watch", { channel }));
    },
  },
  containers: {
    list: (all: boolean) => call<ContainerSummary[]>("container_list", { all }),
    inspect: (id: string) => call<ContainerInspect>("container_inspect", { id }),
    create: (config: Partial<ContainerConfig> & { image: string }) =>
      call<CreateResponse>("container_create", { config }),
    /** Rejects with `invalid` and the CLI's message for a value the CLI
     * would refuse. */
    parseRunOptions: (ports: string[], volumes: string[]) => call<RunOptions>("parse_run_options", { ports, volumes }),
    start: (id: string) => call<void>("container_start", { id }),
    stop: (id: string, timeout?: number) => call<void>("container_stop", { id, timeout }),
    restart: (id: string, timeout?: number) => call<void>("container_restart", { id, timeout }),
    kill: (id: string, signal?: string) => call<void>("container_kill", { id, signal }),
    pause: (id: string) => call<void>("container_pause", { id }),
    unpause: (id: string) => call<void>("container_unpause", { id }),
    remove: (id: string, opts: { force?: boolean; volumes?: boolean } = {}) =>
      call<void>("container_remove", { id, force: opts.force ?? false, volumes: opts.volumes ?? false }),
    isolation: (id: string) => call<Isolation>("container_isolation", { id }),
    logs: (id: string, query: Partial<LogsQuery>, onMessage: (m: StreamMessage<LogEntry>) => void) =>
      openStream<LogEntry>("container_logs", { id, query }, onMessage),
    stats: (id: string, onMessage: (m: StreamMessage<StatsSample>) => void) =>
      openStream<StatsSample>("container_stats", { id }, onMessage),
  },
  images: {
    list: () => call<ImageSummary[]>("image_list"),
    inspect: (name: string) => call<ImageInspect>("image_inspect", { name }),
    remove: (name: string, force = false) => call<ImageDeleteResponse>("image_remove", { name, force }),
    pull: (reference: string, policy: PullPolicy, onMessage: (m: StreamMessage<PullEvent>) => void) =>
      openStream<PullEvent>("image_pull", { reference, policy }, onMessage),
  },
  networks: {
    list: () => call<Network[]>("network_list"),
    inspect: (id: string) => call<Network>("network_inspect", { id }),
    create: (config: Partial<NetworkCreate> & { name: string }) =>
      call<NetworkCreateResponse>("network_create", { config }),
    remove: (id: string) => call<void>("network_remove", { id }),
    connect: (id: string, body: Partial<NetworkConnect> & { container: string }) =>
      call<void>("network_connect", { id, body }),
    disconnect: (id: string, body: Partial<NetworkDisconnect> & { container: string }) =>
      call<void>("network_disconnect", { id, body }),
    prune: () => call<PruneResponse>("network_prune"),
  },
  volumes: {
    list: () => call<Volume[]>("volume_list"),
    inspect: (name: string) => call<Volume>("volume_inspect", { name }),
    create: (config: Partial<VolumeCreate>) => call<Volume>("volume_create", { config }),
    remove: (name: string, force = false) => call<void>("volume_remove", { name, force }),
    prune: (all = false) => call<PruneResponse>("volume_prune", { all }),
  },
  terminal: {
    open: (
      args: { container: string; cmd: string[]; user?: string; rows: number; cols: number },
      onOutput: (message: ArrayBuffer | TerminalMessage) => void,
    ) => {
      const output = new Channel<ArrayBuffer | TerminalMessage>(onOutput);
      return call<number>("terminal_open", { ...args, user: args.user ?? null, output });
    },
    // A `Vec<u8>` comes from JSON as an array of numbers (a typed array
    // would become an object).
    input: (session: number, data: Uint8Array) => call<void>("terminal_input", { session, data: Array.from(data) }),
    resize: (session: number, rows: number, cols: number) => call<void>("terminal_resize", { session, rows, cols }),
    close: (session: number) => call<void>("terminal_close", { session }),
  },
} as const;
