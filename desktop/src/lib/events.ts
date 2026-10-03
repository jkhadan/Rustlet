// How the app stays in step with the daemon, whoever changes it (this app,
// the `rustlet` CLI, a restart policy): every view reads its data through
// TanStack Query, and every daemon event marks the cached data it can
// have changed as stale. Queries that are on screen refetch at once, the
// rest the next time they are shown. Nothing polls.
//
// The rules are coarse on purpose: refetching a list costs a few
// milliseconds over a Unix socket, and a missed refetch shows something
// false. An event names its container by full id, while a detail page may
// have been opened by name or short id, so detail queries are invalidated
// by their prefix (`["container"]` matches every `["container", x]`).

import type { QueryClient, QueryKey } from "@tanstack/react-query";

import type { Event } from "@/bindings";

/** The query keys of the app, in one place. */
export const keys = {
  containers: (all: boolean) => ["containers", { all }] as const,
  container: (id: string) => ["container", id] as const,
  isolation: (id: string) => ["isolation", id] as const,
  images: () => ["images"] as const,
  image: (name: string) => ["image", name] as const,
  networks: () => ["networks"] as const,
  network: (id: string) => ["network", id] as const,
  volumes: () => ["volumes"] as const,
  volume: (name: string) => ["volume", name] as const,
  info: () => ["info"] as const,
};

// Prefixes, for invalidation.
const CONTAINERS = ["containers"];
const CONTAINER = ["container"];
const ISOLATION = ["isolation"];
const IMAGES = ["images"];
const IMAGE = ["image"];
const NETWORKS = ["networks"];
const NETWORK = ["network"];
const VOLUMES = ["volumes"];
const VOLUME = ["volume"];
const INFO = ["info"];

/** Container actions that start or end a run: its addresses, ports and
 * namespaces come and go with it. */
const RUN_CHANGES = new Set(["start", "die", "restart", "kill", "stop", "oom", "pause", "unpause"]);

/** The cached data `event` can have made stale. */
export function invalidationsFor(event: Event): QueryKey[] {
  switch (event.kind) {
    case "container": {
      if (event.action.startsWith("exec_")) {
        // No view lists execs.
        return [];
      }
      const out: QueryKey[] = [CONTAINERS, CONTAINER, INFO];
      if (RUN_CHANGES.has(event.action)) {
        // Endpoints (addresses) of networks, and the namespaces the
        // isolation inspector reads.
        out.push(NETWORKS, NETWORK, ISOLATION);
      }
      if (event.action === "create" || event.action === "destroy") {
        // What uses an image, a volume, a network.
        out.push(IMAGES, IMAGE, VOLUMES, VOLUME, NETWORKS, NETWORK, ISOLATION);
      }
      return out;
    }
    case "image":
      return [IMAGES, IMAGE, INFO];
    case "network":
      if (event.action === "connect" || event.action === "disconnect") {
        return [NETWORKS, NETWORK, CONTAINERS, CONTAINER, ISOLATION];
      }
      return [NETWORKS, NETWORK, INFO];
    case "volume":
      return [VOLUMES, VOLUME, INFO];
    default:
      // A kind this app doesn't know yet (a newer daemon): refetch all.
      return [[]];
  }
}

/** The distinct keys a batch of events makes stale. A batch from a busy
 * daemon (`rm -f` of ten containers) refetches each list once. */
export function invalidationsForAll(events: Event[]): QueryKey[] {
  const seen = new Map<string, QueryKey>();
  for (const event of events) {
    for (const key of invalidationsFor(event)) {
      seen.set(JSON.stringify(key), key);
    }
  }
  return [...seen.values()];
}

/** Marks what `events` changed as stale. */
export function applyEvents(client: QueryClient, events: Event[]): void {
  for (const queryKey of invalidationsForAll(events)) {
    void client.invalidateQueries({ queryKey });
  }
}

/** One line for an event, as the activity feed shows it. `nameOf` gives
 * a container's name from its id where the event has none (network
 * events name the container by id). */
export function describeEvent(e: Event, nameOf: (id: string) => string | undefined = () => undefined): string {
  const name = e.attributes.name ?? e.id.slice(0, 12);
  switch (e.kind) {
    case "container":
      switch (e.action) {
        case "die":
          return `${name} exited (${e.attributes.exit_code ?? "?"})${e.attributes.oom_killed === "true" ? ", OOM-killed" : ""}`;
        case "oom":
          return `${name}: out of memory`;
        case "kill":
          return `${name} was sent ${e.attributes.signal ?? "a signal"}`;
        case "create":
          return `${name} created from ${e.attributes.image ?? "an image"}`;
        case "destroy":
          return `${name} removed`;
        case "restart":
          return `${name} restarted by its restart policy`;
        case "exec_create":
        case "exec_start":
          return `${name}: exec ${e.action === "exec_start" ? "started" : "created"}`;
        case "exec_die":
          return `${name}: exec exited (${e.attributes.exit_code ?? "?"})`;
        default:
          return `${name} ${pastTense(e.action)}`;
      }
    case "image":
      return `image ${e.id} ${e.action === "pull" ? "pulled" : e.action === "untag" ? "untagged" : "deleted"}`;
    case "network": {
      const net = e.attributes.name ?? e.id.slice(0, 12);
      if (e.action === "connect" || e.action === "disconnect") {
        const id = e.attributes.container;
        const c = (id && nameOf(id)) ?? id?.slice(0, 12) ?? "a container";
        return `${c} ${e.action}ed ${e.action === "connect" ? "to" : "from"} ${net}`;
      }
      return `network ${net} ${e.action === "create" ? "created" : "removed"}`;
    }
    case "volume":
      return `volume ${e.id.length > 24 ? e.id.slice(0, 12) : e.id} ${e.action === "create" ? "created" : "removed"}`;
    default:
      return `${e.kind} ${e.id} ${e.action}`;
  }
}

function pastTense(action: string): string {
  switch (action) {
    case "start":
      return "started";
    case "stop":
      return "stopped";
    case "pause":
      return "paused";
    case "unpause":
      return "resumed";
    default:
      return action;
  }
}
