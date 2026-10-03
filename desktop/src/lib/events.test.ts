import { QueryClient } from "@tanstack/react-query";
import { describe, expect, it } from "vitest";

import type { Event, EventKind } from "@/bindings";

import { applyEvents, describeEvent, invalidationsFor, invalidationsForAll, keys } from "./events";

function event(kind: EventKind, action: string, id = "abc123", attributes: Record<string, string> = {}): Event {
  return { time: "2026-10-02T12:00:00.000000000Z", kind, action, id, attributes };
}

/** A client with one cached entry per key, none stale. */
function clientWith(...queryKeys: (readonly unknown[])[]): QueryClient {
  const client = new QueryClient({ defaultOptions: { queries: { staleTime: Infinity } } });
  for (const k of queryKeys) client.setQueryData(k, "cached");
  return client;
}

function stale(client: QueryClient): string[] {
  return client
    .getQueryCache()
    .getAll()
    .filter((q) => q.isStale())
    .map((q) => JSON.stringify(q.queryKey))
    .sort();
}

describe("event → stale queries", () => {
  it("a container that starts refreshes the lists, its page, networks and the inspector", () => {
    const client = clientWith(
      keys.containers(true),
      keys.containers(false),
      keys.container("web"),
      keys.isolation("web"),
      keys.networks(),
      keys.images(),
      keys.volumes(),
      keys.info(),
    );
    applyEvents(client, [event("container", "start", "abc123", { name: "web" })]);
    expect(stale(client)).toEqual(
      [
        keys.containers(false),
        keys.containers(true),
        keys.container("web"),
        keys.info(),
        keys.isolation("web"),
        keys.networks(),
      ]
        .map((k) => JSON.stringify(k))
        .sort(),
    );
  });

  it("a detail page opened by name goes stale on an event that names the container by id", () => {
    const client = clientWith(keys.container("web"), keys.container("0123456789ab"));
    applyEvents(client, [event("container", "pause", "0123456789abcdef")]);
    expect(stale(client)).toHaveLength(2);
  });

  it("create and destroy change what uses images, volumes and networks", () => {
    for (const action of ["create", "destroy"]) {
      const client = clientWith(keys.images(), keys.image("alpine"), keys.volumes(), keys.network("n1"));
      applyEvents(client, [event("container", action)]);
      expect(stale(client)).toHaveLength(4);
    }
  });

  it("an exec changes no view", () => {
    for (const action of ["exec_create", "exec_start", "exec_die"]) {
      expect(invalidationsFor(event("container", action))).toEqual([]);
    }
  });

  it("images, volumes and networks refresh their own views", () => {
    const client = clientWith(keys.images(), keys.volumes(), keys.networks(), keys.containers(true));
    applyEvents(client, [event("image", "pull", "docker.io/library/alpine:latest")]);
    expect(stale(client)).toEqual([JSON.stringify(keys.images())]);

    const v = clientWith(keys.images(), keys.volumes(), keys.volume("data"));
    applyEvents(v, [event("volume", "create", "data")]);
    expect(stale(v)).toEqual([keys.volume("data"), keys.volumes()].map((k) => JSON.stringify(k)).sort());
  });

  it("connecting a container changes the container too", () => {
    const client = clientWith(keys.networks(), keys.container("web"), keys.containers(true), keys.volumes());
    applyEvents(client, [event("network", "connect", "n1", { name: "backend", container: "abc" })]);
    expect(stale(client)).toHaveLength(3);
    expect(stale(client)).not.toContain(JSON.stringify(keys.volumes()));
  });

  it("an unknown kind refreshes everything", () => {
    const client = clientWith(keys.images(), keys.volumes());
    applyEvents(client, [event("plugin" as EventKind, "enable")]);
    expect(stale(client)).toHaveLength(2);
  });

  it("a burst of events refetches each key once", () => {
    const burst = Array.from({ length: 10 }, (_, i) => event("container", "destroy", `id${i}`));
    const keysOnce = invalidationsForAll(burst);
    expect(new Set(keysOnce.map((k) => JSON.stringify(k))).size).toBe(keysOnce.length);
    expect(keysOnce).toEqual(invalidationsFor(burst[0]));
    // A start and a destroy: the destroy's keys cover the start's.
    expect(invalidationsForAll([event("container", "start"), burst[0]])).toHaveLength(keysOnce.length);
  });
});

describe("activity feed lines", () => {
  it("say what happened", () => {
    expect(describeEvent(event("container", "die", "abc", { name: "web", exit_code: "137", oom_killed: "true" }))).toBe(
      "web exited (137), OOM-killed",
    );
    expect(describeEvent(event("container", "unpause", "abc", { name: "web" }))).toBe("web resumed");
    expect(describeEvent(event("network", "connect", "n1", { name: "backend", container: "0123456789abcdef" }))).toBe(
      "0123456789ab connected to backend",
    );
    expect(describeEvent(event("volume", "destroy", "data"))).toBe("volume data removed");
    const names = (id: string) => (id === "0123456789abcdef" ? "web" : undefined);
    expect(describeEvent(event("network", "disconnect", "n1", { name: "bridge", container: "0123456789abcdef" }), names)).toBe(
      "web disconnected from bridge",
    );
  });
});
