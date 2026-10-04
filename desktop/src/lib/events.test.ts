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

  it("a healthcheck's new verdict refreshes the container, its lists and the stacks, and nothing of the network", () => {
    const client = clientWith(
      keys.containers(true),
      keys.container("web"),
      keys.stacks(),
      keys.images(),
      keys.networks(),
      keys.isolation("web"),
    );
    applyEvents(client, [event("container", "health_status", "abc123", { name: "web", health_status: "unhealthy" })]);
    expect(stale(client)).toEqual(
      [keys.container("web"), keys.containers(true), keys.stacks()].map((k) => JSON.stringify(k)).sort(),
    );
  });

  it("a stack is its containers: every container event but an exec's changes it", () => {
    for (const action of ["create", "start", "die", "stop", "destroy", "health_status", "commit"]) {
      expect(invalidationsFor(event("container", action))).toContainEqual(keys.stacks());
    }
    expect(invalidationsFor(event("container", "exec_die"))).not.toContainEqual(keys.stacks());
    for (const kind of ["image", "network", "volume"] as const) {
      expect(invalidationsFor(event(kind, "create"))).not.toContainEqual(keys.stacks());
    }
  });

  it("a commit makes an image, named or not", () => {
    const digest = `sha256:${"ab".repeat(32)}`;
    const client = clientWith(keys.images(), keys.image(digest), keys.volumes(), keys.networks());
    // An unnamed commit's only event: no image event names it.
    applyEvents(client, [event("container", "commit", "abc123", { name: "web", new_image: digest })]);
    expect(stale(client)).toEqual([keys.image(digest), keys.images()].map((k) => JSON.stringify(k)).sort());
  });

  it("a tag (of a build, tag, commit or load) and an unnamed load refresh the images", () => {
    for (const [action, id] of [
      ["tag", "docker.io/library/hits:latest"],
      ["load", `sha256:${"cd".repeat(32)}`],
    ]) {
      const client = clientWith(keys.images(), keys.image("hits"), keys.containers(true), keys.stacks());
      applyEvents(client, [event("image", action, id, { id: `sha256:${"cd".repeat(32)}` })]);
      expect(stale(client)).toEqual([keys.image("hits"), keys.images()].map((k) => JSON.stringify(k)).sort());
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

  it("connecting or disconnecting a container changes the container too, running or not", () => {
    for (const action of ["connect", "disconnect"]) {
      const client = clientWith(keys.networks(), keys.container("web"), keys.containers(true), keys.volumes());
      applyEvents(client, [event("network", action, "n1", { name: "backend", container: "abc" })]);
      expect(stale(client)).toHaveLength(3);
      expect(stale(client)).not.toContain(JSON.stringify(keys.volumes()));
    }
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

  it("name an image as the image list does", () => {
    const digest = `sha256:${"4f".repeat(32)}`;
    // A pull names the reference as stored, with the digest in `id`.
    expect(describeEvent(event("image", "pull", "docker.io/library/alpine:latest", { id: digest }))).toBe(
      "image alpine:latest pulled",
    );
    expect(describeEvent(event("image", "untag", "ghcr.io/o/n:1", { id: digest }))).toBe("image ghcr.io/o/n:1 untagged");
    // One `delete` per image, named as `rmi` was given it: a name or an id.
    expect(describeEvent(event("image", "delete", "alpine", { id: digest }))).toBe("image alpine deleted");
    expect(describeEvent(event("image", "delete", digest, { id: digest }))).toBe("image 4f4f4f4f4f4f deleted");
  });

  it("say a healthcheck's verdict and a commit", () => {
    const e = (action: string, attributes: Record<string, string>) => event("container", action, "abc", { name: "web", ...attributes });
    expect(describeEvent(e("health_status", { health_status: "unhealthy" }))).toBe("web is unhealthy");
    expect(describeEvent(e("health_status", { health_status: "healthy" }))).toBe("web is healthy");
    expect(describeEvent(e("commit", { new_image: `sha256:${"ab".repeat(32)}` }))).toBe("web committed as image abababababab");
  });

  it("say what named an image, and an unnamed load by its id", () => {
    const digest = `sha256:${"4f".repeat(32)}`;
    expect(describeEvent(event("image", "tag", "docker.io/library/hits:latest", { id: digest }))).toBe("image hits:latest tagged");
    expect(describeEvent(event("image", "load", digest, { id: digest }))).toBe("image 4f4f4f4f4f4f loaded");
    // An action this app doesn't know yet says itself, rather than "deleted".
    expect(describeEvent(event("image", "prune", "x"))).toBe("image x prune");
  });

  it("say a restart that couldn't start, not an exit", () => {
    // The restart policy's start failed: no run began, so no exit code.
    const e = event("container", "die", "abc", { name: "web", image: "nginx", error: "the container's image: no such image" });
    expect(describeEvent(e)).toBe("web couldn't restart: the container's image: no such image");
  });
});
