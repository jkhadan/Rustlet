import { describe, expect, it } from "vitest";

import type { ContainerSummary, Network } from "@/bindings";

import { buildTopology, LAYOUT, spread } from "./topology";

function net(id: string, name: string, endpoints: [string, string][]): Network {
  return {
    id,
    name,
    driver: "bridge",
    created: "",
    subnet: "10.89.0.0/24",
    gateway: "10.89.0.1",
    ipv6: false,
    subnet6: null,
    gateway6: null,
    bridge: `rlb${id}`,
    internal: false,
    dns: name !== "bridge",
    labels: {},
    containers: endpoints.map(([container_id, ip_address]) => ({
      container_id,
      container_name: container_id,
      ip_address,
      ipv6_address: null,
      mac_address: "",
      dns_names: [],
    })),
  };
}

function ctr(id: string, network_mode = "bridge", status: "running" | "exited" = "running"): ContainerSummary {
  return {
    id,
    name: `c-${id}`,
    image: "docker.io/library/alpine:latest",
    image_id: "sha256:x",
    command: [],
    created: "",
    state: { status, pid: 1, exit_code: null, oom_killed: false, error: null, started_at: null, finished_at: null, restart_count: 0 },
    labels: {},
    ports: [],
    network_mode,
  };
}

describe("topology", () => {
  it("spreads a row apart, in order, around the same centre", () => {
    expect(spread([0, 0, 0], 10)).toEqual([-10, 0, 10]);
    expect(spread([-100, 100], 10)).toEqual([-100, 100]);
  });

  it("hangs containers under their networks, with an edge per interface", () => {
    const { nodes, edges } = buildTopology(
      [net("n2", "backend", [["b", "10.89.1.2"], ["a", "10.89.1.3"]]), net("n1", "bridge", [["a", "10.89.0.2"]])],
      [ctr("a"), ctr("b", "backend"), ctr("h", "host"), ctr("j", "container:a"), ctr("x", "none"), ctr("gone", "bridge", "exited")],
    );
    const node = (id: string) => nodes.find((n) => n.id === id)!;
    // The default network first.
    expect(node("net:n1").x).toBeLessThan(node("net:n2").x);
    // a is on both networks: between them; b only on backend.
    expect(node("ctr:a").x).toBeLessThan(node("ctr:b").x);
    expect(edges.filter((e) => e.target === "ctr:a").map((e) => e.label).sort()).toEqual(["10.89.0.2", "10.89.1.3"]);
    // Host mode hangs off the host, in the networks' row.
    expect(node("ctr:h").y).toBe(LAYOUT.rowGap);
    expect(edges.find((e) => e.target === "ctr:h")).toMatchObject({ source: "host", dashed: true });
    // Another's namespace: an edge from its owner.
    expect(edges.find((e) => e.target === "ctr:j")).toMatchObject({ source: "ctr:a", dashed: true });
    // No network: a node, no edge. Stopped containers aren't drawn.
    expect(node("ctr:x").flags).toEqual(["no network"]);
    expect(edges.some((e) => e.target === "ctr:x")).toBe(false);
    expect(nodes.some((n) => n.id === "ctr:gone")).toBe(false);
    // Nothing overlaps in a row.
    const row2 = nodes.filter((n) => n.y === LAYOUT.rowGap * 2).map((n) => n.x).sort((p, q) => p - q);
    for (let i = 1; i < row2.length; i++) expect(row2[i] - row2[i - 1]).toBeGreaterThanOrEqual(LAYOUT.colGap);
  });
});
