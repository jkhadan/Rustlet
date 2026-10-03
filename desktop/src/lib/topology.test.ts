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
    expect(buildTopology([net("n1", "bridge", [["a", "10.89.0.2/24"]])], [ctr("a")]).edges[1].label).toBe("10.89.0.2");
    // Host mode hangs off the host, in the networks' row.
    expect(node("ctr:h").y).toBe(LAYOUT.rowGap);
    expect(edges.find((e) => e.target === "ctr:h")).toMatchObject({ source: "host", dashed: true });
    // Another's namespace: below its owner, with an edge from it.
    expect(edges.find((e) => e.target === "ctr:j")).toMatchObject({ source: "ctr:a", dashed: true });
    expect(node("ctr:j")).toMatchObject({ x: node("ctr:a").x, y: LAYOUT.rowGap * 3 });
    // No network: a node, no edge. Stopped containers aren't drawn.
    expect(node("ctr:x").flags).toEqual(["no network"]);
    expect(edges.some((e) => e.target === "ctr:x")).toBe(false);
    expect(nodes.some((n) => n.id === "ctr:gone")).toBe(false);
    // Nothing overlaps in a row.
    const row2 = nodes.filter((n) => n.y === LAYOUT.rowGap * 2).map((n) => n.x).sort((p, q) => p - q);
    for (let i = 1; i < row2.length; i++) expect(row2[i] - row2[i - 1]).toBeGreaterThanOrEqual(LAYOUT.colGap);
  });

  it("draws a running container that is on no network, though its mode names one", () => {
    // `network disconnect bridge web` lets the last network go too: web runs
    // on, with only `lo`, and its mode still says `bridge`.
    const { nodes, edges } = buildTopology([net("n1", "bridge", [])], [ctr("web")]);
    expect(nodes.find((n) => n.id === "ctr:web")).toMatchObject({ y: LAYOUT.rowGap * 2, flags: ["not on any network"] });
    expect(edges.some((e) => e.target === "ctr:web")).toBe(false);
  });

  it("finds the container whose namespace one shares by its full id, and only that one", () => {
    // `run --name web`, `run --network container:web --name side`, `rm -f web`,
    // `run --name web` again: side is in the first web's namespace.
    const old = "0".repeat(64);
    const web = { ...ctr("1".repeat(64)), name: "web" };
    const bridge = net("n1", "bridge", [[web.id, "10.89.0.3/24"]]);
    const gone = buildTopology([bridge], [web, ctr("side", `container:${old}`)]);
    expect(gone.edges.some((e) => e.target === "ctr:side")).toBe(false);
    expect(gone.nodes.find((n) => n.id === "ctr:side")).toMatchObject({
      y: LAYOUT.rowGap * 2,
      flags: ["in the network namespace of a removed container"],
    });
    // Still listed but stopped: named, not drawn under anything.
    const stopped = buildTopology([bridge], [web, { ...ctr(old, "bridge", "exited"), name: "old" }, ctr("side", `container:${old}`)]);
    expect(stopped.edges.some((e) => e.target === "ctr:side")).toBe(false);
    expect(stopped.nodes.find((n) => n.id === "ctr:side")?.flags).toEqual(["in the network namespace of old (exited)"]);
    // Neither a name nor a prefix of an id is an id.
    for (const mode of ["container:web", `container:${web.id.slice(0, 12)}`]) {
      expect(buildTopology([bridge], [web, ctr("side", mode)]).edges.some((e) => e.target === "ctr:side")).toBe(false);
    }
    expect(buildTopology([bridge], [web, ctr("side", `container:${web.id}`)]).edges).toContainEqual(
      expect.objectContaining({ source: `ctr:${web.id}`, target: "ctr:side" }),
    );
  });

  it("shows every published port, with its address when it is a particular one", () => {
    // One entry per mapping: `-p 8080:80` is on 0.0.0.0 alone (its [::]
    // socket has none), `-p [::]:8443:443` on :: alone.
    const web = {
      ...ctr("a"),
      ports: [
        { host_ip: "0.0.0.0", host_port: 8080, container_port: 80, protocol: "tcp" as const },
        { host_ip: "::", host_port: 8443, container_port: 443, protocol: "tcp" as const },
        { host_ip: "127.0.0.1", host_port: 5353, container_port: 53, protocol: "udp" as const },
        { host_ip: "::1", host_port: 9000, container_port: 9000, protocol: "tcp" as const },
      ],
    };
    const { nodes } = buildTopology([net("n1", "bridge", [["a", "10.89.0.2/24"]])], [web]);
    expect(nodes.find((n) => n.id === "ctr:a")!.detail).toEqual([
      "alpine:latest",
      "8080→80/tcp",
      "8443→443/tcp",
      "127.0.0.1:5353→53/udp",
      "[::1]:9000→9000/tcp",
    ]);
  });
});
