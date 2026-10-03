// The networks view's graph: the host on top, its bridge networks below it,
// and the running containers below their networks, an edge per interface
// (labelled with its address). A container on the host's network hangs off
// the host, beside the networks; one in another's namespace hangs below
// that container, in a fourth row. Each container sits under the middle of
// its networks.

import type { ContainerSummary, Network } from "@/bindings";

export type NodeKind = "host" | "network" | "container";

export interface TopoNode {
  id: string;
  kind: NodeKind;
  x: number;
  y: number;
  label: string;
  /** network: subnet, bridge; container: image, ports. */
  detail: string[];
  /** The network or container's own id. */
  ref: string;
  status?: string;
  flags?: string[];
}

export interface TopoEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  dashed?: boolean;
}

export const LAYOUT = { rowGap: 170, colGap: 230, nodeWidth: 200 };

const isRunning = (c: ContainerSummary) => c.state.status === "running" || c.state.status === "paused";

/** Spreads `xs` (wanted positions, in order) at least `gap` apart, keeping
 * their order and their centre. */
export function spread(xs: number[], gap: number): number[] {
  const out = xs.slice();
  for (let i = 1; i < out.length; i++) out[i] = Math.max(out[i], out[i - 1] + gap);
  // Shift back so the row keeps the centre the wanted positions had.
  if (out.length) {
    const want = (xs[0] + xs[xs.length - 1]) / 2;
    const got = (out[0] + out[out.length - 1]) / 2;
    for (let i = 0; i < out.length; i++) out[i] -= got - want;
  }
  return out;
}

export function buildTopology(networks: Network[], containers: ContainerSummary[]): { nodes: TopoNode[]; edges: TopoEdge[] } {
  const nets = networks
    .slice()
    .sort((a, b) => (a.name === "bridge" ? -1 : b.name === "bridge" ? 1 : a.name.localeCompare(b.name)));
  const running = containers.filter(isRunning);
  const byId = new Map(running.map((c) => [c.id, c]));
  const nodes: TopoNode[] = [];
  const edges: TopoEdge[] = [];

  // Row 1: networks, then the containers on the host's network beside them.
  const hostMode = running.filter((c) => c.network_mode === "host");
  const row1 = nets.length + hostMode.length;
  const x1 = (i: number) => (i - (row1 - 1) / 2) * LAYOUT.colGap;
  nodes.push({ id: "host", kind: "host", x: 0, y: 0, label: "host", detail: [], ref: "host" });
  nets.forEach((n, i) => {
    nodes.push({
      id: `net:${n.id}`,
      kind: "network",
      x: x1(i),
      y: LAYOUT.rowGap,
      label: n.name,
      detail: [n.subnet, ...(n.subnet6 ? [n.subnet6] : []), n.bridge].filter(Boolean),
      ref: n.id,
      flags: [n.internal ? "internal" : "", n.dns ? "DNS" : "", n.ipv6 ? "IPv6" : ""].filter(Boolean),
    });
    edges.push({ id: `host-${n.id}`, source: "host", target: `net:${n.id}`, label: n.gateway || undefined });
  });
  hostMode.forEach((c, i) => {
    nodes.push(containerNode(c, x1(nets.length + i), LAYOUT.rowGap));
    edges.push({ id: `hostmode-${c.id}`, source: "host", target: `ctr:${c.id}`, label: "host network", dashed: true });
  });

  // Row 2: containers with interfaces, under the middle of their networks;
  // then those in another's namespace, and those with none.
  const netX = new Map(nets.map((n, i) => [n.id, x1(i)]));
  const attached = new Map<string, { netId: string; ip: string }[]>();
  for (const n of nets) {
    for (const e of n.containers) {
      if (!byId.has(e.container_id)) continue;
      attached.set(e.container_id, [...(attached.get(e.container_id) ?? []), { netId: n.id, ip: e.ip_address }]);
    }
  }
  const row2 = [...attached.entries()]
    .map(([id, eps]) => ({ c: byId.get(id)!, eps, want: eps.reduce((s, e) => s + (netX.get(e.netId) ?? 0), 0) / eps.length }))
    .sort((a, b) => a.want - b.want || a.c.name.localeCompare(b.c.name));
  const joined = running.filter((c) => c.network_mode.startsWith("container:"));
  const isolated = running.filter((c) => c.network_mode === "none");
  const placed = spread(
    row2.map((r) => r.want),
    LAYOUT.colGap,
  );
  // The joined and isolated ones follow the rest at the right.
  let right = row2.length ? placed[row2.length - 1] : -LAYOUT.colGap;
  const next = () => (right += LAYOUT.colGap);
  const y2 = LAYOUT.rowGap * 2;
  row2.forEach((r, i) => {
    nodes.push(containerNode(r.c, placed[i], y2));
    for (const e of r.eps) {
      edges.push({ id: `${e.netId}-${r.c.id}`, source: `net:${e.netId}`, target: `ctr:${r.c.id}`, label: e.ip.replace(/\/\d+$/, "") });
    }
  });
  isolated.forEach((c) => nodes.push(containerNode(c, next(), y2)));
  // Row 3: under the container whose namespace each one joined.
  const ownerOf = (c: ContainerSummary) => {
    const target = c.network_mode.slice("container:".length);
    return running.find((o) => o.id === target || o.name === target || o.id.startsWith(target));
  };
  const placedAt = new Map(nodes.map((n) => [n.id, n.x]));
  const row3 = joined
    .map((c) => ({ c, owner: ownerOf(c) }))
    .map((j) => ({ ...j, want: (j.owner && placedAt.get(`ctr:${j.owner.id}`)) ?? next() }))
    .sort((a, b) => a.want - b.want);
  const xs3 = spread(
    row3.map((j) => j.want),
    LAYOUT.colGap,
  );
  row3.forEach((j, i) => {
    nodes.push(containerNode(j.c, xs3[i], LAYOUT.rowGap * 3));
    if (j.owner) {
      edges.push({ id: `share-${j.c.id}`, source: `ctr:${j.owner.id}`, target: `ctr:${j.c.id}`, label: "same network namespace", dashed: true });
    }
  });
  return { nodes, edges };
}

function containerNode(c: ContainerSummary, x: number, y: number): TopoNode {
  const ports = c.ports.filter((p) => p.host_ip !== "::").map((p) => `${p.host_port}→${p.container_port}/${p.protocol}`);
  return {
    id: `ctr:${c.id}`,
    kind: "container",
    x,
    y,
    label: c.name,
    detail: [c.image.replace(/^docker\.io\/(library\/)?/, ""), ...ports],
    ref: c.id,
    status: c.state.status,
    flags: c.network_mode === "none" ? ["no network"] : [],
  };
}
