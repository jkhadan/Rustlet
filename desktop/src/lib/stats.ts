// What the stats tab plots, derived from consecutive samples the way
// `rustlet stats` computes its columns (crates/rustlet-cli/src/stats.rs).

import type { StatsSample } from "@/bindings";

import { parseTime } from "./format";

/** One point of the charts. Rates are per second, over the time between
 * this sample and the one before. */
export interface Point {
  /** Unix seconds (uPlot's x axis). */
  t: number;
  /** Docker's convention: 100% is one CPU, so 4 busy CPUs read 400%. */
  cpu: number;
  memory: number;
  memoryLimit: number | null;
  rx: number;
  tx: number;
  read: number;
  write: number;
  pids: number;
  pidsLimit: number | null;
}

/** CPU time used over wall time passed, in percent of one CPU. */
export function cpuPercent(prev: StatsSample, cur: StatsSample): number {
  const used = (cur.cpu.usage_usec ?? 0) - (prev.cpu.usage_usec ?? 0);
  const wall = elapsedSeconds(prev, cur) * 1e6;
  return wall > 0 && used >= 0 ? (used / wall) * 100 : 0;
}

/** `memory.current` less the page cache that can be dropped at once
 * (`inactive_file`), as `docker stats` shows it. */
export function memoryUsage(s: StatsSample): number {
  const inactive = s.memory_stat.inactive_file ?? 0;
  return inactive < s.memory_current ? s.memory_current - inactive : s.memory_current;
}

/** The interfaces that count: the container's own, not its loopback. */
function interfaces(s: StatsSample) {
  return s.network.filter((d) => d.name !== "lo");
}

/** Bytes through the container's interfaces. */
export function networkTotals(s: StatsSample): { rx: number; tx: number } {
  let rx = 0;
  let tx = 0;
  for (const d of interfaces(s)) {
    rx += d.rx_bytes;
    tx += d.tx_bytes;
  }
  return { rx, tx };
}

/** Bytes read and written on block devices (`io.stat`). */
export function blockTotals(s: StatsSample): { read: number; write: number } {
  let read = 0;
  let write = 0;
  for (const dev of Object.values(s.io)) {
    read += dev?.rbytes ?? 0;
    write += dev?.wbytes ?? 0;
  }
  return { read, write };
}

function elapsedSeconds(prev: StatsSample, cur: StatsSample): number {
  const a = parseTime(prev.read);
  const b = parseTime(cur.read);
  return a == null || b == null ? 0 : (b - a) / 1000;
}

/** A byte counter of each interface or device, by its name. */
type Counters = Map<string, number>;

const net =
  (key: "rx_bytes" | "tx_bytes") =>
  (s: StatsSample): Counters =>
    new Map(interfaces(s).map((d) => [d.name, d[key]]));

const block =
  (key: "rbytes" | "wbytes") =>
  (s: StatsSample): Counters =>
    new Map(Object.entries(s.io).map(([dev, io]) => [dev, io[key] ?? 0]));

/** How much the counters grew, each against itself. An interface or a
 * device in only one of the samples (`network connect` or `disconnect`
 * between them) adds nothing: subtracting sums would count its whole
 * counter as traffic, or take it away from the others'. A counter that
 * went down started again (an interface of the same name made anew), and
 * adds nothing either. */
function growth(prev: Counters, cur: Counters): number {
  let n = 0;
  for (const [key, b] of cur) {
    const a = prev.get(key);
    if (a !== undefined && b >= a) n += b - a;
  }
  return n;
}

/** The point for `cur`, from the sample before it. A first sample has no
 * rates yet, so it makes no point (`rustlet stats` doesn't draw it
 * either). */
export function toPoint(prev: StatsSample, cur: StatsSample): Point {
  const t = (parseTime(cur.read) ?? Date.now()) / 1000;
  const dt = elapsedSeconds(prev, cur);
  const rate = (counters: (s: StatsSample) => Counters) => (dt > 0 ? growth(counters(prev), counters(cur)) / dt : 0);
  return {
    t,
    cpu: cpuPercent(prev, cur),
    memory: memoryUsage(cur),
    memoryLimit: cur.memory_max,
    rx: rate(net("rx_bytes")),
    tx: rate(net("tx_bytes")),
    read: rate(block("rbytes")),
    write: rate(block("wbytes")),
    pids: cur.pids_current,
    pidsLimit: cur.pids_max,
  };
}

/** The last `max` points of a stream of samples: one for each sample after
 * the first. */
export class Series {
  points: Point[] = [];
  private last: StatsSample | null = null;
  constructor(private readonly max = 120) {}

  push(sample: StatsSample): void {
    if (this.last) this.points.push(toPoint(this.last, sample));
    if (this.points.length > this.max) this.points.splice(0, this.points.length - this.max);
    this.last = sample;
  }

  get latest(): StatsSample | null {
    return this.last;
  }

  /** Columns for uPlot: `[x, ...ys]`. */
  columns(...fields: (keyof Omit<Point, "t">)[]): number[][] {
    return [this.points.map((p) => p.t), ...fields.map((f) => this.points.map((p) => (p[f] as number | null) ?? 0))];
  }
}
