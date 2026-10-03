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

/** Bytes through the container's interfaces (not its loopback). */
export function networkTotals(s: StatsSample): { rx: number; tx: number } {
  let rx = 0;
  let tx = 0;
  for (const d of s.network) {
    if (d.name === "lo") continue;
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

/** The point for `cur`; without `prev`, the rates and CPU are 0. */
export function toPoint(prev: StatsSample | null, cur: StatsSample): Point {
  const t = (parseTime(cur.read) ?? Date.now()) / 1000;
  const dt = prev ? elapsedSeconds(prev, cur) : 0;
  const rate = (a: number, b: number) => (dt > 0 && b >= a ? (b - a) / dt : 0);
  const net = networkTotals(cur);
  const blk = blockTotals(cur);
  const pnet = prev ? networkTotals(prev) : net;
  const pblk = prev ? blockTotals(prev) : blk;
  return {
    t,
    cpu: prev ? cpuPercent(prev, cur) : 0,
    memory: memoryUsage(cur),
    memoryLimit: cur.memory_max,
    rx: rate(pnet.rx, net.rx),
    tx: rate(pnet.tx, net.tx),
    read: rate(pblk.read, blk.read),
    write: rate(pblk.write, blk.write),
    pids: cur.pids_current,
    pidsLimit: cur.pids_max,
  };
}

/** The last `max` points of a stream of samples. */
export class Series {
  points: Point[] = [];
  private last: StatsSample | null = null;
  constructor(private readonly max = 120) {}

  push(sample: StatsSample): void {
    this.points.push(toPoint(this.last, sample));
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
