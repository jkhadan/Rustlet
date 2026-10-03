import { describe, expect, it } from "vitest";

import type { StatsSample } from "@/bindings";

import { cpuPercent, memoryUsage, Series, toPoint } from "./stats";

function sample(read: string, usage: number, extra: Partial<StatsSample> = {}): StatsSample {
  return {
    id: "c",
    name: "web",
    read,
    cpus_online: 4,
    cpu: { usage_usec: usage },
    memory_current: 100 << 20,
    memory_max: null,
    memory_peak: null,
    swap_current: null,
    memory_stat: { inactive_file: 30 << 20, anon: 60 << 20 },
    memory_events: { low: 0, high: 0, max: 0, oom: 0, oom_kill: 0, oom_group_kill: 0 },
    pids_current: 3,
    pids_max: 100,
    io: {},
    pressure: {},
    network: [],
    ...extra,
  };
}

describe("stats", () => {
  it("CPU is time used over wall time, 100% per CPU (as rustlet stats)", () => {
    const a = sample("2026-10-02T12:00:00.000000000Z", 1_000_000);
    const b = sample("2026-10-02T12:00:01.000000000Z", 1_500_000);
    expect(cpuPercent(a, b)).toBeCloseTo(50);
    const two = sample("2026-10-02T12:00:01.000000000Z", 3_000_000);
    expect(cpuPercent(a, two)).toBeCloseTo(200);
    expect(cpuPercent(b, a)).toBe(0);
  });

  it("nanosecond timestamps keep their milliseconds", () => {
    const a = sample("2026-10-02T12:00:00.000999999Z", 0);
    const b = sample("2026-10-02T12:00:00.500999999Z", 250_000);
    expect(cpuPercent(a, b)).toBeCloseTo(50);
  });

  it("memory leaves out the inactive page cache", () => {
    expect(memoryUsage(sample("t", 0))).toBe(70 << 20);
    expect(memoryUsage(sample("t", 0, { memory_stat: { inactive_file: 200 << 20 } }))).toBe(100 << 20);
  });

  it("rates are per second, the loopback doesn't count, and the series keeps the last points", () => {
    const net = (rx: number) => [
      { name: "lo", rx_bytes: 1e9, rx_packets: 0, rx_errors: 0, rx_dropped: 0, tx_bytes: 1e9, tx_packets: 0, tx_errors: 0, tx_dropped: 0 },
      { name: "eth0", rx_bytes: rx, rx_packets: 0, rx_errors: 0, rx_dropped: 0, tx_bytes: 0, tx_packets: 0, tx_errors: 0, tx_dropped: 0 },
    ];
    const a = sample("2026-10-02T12:00:00Z", 0, { network: net(1000), io: { "8:0": { rbytes: 0, wbytes: 10 } } });
    const b = sample("2026-10-02T12:00:02Z", 0, { network: net(5000), io: { "8:0": { rbytes: 4096, wbytes: 10 } } });
    const p = toPoint(a, b);
    expect(p.rx).toBe(2000);
    expect(p.tx).toBe(0);
    expect(p.read).toBe(2048);
    expect(toPoint(null, b).rx).toBe(0);

    const s = new Series(3);
    for (let i = 0; i < 5; i++) s.push(sample(`2026-10-02T12:00:0${i}Z`, i * 100_000));
    expect(s.points).toHaveLength(3);
    const [x, cpu] = s.columns("cpu");
    expect(x).toEqual([Date.parse("2026-10-02T12:00:02Z") / 1000, Date.parse("2026-10-02T12:00:03Z") / 1000, Date.parse("2026-10-02T12:00:04Z") / 1000]);
    expect(cpu[2]).toBeCloseTo(10);
  });
});
