// @vitest-environment jsdom
// The stats tab's stream.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ContainerInspect, StatsSample } from "@/bindings";

const h = vi.hoisted(() => {
  // uPlot (the charts) asks for it when it loads; jsdom has none.
  window.matchMedia ??= ((q: string) => ({ matches: false, media: q, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} })) as unknown as typeof window.matchMedia;
  const handlers: Record<string, (args: any) => unknown> = {};
  const calls: { cmd: string; args: any }[] = [];
  class Channel<T> {
    onmessage: (m: T) => void;
    constructor(on?: (m: T) => void) {
      this.onmessage = on ?? (() => {});
    }
  }
  const invoke = async (cmd: string, args?: any) => {
    calls.push({ cmd, args });
    const f = handlers[cmd];
    if (!f) throw { kind: "failed", message: `no handler for ${cmd}` };
    return f(args);
  };
  return { handlers, calls, Channel, invoke };
});
vi.mock("@tauri-apps/api/core", () => ({ Channel: h.Channel, invoke: h.invoke }));
// Drawing needs a canvas; what is drawn isn't what this is about.
vi.mock("@/components/Chart", () => ({ Chart: () => null }));

import { DaemonProvider } from "@/lib/daemon";

import { StatsTab } from "./StatsTab";

const container = {
  id: "c1",
  name: "web",
  config: { cpus: null },
  cgroup: "/rustlet/c1",
  state: { status: "running", pid: 42, started_at: "2026-10-03T00:00:01Z" },
} as unknown as ContainerInspect;

const sample = (read: string, usage: number): StatsSample => ({
  id: "c1",
  name: "web",
  read,
  cpus_online: 4,
  cpu: { usage_usec: usage },
  memory_current: 0,
  memory_max: null,
  memory_peak: null,
  swap_current: null,
  memory_stat: {},
  memory_events: { low: 0, high: 0, max: 0, oom: 0, oom_kill: 0, oom_group_kill: 0 },
  pids_current: 1,
  pids_max: null,
  io: {},
  pressure: {},
  network: [],
});

const called = (cmd: string) => h.calls.filter((c) => c.cmd === cmd);
let channels: { onmessage: (m: unknown) => void }[] = [];
let watch: { onmessage: (m: unknown) => void } | undefined;
const send = (m: unknown) => act(() => channels[channels.length - 1].onmessage(m));
const daemon = (m: unknown) => act(() => watch!.onmessage(m));
const connected = { type: "connected", socket: "/run/rustlet/rustlet.sock", version: { version: "0.1.0" } };

beforeEach(() => {
  h.calls.length = 0;
  channels = [];
  watch = undefined;
  h.handlers.container_stats = (args) => {
    channels.push(args.channel);
    return channels.length;
  };
  h.handlers.daemon_watch = (args) => {
    watch = args.channel;
    return 99;
  };
  h.handlers.stream_cancel = () => true;
});
afterEach(cleanup);

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <DaemonProvider>
        <StatsTab container={container} running />
      </DaemonProvider>
    </QueryClientProvider>,
  );
}

describe("stats", () => {
  it("shows nothing for the first sample, which has no rates yet", async () => {
    mount();
    await waitFor(() => expect(channels.length).toBe(1));
    await send({ type: "items", items: [sample("2026-10-03T00:00:02Z", 1_000_000)] });
    expect(screen.queryByTestId("stats")).toBeNull();
    await send({ type: "items", items: [sample("2026-10-03T00:00:03Z", 1_500_000)] });
    expect(screen.getByTestId("stats").textContent).toContain("50.0%");
  });

  it("sampling starts again once rustletd is back", async () => {
    mount();
    await waitFor(() => expect(watch).toBeDefined());
    await daemon(connected);
    await waitFor(() => expect(channels.length).toBe(1));
    await send({ type: "error", error: { kind: "failed", message: "connection closed before message completed" } });
    await daemon({ type: "disconnected", socket: "/run/rustlet/rustlet.sock", error: { kind: "unreachable", message: "connection refused" } });
    expect(called("container_stats").length).toBe(1);
    await daemon(connected);
    await waitFor(() => expect(called("container_stats").length).toBe(2));
    expect(screen.queryByText(/connection closed/)).toBeNull();
  });
});
