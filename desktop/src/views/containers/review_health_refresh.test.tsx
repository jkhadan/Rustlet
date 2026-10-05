// @vitest-environment jsdom
// Review: the container page's Health section against what rustletd does
// between two verdicts.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ContainerInspect, Health } from "@/bindings";
import { TooltipProvider } from "@/components/ui/tooltip";

const h = vi.hoisted(() => {
  const handlers: Record<string, (args: any) => unknown> = {};
  class Channel<T> {
    onmessage: (m: T) => void;
    constructor(on?: (m: T) => void) {
      this.onmessage = on ?? (() => {});
    }
  }
  const invoke = async (cmd: string, args?: any) => {
    const f = handlers[cmd];
    if (!f) throw { kind: "failed", message: `no handler for ${cmd}` };
    return f(args);
  };
  return { handlers, Channel, invoke };
});
vi.mock("@tauri-apps/api/core", () => ({ Channel: h.Channel, invoke: h.invoke }));
// The other tabs (uPlot, xterm.js) need a real browser; only the Overview
// is under test.
vi.mock("./StatsTab", () => ({ StatsTab: () => null }));
vi.mock("./TerminalTab", () => ({ TerminalTab: () => null }));
vi.mock("./LogsTab", () => ({ LogsTab: () => null }));

import { ContainerPage } from "./ContainerPage";

afterEach(cleanup);

const check = (second: number, exit_code: number) => ({
  start: `2026-10-04T10:00:${String(second).padStart(2, "0")}.000000000Z`,
  end: `2026-10-04T10:00:${String(second).padStart(2, "0")}.010000000Z`,
  exit_code,
  output: exit_code ? "Could not connect to Redis\n" : "PONG\n",
});

function inspect(health: Health): ContainerInspect {
  return {
    id: "a".repeat(64),
    name: "redis",
    created: "2026-10-04T10:00:00Z",
    image: "redis:7-alpine",
    image_id: "sha256:" + "b".repeat(64),
    command: ["redis-server"],
    config: {
      image: "redis:7-alpine",
      name: "redis",
      cmd: [],
      entrypoint: null,
      env: [],
      user: null,
      workdir: null,
      hostname: null,
      tty: false,
      open_stdin: false,
      stdin_once: false,
      labels: {},
      read_only: false,
      userns: "host",
      memory: null,
      cpus: null,
      pids_limit: null,
      restart: { name: "no", max_retries: 0 },
      auto_remove: false,
      stop_signal: null,
      stop_timeout: null,
      // compose's `healthcheck:` (examples/hits: every 2 s, 5 retries);
      // shortened here so that the test needn't wait long.
      healthcheck: { test: ["CMD", "redis-cli", "ping"], interval: 300e6, timeout: 2e9, start_period: null, start_interval: null, retries: 5 },
      cap_add: [],
      cap_drop: [],
      privileged: false,
      security_opt: [],
      devices: [],
      network: "bridge",
      network_aliases: [],
      ip: null,
      ip6: null,
      extra_networks: [],
      ports: [],
      publish_all: false,
      dns: [],
      dns_search: [],
      dns_options: [],
      extra_hosts: [],
      mounts: [],
    },
    state: {
      status: "running",
      pid: 42,
      exit_code: null,
      oom_killed: false,
      error: null,
      started_at: "2026-10-04T10:00:00Z",
      finished_at: null,
      restart_count: 0,
      health,
    },
    hostname: "aaaaaaaaaaaa",
    rootfs: null,
    dir: "/x",
    log_path: "/x/container.log",
    cgroup: "/rustlet/a",
    uid_map: null,
    network: { mode: "bridge", networks: [], ports: [], dns_names: [] },
    mounts: [],
  } as unknown as ContainerInspect;
}

describe("the Health section of a container's overview", () => {
  // Expected: the section shows the failing streak and "the last five
  // results" (desktop/README.md; docs/architecture.md §2.8: "a Health
  // section in its overview (verdict, failing streak, the last checks)"),
  // and "Nothing polls: so every change a view shows has an event" (§2.8,
  // Live state). But rustletd saves every check and sends `health_status`
  // only when the verdict changes (crates/rustletd/src/health.rs,
  // check_health: `if let Some(status) = changed { … emit(…) }`; chapter
  // 19: "Two more failures changed nothing, so there was no event for
  // them"). So checks that fail without changing the verdict (here two, of
  // five retries) never reach the page: it keeps saying the last check
  // passed and nothing is failing, while the container is two checks from
  // unhealthy.
  it("shows checks that ran after it was opened, though the verdict didn't change", { timeout: 10_000 }, async () => {
    let health: Health = { status: "healthy", failing_streak: 0, log: [check(0, 0)] };
    h.handlers.container_inspect = () => inspect(health);
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter initialEntries={["/containers/redis"]}>
          <TooltipProvider>
            <Routes>
              <Route path="/containers/:id/:tab?" element={<ContainerPage />} />
            </Routes>
          </TooltipProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const card = await screen.findByTestId("health");
    expect(within(card).getByTestId("health-checks").querySelectorAll("tbody tr")).toHaveLength(1);

    // rustletd runs two more checks (every 300 ms here); both fail, the
    // verdict stays `healthy` (5 retries): no event.
    health = { status: "healthy", failing_streak: 2, log: [check(0, 0), check(1, 1), check(2, 1)] };

    await waitFor(
      () => {
        const rows = screen.getByTestId("health-checks").querySelectorAll("tbody tr");
        expect(rows).toHaveLength(3);
        expect(screen.getByTestId("health").textContent).toContain("2 checks failed in a row");
      },
      { timeout: 3_000 },
    );
  });
});
