// @vitest-environment jsdom
// Review: the dashboard's numbers while a build's step container runs.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => {
  const handlers: Record<string, (args: any) => unknown> = {};
  const invoke = async (cmd: string, args?: any) => {
    const f = handlers[cmd];
    if (!f) throw { kind: "failed", message: `no handler for ${cmd}` };
    return f(args);
  };
  return { handlers, invoke };
});
vi.mock("@tauri-apps/api/core", () => ({ Channel: class {}, invoke: h.invoke }));

import { Dashboard } from "./Dashboard";

afterEach(cleanup);

function running(name: string, labels: Record<string, string> = {}) {
  return {
    id: name.padEnd(64, "0"),
    name,
    image: "x",
    image_id: "sha256:x",
    command: [],
    created: "2026-10-04T00:00:00Z",
    state: {
      status: "running",
      pid: 1,
      exit_code: null,
      oom_killed: false,
      error: null,
      started_at: "2026-10-04T00:00:00Z",
      finished_at: null,
      restart_count: 0,
      health: null,
    },
    labels,
    ports: [],
    network_mode: "bridge",
  };
}

describe("the dashboard's counts", () => {
  // Expected: the numbers agree with the lists, which leave a build's step
  // containers out unless asked (docs/architecture.md §2.8: "the build's
  // step containers (label io.rustlet.build) hidden unless asked for").
  // While a RUN step runs, the Containers page says "2 running · 0 stopped
  // · 1 build container hidden" and the Running card lists 2, but the
  // Containers count above it says 3 running: daemon_info's counts
  // (rustletd's Info) include the step container, and Dashboard.tsx shows
  // them as they come.
  it("say as many running as the Running card lists, a build's step container left out", async () => {
    h.handlers.daemon_info = () => ({ containers: 3, running: 3, paused: 0, stopped: 0, images: 2, networks: 1, volumes: 0 });
    h.handlers.container_list = () => [running("web"), running("db"), running("build-0123456789ab-3", { "io.rustlet.build": "0123456789ab" })];
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter>
          <Dashboard />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const list = await screen.findByTestId("running");
    expect(within(list).getAllByRole("link")).toHaveLength(2);
    const counts = screen.getByTestId("counts");
    await waitFor(() => expect(counts.textContent).toContain("running"));
    expect(counts.textContent).toContain("2 running");
  });
});
