// @vitest-environment jsdom
// The dashboard's running list: health beside each, build steps folded away.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

function summary(name: string, labels: Record<string, string>, health: string | null) {
  return {
    id: name.padEnd(64, "0"),
    name,
    image: "x",
    image_id: "sha256:x",
    command: [],
    created: "2026-10-03T00:00:00Z",
    state: {
      status: "running",
      pid: 1,
      exit_code: null,
      oom_killed: false,
      error: null,
      started_at: "2026-10-03T00:00:00Z",
      finished_at: null,
      restart_count: 0,
      health: health && { status: health, failing_streak: 1, log: [] },
    },
    labels,
    ports: [],
    network_mode: "bridge",
  };
}

describe("the dashboard", () => {
  it("lists what runs with its health, a build's step containers only when asked", async () => {
    h.handlers.daemon_info = () => ({ containers: 3, running: 3, paused: 0, stopped: 0, images: 1, networks: 1, volumes: 0 });
    h.handlers.container_list = () => [
      summary("web", {}, "unhealthy"),
      summary("eager_turing", { "io.rustlet.build": "0123456789ab" }, null),
    ];
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter>
          <Dashboard />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const running = await screen.findByTestId("running");
    expect(within(running).getAllByRole("link").map((l) => l.textContent)).toEqual([expect.stringContaining("web")]);
    expect(running.querySelector('[data-health="unhealthy"]')).not.toBeNull();
    fireEvent.click(screen.getByTestId("toggle-build-containers"));
    await waitFor(() => expect(within(screen.getByTestId("running")).getAllByRole("link")).toHaveLength(2));
    expect(screen.getByTestId("toggle-build-containers").textContent).toBe("Hide build containers");
  });
});
