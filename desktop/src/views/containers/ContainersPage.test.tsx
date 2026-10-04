// @vitest-environment jsdom
// The containers list against what the daemon lists.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

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

import { ContainersPage } from "./ContainersPage";

afterEach(cleanup);

describe("containers list", () => {
  it("with stopped containers hidden, the subtitle doesn't say none are stopped", async () => {
    const summary = (name: string, status: string) => ({
      id: name.padEnd(64, "0"),
      name,
      image: "alpine",
      image_id: "sha256:x",
      command: ["sh"],
      created: "2026-10-03T00:00:00Z",
      state: { status, pid: null, exit_code: 0, oom_killed: false, error: null, started_at: null, finished_at: null, restart_count: 0 },
      labels: {},
      ports: [],
      network_mode: "bridge",
    });
    const every = [summary("up", "running"), summary("down1", "exited"), summary("down2", "exited")];
    // GET /containers?all=false lists only live ones (ListQuery.all).
    h.handlers.container_list = ({ all }: { all: boolean }) => (all ? every : every.slice(0, 1));
    h.handlers.image_list = () => [];
    h.handlers.network_list = () => [];
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <TooltipProvider>
            <ContainersPage />
          </TooltipProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await screen.findByText("1 running · 2 stopped");
    fireEvent.click(screen.getByLabelText("Show stopped containers"));
    await waitFor(() => expect(screen.queryAllByTestId("container-row").length).toBe(1));
    expect(document.body.textContent).not.toContain("0 stopped");
    expect(document.body.textContent).toContain("1 running · stopped ones hidden");
  });

  it("leaves a build's step containers out unless asked, and shows what a healthcheck says", async () => {
    const summary = (name: string, labels: Record<string, string>, health: string | null) => ({
      id: name.padEnd(64, "0"),
      name,
      image: "x",
      image_id: "sha256:x",
      command: ["sh"],
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
        health: health && { status: health, failing_streak: 0, log: [] },
      },
      labels,
      ports: [],
      network_mode: "bridge",
    });
    h.handlers.container_list = () => [
      summary("web", {}, "healthy"),
      summary("db", {}, null),
      summary("eager_turing", { "io.rustlet.build": "0123456789ab" }, null),
    ];
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <TooltipProvider>
            <ContainersPage />
          </TooltipProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await screen.findByText("2 running · 0 stopped · 1 build container hidden");
    const rows = () => screen.queryAllByTestId("container-row").map((r) => [r.dataset.name, r.dataset.health]);
    expect(rows()).toEqual([
      ["web", "healthy"],
      ["db", undefined],
    ]);
    fireEvent.click(screen.getByLabelText("Show build containers"));
    await waitFor(() => expect(rows()).toHaveLength(3));
    expect(document.body.textContent).toContain("3 running · 0 stopped");
  });
});
