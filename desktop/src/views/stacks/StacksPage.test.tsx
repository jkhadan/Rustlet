// @vitest-environment jsdom
// The Stacks view against what stack_list, compose_up and compose_down do.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { HealthStatus, PublishedPort } from "@/bindings";
import { TooltipProvider } from "@/components/ui/tooltip";
import type { Stack, StreamMessage } from "@/lib/ipc";

const h = vi.hoisted(() => {
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

import { StacksPage } from "./StacksPage";

const args = (cmd: string) => h.calls.filter((c) => c.cmd === cmd).map((c) => c.args);

function summary(name: string, status: string, health: HealthStatus | null, ports: PublishedPort[] = []) {
  return {
    id: name.padEnd(64, "0"),
    name,
    image: "x",
    image_id: "sha256:x",
    command: [],
    created: "2026-10-03T00:00:00Z",
    state: {
      status,
      pid: null,
      exit_code: 0,
      oom_killed: false,
      error: null,
      started_at: null,
      finished_at: null,
      restart_count: 0,
      health: health && { status: health, failing_streak: 0, log: [] },
    },
    labels: {},
    ports,
    network_mode: "hits_default",
  };
}

const hits = {
  name: "hits",
  working_dir: "/home/u/hits",
  config_files: ["/home/u/hits/compose.yaml"],
  containers: [
    { service: "redis", number: 1, container: summary("hits-redis-1", "running", "healthy") },
    {
      service: "web",
      number: 1,
      container: summary("hits-web-1", "running", "starting", [{ host_ip: "0.0.0.0", host_port: 8000, container_port: 8000, protocol: "tcp" }]),
    },
  ],
} as unknown as Stack;

function mount() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <TooltipProvider>
          <StacksPage />
        </TooltipProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  h.calls.length = 0;
  for (const k of Object.keys(h.handlers)) delete h.handlers[k];
  h.handlers.stack_list = () => [hits];
  h.handlers.stream_cancel = () => true;
});
afterEach(cleanup);

describe("stacks", () => {
  it("show each project with what runs, its services' health and ports", async () => {
    mount();
    const card = await screen.findByTestId("stack");
    expect(card.dataset.name).toBe("hits");
    expect(card.dataset.state).toBe("running");
    expect(within(card).getByTestId("stack-running").textContent).toBe("running 2/2");
    expect(within(card).getByText("1 starting")).toBeTruthy();
    const rows = within(card).getAllByTestId("stack-container");
    expect(rows.map((r) => [r.dataset.service, r.dataset.name, r.dataset.health])).toEqual([
      ["redis", "hits-redis-1", "healthy"],
      ["web", "hits-web-1", "starting"],
    ]);
    expect(within(card).getByText("8000->8000/tcp")).toBeTruthy();
    expect(within(card).getByText("/home/u/hits")).toBeTruthy();
    expect(within(card).getByRole("link", { name: "hits-web-1" }).getAttribute("href")).toBe(`/containers/${"hits-web-1".padEnd(64, "0")}`);
  });

  it("take a project down, with its volumes when asked", async () => {
    h.handlers.compose_down = () => undefined;
    mount();
    fireEvent.click(await screen.findByTestId("stack-down"));
    fireEvent.click(screen.getByLabelText(/Also remove its volumes/));
    fireEvent.click(screen.getByRole("button", { name: "Down" }));
    await waitFor(() => expect(args("compose_down")).toEqual([{ project: "hits", volumes: true }]));
  });

  it("come up again from the files their labels name, under their name and in their directory", async () => {
    let channel: { onmessage: (m: StreamMessage<unknown>) => void } | undefined;
    h.handlers.compose_up = (a) => {
      channel = a.channel;
      return 3;
    };
    mount();
    fireEvent.click(await screen.findByTestId("stack-up"));
    await waitFor(() => expect(args("compose_up").length).toBe(1));
    expect(args("compose_up")[0]).toMatchObject({
      files: ["/home/u/hits/compose.yaml"],
      project_name: "hits",
      project_dir: "/home/u/hits",
    });
    act(() =>
      channel!.onmessage({
        type: "items",
        items: [
          { type: "resource", kind: "network", name: "hits_default", action: "running" },
          { type: "resource", kind: "container", name: "hits-web-1", action: "recreated" },
        ],
      }),
    );
    expect(screen.getByTestId("compose-progress").dataset.phase).toBe("running");
    act(() => channel!.onmessage({ type: "end" }));
    const progress = screen.getByTestId("compose-progress");
    expect(progress.dataset.phase).toBe("done");
    expect(within(progress).getByText("Recreated")).toBeTruthy();
  });

  it("whose containers don't name their file can't come up again from here", async () => {
    h.handlers.stack_list = () => [{ ...hits, working_dir: null, config_files: [] }];
    mount();
    expect(((await screen.findByTestId("stack-up")) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/don't say where it was brought up from/)).toBeTruthy();
  });

  it("say there are none, and how to make one", async () => {
    h.handlers.stack_list = () => [];
    mount();
    expect(await screen.findByText("No stacks yet")).toBeTruthy();
  });
});

describe("up from a file", () => {
  it("loads the file named; one that doesn't load says why, before anything runs", async () => {
    h.handlers.stack_list = () => [];
    h.handlers.compose_up = () => {
      throw { kind: "invalid", message: "compose.yaml: services.web: unknown field `imgae`" };
    };
    mount();
    fireEvent.click(await screen.findByTestId("open-compose-up"));
    fireEvent.change(document.querySelector('input[name="file"]')!, { target: { value: "~/hits/compose.yaml" } });
    fireEvent.click(screen.getByTestId("compose-up-submit"));
    expect((await screen.findByTestId("compose-up-error")).textContent).toContain("unknown field");
    expect(args("compose_up")[0]).toMatchObject({ files: ["~/hits/compose.yaml"], project_name: null, project_dir: null });
    expect(screen.queryByTestId("compose-progress")).toBeNull();
  });

  it("closed while it runs, stops following it and nothing more (the app runs it to its end)", async () => {
    let channel: { onmessage: (m: StreamMessage<unknown>) => void } | undefined;
    h.handlers.compose_up = (a) => {
      channel = a.channel;
      return 9;
    };
    mount();
    fireEvent.click(await screen.findByTestId("open-compose-up"));
    fireEvent.change(document.querySelector('input[name="file"]')!, { target: { value: "/srv/app/compose.yaml" } });
    fireEvent.change(document.querySelector('input[name="project"]')!, { target: { value: "app" } });
    fireEvent.click(screen.getByTestId("compose-up-submit"));
    await waitFor(() => expect(args("compose_up").length).toBe(1));
    expect(args("compose_up")[0]).toMatchObject({ project_name: "app" });
    // The footer's Close (the header's × is the other).
    fireEvent.click(screen.getAllByRole("button", { name: "Close" }).at(-1)!);
    await waitFor(() => expect(args("stream_cancel")).toEqual([{ stream: 9 }]));
    expect(args("compose_down")).toEqual([]);
    // What it still sends goes nowhere.
    act(() => channel!.onmessage({ type: "end" }));
    expect(screen.queryByTestId("compose-progress")).toBeNull();
  });

  it("a failure halfway is the last word", async () => {
    let channel: { onmessage: (m: StreamMessage<unknown>) => void } | undefined;
    h.handlers.compose_up = (a) => {
      channel = a.channel;
      return 4;
    };
    mount();
    fireEvent.click(await screen.findByTestId("stack-up"));
    await waitFor(() => expect(channel).toBeDefined());
    act(() => channel!.onmessage({ type: "items", items: [{ type: "waiting", service: "web", on: "redis", condition: "healthy" }] }));
    act(() => channel!.onmessage({ type: "error", error: { kind: "failed", message: "redis is unhealthy" } }));
    const progress = screen.getByTestId("compose-progress");
    expect(progress.dataset.phase).toBe("error");
    expect(within(progress).getByText("redis is unhealthy")).toBeTruthy();
    expect(within(progress).getByText("web waits for redis to be healthy")).toBeTruthy();
  });
});
