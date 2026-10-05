// @vitest-environment jsdom
// Review: a stack's Up dialog when the file its labels name is changed.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { TooltipProvider } from "@/components/ui/tooltip";
import type { Stack } from "@/lib/ipc";

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

const hits = {
  name: "hits",
  working_dir: "/home/u/hits",
  config_files: ["/home/u/hits/compose.yaml"],
  containers: [
    {
      service: "redis",
      number: 1,
      container: {
        id: "r".padEnd(64, "0"),
        name: "hits-redis-1",
        image: "redis:7-alpine",
        image_id: "sha256:x",
        command: [],
        created: "2026-10-04T00:00:00Z",
        state: {
          status: "exited",
          pid: null,
          exit_code: 0,
          oom_killed: false,
          error: null,
          started_at: null,
          finished_at: null,
          restart_count: 0,
          health: null,
        },
        labels: {},
        ports: [],
        network_mode: "hits_default",
      },
    },
  ],
} as unknown as Stack;

beforeEach(() => {
  h.calls.length = 0;
  for (const k of Object.keys(h.handlers)) delete h.handlers[k];
  h.handlers.stack_list = () => [hits];
  h.handlers.stream_cancel = () => true;
});
afterEach(cleanup);

describe("a stack's Up", () => {
  // Expected: the file field's own hint says "Its directory is the
  // project's: paths and .env are read from there" (ComposeUpDialog.tsx),
  // and compose_up without project_dir takes the first file's directory
  // (src-tauri/src/commands.rs, compose_up: "rooted at project_dir if
  // given …; else the first file's directory"). The project moved to
  // ~/src/hits: Up from its card fails (its label names the old file), the
  // user types the new path, and presses Up again. The dialog still sends
  // the old project_dir from the stack's label (`projectDir:
  // request.projectDir`), so the new file is loaded as a project rooted in
  // /home/u/hits: its build contexts, bind mounts and .env are looked for
  // there.
  it("with another file typed, roots the project in that file's directory, not the old one", async () => {
    h.handlers.compose_up = () => {
      throw { kind: "failed", message: "/home/u/hits/compose.yaml: No such file or directory (os error 2)" };
    };
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter>
          <TooltipProvider>
            <StacksPage />
          </TooltipProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(await screen.findByTestId("stack-up"));
    await screen.findByTestId("compose-up-error");
    h.handlers.compose_up = () => 7;
    fireEvent.change(document.querySelector('input[name="file"]')!, { target: { value: "/home/u/src/hits/compose.yaml" } });
    fireEvent.click(screen.getByTestId("compose-up-submit"));
    await waitFor(() => expect(args("compose_up")).toHaveLength(2));
    expect(args("compose_up")[1].files).toEqual(["/home/u/src/hits/compose.yaml"]);
    expect(args("compose_up")[1].project_dir).not.toBe("/home/u/hits");
  });
});
