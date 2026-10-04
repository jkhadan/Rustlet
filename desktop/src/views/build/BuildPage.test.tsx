// @vitest-environment jsdom
// The Build view against what image_build streams.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { BuildEvent } from "@/bindings";
import type { StreamMessage } from "@/lib/ipc";

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

import { BuildPage } from "./BuildPage";
import { clearBuild } from "./session";

const args = (cmd: string) => h.calls.filter((c) => c.cmd === cmd).map((c) => c.args);
const field = (name: string) => document.querySelector(`[name="${name}"]`) as HTMLInputElement;

let channel: { onmessage: (m: StreamMessage<BuildEvent>) => void } | undefined;
const send = (items: BuildEvent[]) => act(() => channel!.onmessage({ type: "items", items }));

function mount(client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <BuildPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Fills the context and presses Build; resolves once image_build is called. */
async function build(context = "~/src/hits") {
  fireEvent.change(field("context"), { target: { value: context } });
  fireEvent.click(screen.getByTestId("build-submit"));
  await waitFor(() => expect(channel).toBeDefined());
}

beforeEach(() => {
  clearBuild();
  channel = undefined;
  h.calls.length = 0;
  for (const k of Object.keys(h.handlers)) delete h.handlers[k];
  h.handlers.network_list = () => [];
  h.handlers.stream_cancel = () => true;
  h.handlers.image_build = (a) => {
    channel = a.channel;
    return 5;
  };
});
afterEach(cleanup);

const start: BuildEvent[] = [
  { type: "context", files: 3, bytes: 1200 },
  { type: "stage", index: 0, name: null, base: "python:3-slim" },
  { type: "step", step: 1, total: 2, instruction: "FROM python:3-slim" },
  { type: "step_done", step: 1, layer: null },
  { type: "step", step: 2, total: 2, instruction: "RUN pip install redis" },
  { type: "output", step: 2, stream: "stdout", text: "\x1b[32mSuccessfully installed redis\x1b[0m\n" },
];

describe("the build view", () => {
  it("builds what the form says, the rest left to the API's defaults", async () => {
    mount();
    fireEvent.change(field("tags"), { target: { value: "hits:latest, hits:1" } });
    fireEvent.change(field("build-args"), { target: { value: "V=1\nGREETING=hi there" } });
    fireEvent.change(field("containerfile"), { target: { value: "build/Containerfile" } });
    fireEvent.click(screen.getByLabelText(/No cache/));
    await build();
    expect(args("image_build")[0]).toMatchObject({
      context: "~/src/hits",
      containerfile: "build/Containerfile",
      options: {
        tags: ["hits:latest", "hits:1"],
        build_args: { V: "1", GREETING: "hi there" },
        target: null,
        no_cache: true,
        pull: "missing",
        network: "bridge",
      },
    });
    expect(args("image_build")[0].options.dockerfile).toBeUndefined();
  });

  it("shows each step as it comes, a RUN's output coloured, and the image it made", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    client.setQueryData(["images"], []);
    mount(client);
    await build();
    expect(screen.getByTestId("build-progress").dataset.phase).toBe("sending");
    send(start);
    expect(screen.getAllByTestId("build-step").map((s) => s.dataset.state)).toEqual(["done", "running"]);
    // The running step shows its output, coloured as the terminal would.
    const out = screen.getByTestId("build-output");
    expect(out.textContent).toContain("Successfully installed redis");
    expect(out.querySelector("span[style*='color']")).not.toBeNull();
    send([
      { type: "step_done", step: 2, layer: `sha256:${"a".repeat(64)}` },
      { type: "done", id: `sha256:${"b".repeat(64)}`, names: ["docker.io/library/hits:latest"] },
    ]);
    act(() => channel!.onmessage({ type: "end" }));
    expect(screen.getByTestId("build-progress").dataset.phase).toBe("done");
    expect(screen.getByText("layer aaaaaaaaaaaa")).toBeTruthy();
    const result = screen.getByTestId("build-result");
    expect(within(result).getByRole("link").getAttribute("href")).toBe("/images/docker.io%2Flibrary%2Fhits%3Alatest");
    // An image built without a name gets no event: the list is told here.
    expect(client.getQueryState(["images"])?.isInvalidated).toBe(true);
  });

  it("a step that fails shows the daemon's error, the step marked, its output open", async () => {
    mount();
    await build();
    send(start);
    act(() =>
      channel!.onmessage({
        type: "error",
        error: { kind: "failed", message: "The command '/bin/sh -c pip install redis' returned a non-zero code: 1" },
      }),
    );
    expect(screen.getByTestId("build-progress").dataset.phase).toBe("error");
    expect(screen.getByTestId("build-error").textContent).toMatch(/non-zero code: 1/);
    expect(screen.getAllByTestId("build-step").map((s) => s.dataset.state)).toEqual(["done", "failed"]);
    expect(screen.getByTestId("build-output").textContent).toContain("Successfully installed redis");
  });

  it("a context the app can't use is refused, with the app's reason", async () => {
    h.handlers.image_build = () => {
      throw { kind: "invalid", message: "/home/u/src/nope: No such file or directory (os error 2)" };
    };
    mount();
    fireEvent.change(field("context"), { target: { value: "~/src/nope" } });
    fireEvent.click(screen.getByTestId("build-submit"));
    expect((await screen.findByTestId("build-error")).textContent).toMatch(/No such file/);
  });

  it("a build arg without a value is refused before anything is sent", async () => {
    mount();
    fireEvent.change(field("build-args"), { target: { value: "HTTP_PROXY" } });
    fireEvent.change(field("context"), { target: { value: "~/src/hits" } });
    fireEvent.click(screen.getByTestId("build-submit"));
    expect(screen.getByTestId("build-form-error").textContent).toBe('build arg "HTTP_PROXY": give KEY=VALUE');
    expect(args("image_build")).toEqual([]);
  });

  it("Stop cancels the build's stream; what comes after is ignored", async () => {
    mount();
    await build();
    send(start);
    fireEvent.click(screen.getByTestId("build-stop"));
    await waitFor(() => expect(args("stream_cancel")).toEqual([{ stream: 5 }]));
    expect(screen.getByTestId("build-progress").dataset.phase).toBe("stopped");
    send([{ type: "step", step: 3, total: 3, instruction: "COPY . ." }]);
    expect(screen.getAllByTestId("build-step")).toHaveLength(2);
  });

  it("goes on while the view is away, and is there when it comes back", async () => {
    const view = mount();
    await build();
    view.unmount();
    send(start);
    expect(args("stream_cancel")).toEqual([]);
    mount();
    expect(screen.getAllByTestId("build-step")).toHaveLength(2);
    // The form is as it was submitted.
    expect(field("context").value).toBe("~/src/hits");
  });
});
