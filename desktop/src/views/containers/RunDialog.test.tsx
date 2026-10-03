// @vitest-environment jsdom
// The run dialog against what `rustlet run` does for the same input.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

import { RunDialog } from "./RunDialog";

function dialog(client: QueryClient, open: boolean, onOpenChange: (o: boolean) => void = () => {}) {
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <RunDialog open={open} onOpenChange={onOpenChange} />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function mount(onOpenChange?: (o: boolean) => void) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(dialog(client, true, onOpenChange));
  // ContainersPage keeps the dialog mounted and only flips `open`.
  const reopen = () => {
    view.rerender(dialog(client, false, onOpenChange));
    view.rerender(dialog(client, true, onOpenChange));
  };
  return { reopen };
}

const field = (selector: string) => document.querySelector(selector) as HTMLInputElement;
const called = (cmd: string) => h.calls.filter((c) => c.cmd === cmd);

beforeEach(() => {
  h.calls.length = 0;
  for (const k of Object.keys(h.handlers)) delete h.handlers[k];
  h.handlers.image_list = () => [];
  h.handlers.network_list = () => [];
  h.handlers.parse_run_options = () => ({ ports: [], mounts: [] });
});
afterEach(cleanup);

describe("volumes are handed to the CLI's parser as the CLI gets them", () => {
  it("a -v value with an option list (ro,nocopy) stays one value", async () => {
    mount();
    fireEvent.change(field('input[name="image"]'), { target: { value: "alpine" } });
    fireEvent.change(field('textarea[placeholder="data:/data"]'), { target: { value: "cache:/var/cache:ro,nocopy\n/srv:/srv" } });
    fireEvent.change(field('textarea[placeholder="8080:80"]'), { target: { value: "8080:80, 8443:443" } });
    h.handlers.container_create = () => ({ id: "c1", name: "x", warnings: [] });
    h.handlers.container_start = () => undefined;
    fireEvent.click(screen.getByTestId("run-submit"));
    await waitFor(() => expect(called("parse_run_options").length).toBe(1));
    // `rustlet run -v cache:/var/cache:ro,nocopy` is one -v value; ports
    // can't hold a comma, so it may separate them.
    expect(called("parse_run_options")[0].args).toEqual({ ports: ["8080:80", "8443:443"], volumes: ["cache:/var/cache:ro,nocopy", "/srv:/srv"] });
  });
});

describe("a start that fails after the create", () => {
  beforeEach(() => {
    // The daemon's names: one in use until its container is removed.
    const names = new Map<string, string>();
    h.handlers.container_create = ({ config }) => {
      if ([...names.values()].includes(config.name)) {
        throw { kind: "conflict", message: `the container name "${config.name}" is already in use` };
      }
      const id = `c${names.size + 1}`;
      names.set(id, config.name);
      return { id, name: config.name, warnings: [] };
    };
    h.handlers.container_start = () => {
      throw { kind: "invalid", message: '-e "FOO": give a value (FOO=…); there is no client environment to copy it from' };
    };
    h.handlers.container_remove = ({ id }) => void names.delete(id);
  });

  it("with --rm, removes the container that never ran (as `rustlet run --rm -d` does) and shows the start's error", async () => {
    mount();
    fireEvent.change(field('input[name="image"]'), { target: { value: "alpine" } });
    fireEvent.change(field('input[name="name"]'), { target: { value: "web" } });
    fireEvent.change(field('textarea[placeholder="POSTGRES_PASSWORD=secret"]'), { target: { value: "FOO" } });
    fireEvent.click(screen.getByLabelText("Remove when it exits (--rm)"));
    fireEvent.click(screen.getByTestId("run-submit"));
    await screen.findByText(/give a value/);
    expect(called("container_remove")).toEqual([{ cmd: "container_remove", args: { id: "c1", force: true, volumes: true } }]);
  });

  it("fixing the input and pressing Run again works", async () => {
    mount();
    fireEvent.change(field('input[name="image"]'), { target: { value: "alpine" } });
    fireEvent.change(field('input[name="name"]'), { target: { value: "web" } });
    fireEvent.change(field('textarea[placeholder="POSTGRES_PASSWORD=secret"]'), { target: { value: "FOO" } });
    fireEvent.click(screen.getByTestId("run-submit"));
    await screen.findByText(/give a value/);
    h.handlers.container_start = () => undefined;
    fireEvent.change(field('textarea[placeholder="POSTGRES_PASSWORD=secret"]'), { target: { value: "FOO=1" } });
    await waitFor(() => expect((screen.getByTestId("run-submit") as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByTestId("run-submit"));
    await waitFor(() => expect(called("container_start").length).toBe(2));
    expect(called("container_create").length).toBe(2);
    expect(screen.queryByTestId("run-error")).toBeNull();
  });
});

describe("closing", () => {
  it("with Cancel starts the next opening afresh, as closing with Escape or X does", async () => {
    h.handlers.container_create = () => {
      throw { kind: "invalid", message: "--rm and a restart policy contradict each other" };
    };
    const { reopen } = mount();
    fireEvent.change(field('input[name="image"]'), { target: { value: "alpine" } });
    fireEvent.click(screen.getByTestId("run-submit"));
    await screen.findByTestId("run-error");
    fireEvent.click(screen.getByText("Cancel"));
    reopen();
    expect(screen.queryByTestId("run-error")).toBeNull();
    expect(field('input[name="image"]').value).toBe("");
  });

  it("works during a pull, which rustletd goes on with; its progress stops coming", async () => {
    h.handlers.container_create = () => {
      throw { kind: "no_such_image", message: "no such image: nginx" };
    };
    let channel: { onmessage: (m: unknown) => void } | undefined;
    let started: (id: number) => void = () => {};
    h.handlers.image_pull = (args) => {
      channel = args.channel;
      return new Promise<number>((resolve) => (started = resolve));
    };
    h.handlers.stream_cancel = () => true;
    const closes: boolean[] = [];
    const { reopen } = mount((o) => closes.push(o));
    fireEvent.change(field('input[name="image"]'), { target: { value: "nginx" } });
    fireEvent.click(screen.getByTestId("run-submit"));
    await waitFor(() => expect(called("image_pull").length).toBe(1));
    fireEvent.click(screen.getByText("Cancel"));
    expect(closes).toEqual([false]);
    // The stream's id comes after the close: it is cancelled then.
    await act(async () => started(7));
    await waitFor(() => expect(called("stream_cancel").map((c) => c.args)).toEqual([{ stream: 7 }]));
    act(() => channel!.onmessage({ type: "end" }));
    reopen();
    await new Promise((r) => setTimeout(r, 50));
    expect(called("container_create").length).toBe(1);
    expect(screen.queryByTestId("pull-progress")).toBeNull();
    expect(screen.queryByTestId("run-error")).toBeNull();
  });
});

describe("a pull that fails", () => {
  it("leaves the progress saying it failed, not still asking the registry", async () => {
    h.handlers.container_create = () => {
      throw { kind: "no_such_image", message: "no such image: ngnix" };
    };
    h.handlers.image_pull = (args) => {
      setTimeout(() => {
        args.channel.onmessage({ type: "items", items: [{ status: "resolving", reference: "ngnix" }] });
        // rustlet-client turns the daemon's `error` event into the stream's
        // error (client lib.rs `pull`), so this is how a failed pull ends.
        args.channel.onmessage({ type: "error", error: { kind: "failed", message: "registry: manifest unknown" } });
      }, 0);
      return 7;
    };
    mount();
    fireEvent.change(field('input[name="image"]'), { target: { value: "ngnix" } });
    fireEvent.click(screen.getByTestId("run-submit"));
    await screen.findByTestId("run-error");
    expect(screen.getByTestId("pull-progress").dataset.phase).toBe("error");
  });
});
