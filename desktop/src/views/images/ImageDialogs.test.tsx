// @vitest-environment jsdom
// The tag, save and load dialogs against their commands.

import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { LoadEvent } from "@/bindings";
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

import { LoadDialog, SaveDialog, TagDialog } from "./ImageDialogs";

const args = (cmd: string) => h.calls.filter((c) => c.cmd === cmd).map((c) => c.args);
const field = (name: string) => document.querySelector(`input[name="${name}"]`) as HTMLInputElement;

beforeEach(() => {
  h.calls.length = 0;
  for (const k of Object.keys(h.handlers)) delete h.handlers[k];
});
afterEach(cleanup);

describe("repeated form submissions", () => {
  it.each(["tag", "save", "load"])("starts only one %s while its command is pending", async (operation) => {
    const command = `image_${operation}`;
    h.handlers[command] = () => new Promise(() => {});
    render(
      <MemoryRouter>
        {operation === "tag" ? <TagDialog open source="hits" onOpenChange={() => {}} /> :
          operation === "save" ? <SaveDialog open names={["hits"]} onOpenChange={() => {}} /> :
          <LoadDialog open onOpenChange={() => {}} />}
      </MemoryRouter>,
    );
    const input = field(operation === "tag" ? "target" : "path");
    fireEvent.change(input, { target: { value: operation === "tag" ? "hits:new" : "~/hits.tar" } });
    fireEvent.click(screen.getByTestId(`${operation}-submit`));
    await waitFor(() => expect(args(command)).toHaveLength(1));
    fireEvent.submit(input.closest("form")!);
    await act(async () => {});
    expect(args(command)).toHaveLength(1);
  });
});

describe("tag", () => {
  it("gives the image the name typed", async () => {
    h.handlers.image_tag = () => undefined;
    const closes: boolean[] = [];
    render(<TagDialog open source="docker.io/library/hits:latest" onOpenChange={(o) => closes.push(o)} />);
    expect(screen.getByText("Tag hits:latest")).toBeTruthy();
    fireEvent.change(field("target"), { target: { value: " hits:1.0 " } });
    fireEvent.click(screen.getByTestId("tag-submit"));
    await waitFor(() => expect(closes).toEqual([false]));
    expect(args("image_tag")).toEqual([{ source: "docker.io/library/hits:latest", target: "hits:1.0" }]);
  });

  it("says why the daemon refused, and stays open", async () => {
    h.handlers.image_tag = () => {
      throw { kind: "invalid", message: 'invalid reference "Hits": repository names must be lowercase' };
    };
    render(<TagDialog open source="hits" onOpenChange={() => {}} />);
    fireEvent.change(field("target"), { target: { value: "Hits" } });
    fireEvent.click(screen.getByTestId("tag-submit"));
    expect((await screen.findByTestId("tag-error")).textContent).toMatch(/must be lowercase/);
  });
});

describe("save", () => {
  it("saves the images named into the file typed", async () => {
    h.handlers.image_save = () => 46_137_344;
    const closes: boolean[] = [];
    render(<SaveDialog open names={["docker.io/library/hits:latest"]} onOpenChange={(o) => closes.push(o)} />);
    expect(field("images").value).toBe("docker.io/library/hits:latest");
    fireEvent.change(field("images"), { target: { value: "docker.io/library/hits:latest, redis:7-alpine" } });
    fireEvent.change(field("path"), { target: { value: "~/hits.tar" } });
    fireEvent.click(screen.getByTestId("save-submit"));
    await waitFor(() => expect(closes).toEqual([false]));
    expect(args("image_save")).toEqual([{ names: ["docker.io/library/hits:latest", "redis:7-alpine"], path: "~/hits.tar" }]);
  });

  it("a file that exists is the user's to rename", async () => {
    h.handlers.image_save = () => {
      throw { kind: "invalid", message: "/home/u/hits.tar already exists: choose another name" };
    };
    render(<SaveDialog open names={["hits"]} onOpenChange={() => {}} />);
    fireEvent.change(field("path"), { target: { value: "~/hits.tar" } });
    fireEvent.click(screen.getByTestId("save-submit"));
    expect((await screen.findByTestId("save-error")).textContent).toMatch(/already exists/);
  });
});

describe("load", () => {
  it("streams the load, listing each image as it is loaded", async () => {
    let channel: { onmessage: (m: StreamMessage<LoadEvent>) => void } | undefined;
    h.handlers.image_load = (a) => {
      channel = a.channel;
      return 2;
    };
    render(
      <MemoryRouter>
        <LoadDialog open onOpenChange={() => {}} />
      </MemoryRouter>,
    );
    fireEvent.change(field("path"), { target: { value: "~/hits.tar" } });
    fireEvent.click(screen.getByTestId("load-submit"));
    await waitFor(() => expect(channel).toBeDefined());
    expect(args("image_load")[0]).toMatchObject({ path: "~/hits.tar" });
    act(() =>
      channel!.onmessage({
        type: "items",
        items: [
          { status: "blob", digest: "sha256:a", size: 2048, existed: false },
          { status: "loaded", id: `sha256:${"c".repeat(64)}`, name: "docker.io/library/hits:latest" },
          { status: "loaded", id: `sha256:${"d".repeat(64)}`, name: null },
        ],
      }),
    );
    act(() => channel!.onmessage({ type: "end" }));
    const progress = screen.getByTestId("load-progress");
    expect(progress.dataset.phase).toBe("done");
    expect(progress.textContent).toContain("1 blob (2.0 KiB)");
    expect(screen.getByRole("link", { name: "hits:latest" }).getAttribute("href")).toBe("/images/docker.io%2Flibrary%2Fhits%3Alatest");
    expect(screen.getByText("dddddddddddd (unnamed)")).toBeTruthy();
  });

  it("a load that fails says why", async () => {
    let channel: { onmessage: (m: StreamMessage<LoadEvent>) => void } | undefined;
    h.handlers.image_load = (a) => {
      channel = a.channel;
      return 2;
    };
    render(
      <MemoryRouter>
        <LoadDialog open onOpenChange={() => {}} />
      </MemoryRouter>,
    );
    fireEvent.change(field("path"), { target: { value: "/tmp/x.tar" } });
    fireEvent.click(screen.getByTestId("load-submit"));
    await waitFor(() => expect(channel).toBeDefined());
    act(() => channel!.onmessage({ type: "error", error: { kind: "failed", message: "sha256:a: digest mismatch" } }));
    expect(screen.getByTestId("load-progress").dataset.phase).toBe("error");
    expect(screen.getByText("sha256:a: digest mismatch")).toBeTruthy();
  });
});
