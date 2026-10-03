// @vitest-environment jsdom
// The terminal tab's session against what xterm.js reports.

import { act, cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ContainerInspect } from "@/bindings";

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
  type Cb<T> = (v: T) => void;
  class FakeTerminal {
    static all: FakeTerminal[] = [];
    rows = 24;
    cols = 80;
    disposed = false;
    data: Cb<string>[] = [];
    binary: Cb<string>[] = [];
    resizes: Cb<{ rows: number; cols: number }>[] = [];
    constructor() {
      FakeTerminal.all.push(this);
    }
    loadAddon() {}
    open() {}
    focus() {}
    write() {}
    dispose() {
      this.disposed = true;
    }
    onData(cb: Cb<string>) {
      this.data.push(cb);
      return { dispose() {} };
    }
    onBinary(cb: Cb<string>) {
      this.binary.push(cb);
      return { dispose() {} };
    }
    onResize(cb: Cb<{ rows: number; cols: number }>) {
      this.resizes.push(cb);
      return { dispose() {} };
    }
    /** What the fit addon does when the pane changes size. */
    resize(cols: number, rows: number) {
      this.cols = cols;
      this.rows = rows;
      this.resizes.forEach((cb) => cb({ rows, cols }));
    }
    /** A keystroke, or a paste. */
    type(text: string) {
      this.data.forEach((cb) => cb(text));
    }
  }
  return { handlers, calls, Channel, invoke, FakeTerminal };
});
vi.mock("@tauri-apps/api/core", () => ({ Channel: h.Channel, invoke: h.invoke }));
vi.mock("@xterm/xterm", () => ({ Terminal: h.FakeTerminal }));
vi.mock("@xterm/addon-fit", () => ({ FitAddon: class { fit() {} } }));

import { TerminalTab } from "./TerminalTab";

const container = (status = "running") => ({ id: "c1", name: "web", state: { status } }) as unknown as ContainerInspect;
const called = (cmd: string) => h.calls.filter((c) => c.cmd === cmd);
const utf8 = (s: string) => [...new TextEncoder().encode(s)];
let opened: (id: number) => void = () => {};

beforeEach(() => {
  h.calls.length = 0;
  h.FakeTerminal.all = [];
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
  // The exec's create and start take a round trip or two.
  h.handlers.terminal_open = () => new Promise<number>((resolve) => (opened = resolve));
  h.handlers.terminal_input = () => undefined;
  h.handlers.terminal_resize = () => undefined;
  h.handlers.terminal_close = () => undefined;
});
afterEach(cleanup);

async function start() {
  const view = render(<TerminalTab container={container()} running />);
  await waitFor(() => expect(called("terminal_open").length).toBe(1));
  return { view, term: h.FakeTerminal.all[h.FakeTerminal.all.length - 1] };
}

describe("while the shell is starting", () => {
  it("a resize reaches the session once it is open", async () => {
    const { term } = await start();
    expect(called("terminal_open")[0].args).toMatchObject({ rows: 24, cols: 80 });
    act(() => term.resize(120, 40)); // the window grows, or the web font loads
    await act(async () => opened(5));
    await waitFor(() => expect(called("terminal_resize").map((c) => c.args)).toContainEqual({ session: 5, rows: 40, cols: 120 }));
  });

  it("what is typed reaches the shell once it is open, in order", async () => {
    const { term } = await start();
    act(() => term.type("ls"));
    act(() => term.type(" -l\r"));
    await act(async () => opened(5));
    // The first keystroke's call waited for the session; what came after
    // it, for that call.
    await waitFor(() => expect(called("terminal_input").length).toBe(2));
    expect(called("terminal_input").map((c) => c.args)).toEqual([
      { session: 5, data: utf8("ls") },
      { session: 5, data: utf8(" -l\r") },
    ]);
  });
});

describe("binary input (xterm's onBinary: X10 mouse reports past column 95)", () => {
  it("reaches the PTY as the bytes xterm meant", async () => {
    const { term } = await start();
    await act(async () => opened(5));
    // A left click at column 130, row 2: ESC [ M, then 32+0, 32+130, 32+2,
    // one byte each, in a "binary string" (xterm.js docs for onBinary).
    const report = "\x1b[M" + String.fromCharCode(32, 32 + 130, 32 + 2);
    act(() => term.binary.forEach((cb) => cb(report)));
    await waitFor(() => expect(called("terminal_input").length).toBe(1));
    // terminal_input takes a Vec<u8>: JSON numbers, written as they are.
    expect(called("terminal_input")[0].args.data).toEqual([0x1b, 0x5b, 0x4d, 32, 162, 34]);
  });
});

describe("pausing the container", () => {
  it("keeps the shell: its session stays open and what is typed still goes to it", async () => {
    const { view, term } = await start();
    await act(async () => opened(5));
    view.rerender(<TerminalTab container={container("paused")} running />);
    expect(document.querySelector('[data-testid="terminal-state"]')?.textContent).toContain("paused");
    act(() => term.type("make\r"));
    await waitFor(() => expect(called("terminal_input").map((c) => c.args)).toEqual([{ session: 5, data: utf8("make\r") }]));
    view.rerender(<TerminalTab container={container()} running />);
    await new Promise((r) => setTimeout(r, 20));
    expect(called("terminal_close")).toEqual([]);
    expect(called("terminal_open").length).toBe(1);
    expect(h.FakeTerminal.all.map((t) => t.disposed)).toEqual([false]);
  });

  it("a tab opened while it is paused starts its shell when it resumes", async () => {
    const view = render(<TerminalTab container={container("paused")} running />);
    await new Promise((r) => setTimeout(r, 20));
    expect(called("terminal_open")).toEqual([]);
    view.rerender(<TerminalTab container={container()} running />);
    await waitFor(() => expect(called("terminal_open").length).toBe(1));
  });
});
