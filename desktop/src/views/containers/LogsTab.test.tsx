// @vitest-environment jsdom
// The logs tab's stream and the log view's layout.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ContainerInspect, LogEntry } from "@/bindings";

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

import { DaemonProvider } from "@/lib/daemon";

import { LogsTab } from "./LogsTab";

const container = {
  id: "c1",
  name: "web",
  state: { status: "running", pid: 42, exit_code: null, oom_killed: false, error: null, started_at: "2026-10-03T00:00:01Z", finished_at: null, restart_count: 0 },
} as unknown as ContainerInspect;

const entry = (log: string, ts = "2026-10-03T00:00:02.000000001Z", stream: LogEntry["stream"] = "stdout"): LogEntry => ({ ts, stream, log });
const called = (cmd: string) => h.calls.filter((c) => c.cmd === cmd);
let channels: { onmessage: (m: unknown) => void }[] = [];
const send = (m: unknown) => act(() => channels[channels.length - 1].onmessage(m));
const status = () => screen.getByTestId("logs-status").textContent;
const rows = () => [...document.querySelectorAll<HTMLElement>("[data-index]")].map((r) => r.textContent);

beforeEach(() => {
  h.calls.length = 0;
  channels = [];
  h.handlers.container_logs = (args) => {
    channels.push(args.channel);
    return channels.length;
  };
  h.handlers.stream_cancel = () => true;
});
afterEach(cleanup);

// A browser's layout, as far as the virtualizer reads it (in jsdom's own,
// it draws no rows): the scroller is 400 px high; a row is 20 px, or 100 px
// when its text wraps (> 200 characters). ResizeObserver reports an element
// once when it is first observed (as browsers do), and again only if its
// size changes.
const height = (el: HTMLElement) =>
  el.dataset.testid === "logs" ? 400 : el.dataset.index != null ? ((el.textContent ?? "").length > 200 ? 100 : 20) : 0;
let restore: (() => void)[] = [];
beforeEach(() => {
  const oh = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetHeight");
  const ow = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetWidth");
  Object.defineProperty(HTMLElement.prototype, "offsetHeight", { configurable: true, get() { return height(this); } });
  Object.defineProperty(HTMLElement.prototype, "offsetWidth", { configurable: true, get() { return 800; } });
  const RO = globalThis.ResizeObserver;
  globalThis.ResizeObserver = class {
    constructor(private cb: ResizeObserverCallback) {}
    observe(el: Element) {
      setTimeout(() => {
        const h = height(el as HTMLElement);
        this.cb([{ target: el, borderBoxSize: [{ blockSize: h, inlineSize: 800 }], contentRect: { height: h, width: 800 } } as unknown as ResizeObserverEntry], this as unknown as ResizeObserver);
      }, 0);
    }
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
  restore = [
    () => oh && Object.defineProperty(HTMLElement.prototype, "offsetHeight", oh),
    () => ow && Object.defineProperty(HTMLElement.prototype, "offsetWidth", ow),
    () => (globalThis.ResizeObserver = RO),
  ];
});
afterEach(() => restore.forEach((f) => f()));

describe("a line of output longer than 16 KiB", () => {
  it("is one line in the view, as `rustlet logs` prints it, at the time of its first piece", async () => {
    render(<LogsTab container={container} />);
    await waitFor(() => expect(channels.length).toBe(1));
    // The shim cuts a line at MAX_LINE (16 KiB) into entries; only the last
    // has the newline (rustlet-spec logs.rs, shim logfile.rs LineSplitter).
    // Each stream's pieces are its own.
    const long = "x".repeat(16 * 1024);
    await send({
      type: "items",
      items: [
        entry(long, "2026-10-03T00:00:02.000000001Z"),
        entry("oops\n", "2026-10-03T00:00:03.000000001Z", "stderr"),
        entry("yyy\n", "2026-10-03T00:00:04.000000001Z"),
      ],
    });
    expect(status()).toContain(" 2 lines");
    fireEvent.click(screen.getByLabelText("Timestamps"));
    await waitFor(() => expect(rows()).toContain(`2026-10-03 00:00:02.000${long}yyy`));
    expect(rows()).toContain("2026-10-03 00:00:03.000oops");
  });

  it("the last output before an exit shows though it has no newline", async () => {
    render(<LogsTab container={container} />);
    await waitFor(() => expect(channels.length).toBe(1));
    await send({ type: "items", items: [entry("hello\n"), entry("bye")] });
    expect(status()).toContain(" 1 lines");
    await send({ type: "end" });
    expect(status()).toContain(" 2 lines");
  });

  it("shows bounded output with a truncation notice and keeps a partial line on disconnection", async () => {
    render(<LogsTab container={container} />);
    await waitFor(() => expect(channels.length).toBe(1));
    await send({ type: "items", items: Array.from({ length: 8 }, () => entry("x".repeat(16 * 1024))) });
    await send({ type: "error", error: { kind: "failed", message: "connection closed" } });
    await waitFor(() => expect(rows()[0]).toContain("[65536 characters not kept]"));
    expect(rows()[0]!.length).toBeLessThan(66_000);
    expect(status()).toContain(" 1 lines");
  });
});

describe("rustletd restarting while the container runs", () => {
  let watch: { onmessage: (m: unknown) => void } | undefined;
  const connected = { type: "connected", socket: "/run/rustlet/rustlet.sock", version: { version: "0.1.0" } };
  beforeEach(() => {
    h.handlers.daemon_watch = (args) => {
      watch = args.channel;
      return 99;
    };
  });
  function withDaemon(children: ReactNode) {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(
      <QueryClientProvider client={client}>
        <DaemonProvider>{children}</DaemonProvider>
      </QueryClientProvider>,
    );
  }
  const daemon = (m: unknown) => act(() => watch!.onmessage(m));

  it("follows again once the daemon is back, from the tail, showing no line twice", async () => {
    withDaemon(<LogsTab container={container} />);
    await waitFor(() => expect(watch).toBeDefined());
    await daemon(connected);
    await waitFor(() => expect(channels.length).toBe(1));
    await send({ type: "items", items: [entry("hello\n")] });
    await send({ type: "error", error: { kind: "failed", message: "connection closed before message completed" } });
    await daemon({ type: "disconnected", socket: "/run/rustlet/rustlet.sock", error: { kind: "unreachable", message: "connection refused" } });
    expect(called("container_logs").length).toBe(1);
    await daemon(connected);
    await waitFor(() => expect(called("container_logs").length).toBe(2));
    expect(called("container_logs")[1].args.query).toMatchObject({ follow: true, tail: 1000 });
    await send({ type: "items", items: [entry("hello\n"), entry("again\n")] });
    expect(rows()).toEqual(["hello", "again"]);
    expect(status()).toContain("following");
  });

  it("a stream that wasn't cut stays as it is", async () => {
    withDaemon(<LogsTab container={container} />);
    await waitFor(() => expect(watch).toBeDefined());
    await daemon(connected);
    await waitFor(() => expect(channels.length).toBe(1));
    await daemon(connected);
    await new Promise((r) => setTimeout(r, 20));
    expect(called("container_logs").length).toBe(1);
  });

  it("follows again when the old stream ends after the daemon already reconnected", async () => {
    withDaemon(<LogsTab container={container} />);
    await waitFor(() => expect(watch).toBeDefined());
    await daemon(connected);
    await waitFor(() => expect(channels.length).toBe(1));
    await daemon(connected);
    await send({ type: "end" });
    await waitFor(() => expect(called("container_logs")).toHaveLength(2));
  });
});

describe("the virtualized log after a filter", () => {
  const top = (text: string) => {
    const row = [...document.querySelectorAll<HTMLElement>("[data-index]")].find((r) => r.textContent?.includes(text));
    return row?.style.transform;
  };

  it("places each row below the one before it", async () => {
    render(<LogsTab container={container} />);
    await waitFor(() => expect(channels.length).toBe(1));
    await send({ type: "items", items: [entry("alpha one\n"), entry("x".repeat(300) + " keep\n"), entry("keep gamma\n")] });
    // Unfiltered: 0, 20, 120.
    await waitFor(() => expect(top("keep gamma")).toBe("translateY(120px)"));
    fireEvent.change(screen.getByPlaceholderText("Filter lines"), { target: { value: "keep" } });
    await new Promise((r) => setTimeout(r, 50));
    // Filtered: the long line first (0 to 100), then "keep gamma" at 100.
    expect(top(" keep")).toBe("translateY(0px)");
    expect(top("keep gamma")).toBe("translateY(100px)");
  });
});
