// @vitest-environment jsdom
import { QueryClient, QueryObserver } from "@tanstack/react-query";
import { describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ Channel: class {}, invoke: vi.fn(() => new Promise(() => {})) }));
// The views aren't what this is about (and the toaster wants matchMedia).
vi.mock("./App", () => ({ App: () => null }));
vi.mock("sonner", () => ({ Toaster: () => null }));

document.body.innerHTML = '<div id="root"></div>';
await import("./main");

/** Fetches of a stale query as `event` comes to the window. */
async function fetchesOn(event: string): Promise<number> {
  let fetches = 0;
  const client = new QueryClient({ defaultOptions: { queries: { staleTime: 0, retry: false } } });
  client.mount(); // as QueryClientProvider does
  const observer = new QueryObserver(client, { queryKey: ["container", "web"], queryFn: async () => ++fetches });
  const unsubscribe = observer.subscribe(() => {});
  await new Promise((r) => setTimeout(r, 0));
  window.dispatchEvent(new Event(event));
  await new Promise((r) => setTimeout(r, 0));
  unsubscribe();
  client.unmount();
  return fetches;
}

describe("refetch on focus", () => {
  it("a window focus refetches, the document having stayed visible", async () => {
    // The user comes back from a terminal where they ran `rustlet stop`.
    expect(await fetchesOn("focus")).toBe(2);
  });

  it("so does a visibilitychange", async () => {
    expect(await fetchesOn("visibilitychange")).toBe(2);
  });
});
