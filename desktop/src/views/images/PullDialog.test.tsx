// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

const calls: [string, unknown][] = [];
let answerPull: (id: number) => void = () => {};
let deliver: (m: unknown) => void = () => {};

vi.mock("@tauri-apps/api/core", () => ({
  Channel: class {
    constructor(onmessage: (m: unknown) => void) {
      deliver = onmessage;
    }
  },
  invoke: vi.fn((cmd: string, args: unknown) => {
    calls.push([cmd, args]);
    if (cmd === "image_pull") return new Promise<number>((r) => (answerPull = r));
    return Promise.resolve(true);
  }),
}));

const { PullDialog } = await import("./PullDialog");

afterEach(() => {
  cleanup();
  calls.length = 0;
});

function pullAlpine() {
  let open = true;
  const onOpenChange = (o: boolean) => (open = o);
  const view = render(<PullDialog open={open} onOpenChange={onOpenChange} />);
  fireEvent.change(screen.getByPlaceholderText(/nginx/), { target: { value: "alpine" } });
  fireEvent.click(screen.getByTestId("pull-submit"));
  return { rerender: () => view.rerender(<PullDialog open={open} onOpenChange={onOpenChange} />), reopen: () => (open = true) };
}

describe("the pull dialog", () => {
  it("says a close leaves the pull to rustletd, which runs it to the end", () => {
    pullAlpine();
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
    expect(screen.getByText(/doesn't stop the pull/)).toBeTruthy();
  });

  it("closed before image_pull answers, it stops following the pull once it does", async () => {
    const dialog = pullAlpine();
    // The footer's Close (the header's × is the other).
    fireEvent.click(screen.getAllByRole("button", { name: "Close" }).at(-1)!);
    dialog.rerender();
    await act(async () => answerPull(7));
    expect(calls).toContainEqual(["stream_cancel", { stream: 7 }]);
    // Its progress doesn't come back into the next opening.
    act(() => deliver({ type: "items", items: [{ status: "resolving", reference: "alpine" }] }));
    dialog.reopen();
    dialog.rerender();
    expect(screen.queryByTestId("pull-progress")).toBeNull();
  });

  it("a stream that fails shows the pull failed, with nothing still spinning", async () => {
    pullAlpine();
    await act(async () => answerPull(8));
    act(() =>
      deliver({
        type: "items",
        items: [
          { status: "resolving", reference: "alpine" },
          { status: "downloading", kind: "layer", digest: "sha256:a", current: 40, total: 100 },
        ],
      }),
    );
    // The daemon's own `error` event arrives as a stream error.
    act(() => deliver({ type: "error", error: { kind: "failed", message: "alpine: connection reset" } }));
    const progress = screen.getByTestId("pull-progress");
    expect(progress.dataset.phase).toBe("error");
    expect(screen.getByText("alpine: connection reset")).toBeTruthy();
    expect(progress.querySelector(".animate-spin")).toBeNull();
  });
});
