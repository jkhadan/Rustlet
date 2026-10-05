// @vitest-environment jsdom
// Review: what the Save dialog says it saved.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => {
  const handlers: Record<string, (args: any) => unknown> = {};
  const invoke = async (cmd: string, args?: any) => {
    const f = handlers[cmd];
    if (!f) throw { kind: "failed", message: `no handler for ${cmd}` };
    return f(args);
  };
  const toasts: string[] = [];
  const toast = Object.assign((m: string) => void toasts.push(m), {
    success: (m: string) => void toasts.push(m),
    error: (m: string) => void toasts.push(m),
  });
  return { handlers, invoke, toasts, toast };
});
vi.mock("@tauri-apps/api/core", () => ({ Channel: class {}, invoke: h.invoke }));
vi.mock("sonner", () => ({ toast: h.toast }));

import { SaveDialog } from "./ImageDialogs";

const field = (name: string) => document.querySelector(`input[name="${name}"]`) as HTMLInputElement;

beforeEach(() => {
  h.toasts.length = 0;
  for (const k of Object.keys(h.handlers)) delete h.handlers[k];
});
afterEach(cleanup);

describe("save", () => {
  // Expected: the toast counts the images saved. The image page opens Save
  // with every name of its one image (ImagePage.tsx: `names={i.names}`),
  // and rustletd saves "an image named twice … once, with both names"
  // (bindings/ImageSaveRequest.ts; Images::for_save in
  // crates/rustletd/src/images.rs). One image went into the file; the toast
  // counts the names typed (`plural(list.length, "image")`) and says two.
  it("of one image by its two names says one image was saved", async () => {
    h.handlers.image_save = () => 46_137_344;
    render(<SaveDialog open names={["docker.io/library/hits:latest", "docker.io/library/hits:1.0"]} onOpenChange={() => {}} />);
    fireEvent.change(field("path"), { target: { value: "~/hits.tar" } });
    fireEvent.click(screen.getByTestId("save-submit"));
    await waitFor(() => expect(h.toasts).toHaveLength(1));
    expect(h.toasts[0]).not.toMatch(/2 images/);
  });
});
