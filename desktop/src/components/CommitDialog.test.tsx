// @vitest-environment jsdom
// The commit dialog against container_commit.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => {
  const handlers: Record<string, (args: any) => unknown> = {};
  const calls: { cmd: string; args: any }[] = [];
  const invoke = async (cmd: string, args?: any) => {
    calls.push({ cmd, args });
    const f = handlers[cmd];
    if (!f) throw { kind: "failed", message: `no handler for ${cmd}` };
    return f(args);
  };
  return { handlers, calls, invoke };
});
vi.mock("@tauri-apps/api/core", () => ({ Channel: class {}, invoke: h.invoke }));

import { CommitDialog } from "./CommitDialog";

const args = (cmd: string) => h.calls.filter((c) => c.cmd === cmd).map((c) => c.args);
const field = (name: string) => document.querySelector(`input[name="${name}"]`) as HTMLInputElement;

function dialog(live: boolean, onOpenChange: (o: boolean) => void = () => {}) {
  render(
    <MemoryRouter>
      <CommitDialog container="web" live={live} open onOpenChange={onOpenChange} />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  h.calls.length = 0;
  for (const k of Object.keys(h.handlers)) delete h.handlers[k];
});
afterEach(cleanup);

describe("commit", () => {
  it("sends the name and comment typed, pausing a running container", async () => {
    h.handlers.container_commit = () => ({ id: `sha256:${"e".repeat(64)}`, name: "docker.io/library/web:snap", layer: "sha256:l" });
    const closes: boolean[] = [];
    dialog(true, (o) => closes.push(o));
    fireEvent.change(field("reference"), { target: { value: "web:snap " } });
    fireEvent.change(field("comment"), { target: { value: "installed curl" } });
    fireEvent.click(screen.getByTestId("commit-submit"));
    await waitFor(() => expect(closes).toEqual([false]));
    expect(args("container_commit")).toEqual([{ request: { container: "web", reference: "web:snap", comment: "installed curl", pause: true } }]);
  });

  it("left unnamed, keeps the image unnamed; the pause is the user's to turn off", async () => {
    h.handlers.container_commit = () => ({ id: `sha256:${"e".repeat(64)}`, name: null, layer: "sha256:l" });
    dialog(true);
    fireEvent.click(screen.getByLabelText(/Pause it while its changes are read/));
    fireEvent.click(screen.getByTestId("commit-submit"));
    await waitFor(() => expect(args("container_commit")).toHaveLength(1));
    expect(args("container_commit")[0].request).toEqual({ container: "web", reference: null, comment: null, pause: false });
  });

  it("a stopped container has nothing to pause; a refusal says why", async () => {
    h.handlers.container_commit = () => {
      throw { kind: "conflict", message: "web is being removed" };
    };
    dialog(false);
    expect(screen.queryByLabelText(/Pause it/)).toBeNull();
    fireEvent.click(screen.getByTestId("commit-submit"));
    expect((await screen.findByTestId("commit-error")).textContent).toBe("web is being removed");
  });
});
