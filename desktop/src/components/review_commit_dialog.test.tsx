// @vitest-environment jsdom
// Review: the commit dialog while its commit is under way.

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

beforeEach(() => {
  h.calls.length = 0;
  for (const k of Object.keys(h.handlers)) delete h.handlers[k];
});
afterEach(cleanup);

describe("commit dialog", () => {
  // Expected: one Commit makes one image. While a commit runs the dialog is
  // "Committing…" and its button disabled (CommitDialog.tsx), but its
  // fields stay enabled and its form has a submit button that never is
  // (`<button type="submit" hidden />`): Enter in "Image name" or "Comment"
  // submits the form again (HTML implicit submission clicks the form's
  // default button, hidden or not), and `submit` doesn't look at `busy`.
  // A commit of a large container takes seconds (rustletd diffs its upper
  // directory, crates/rustletd/src/commit.rs), long enough for a second
  // Enter: a second container_commit, a second image, and the name moved
  // to it, leaving the first one unnamed.
  it("sends one commit while one is under way, whatever submits the form again", async () => {
    // A commit that is still running.
    h.handlers.container_commit = () => new Promise(() => {});
    render(
      <MemoryRouter>
        <CommitDialog container="web" live open onOpenChange={() => {}} />
      </MemoryRouter>,
    );
    fireEvent.change(field("reference"), { target: { value: "web:snap" } });
    fireEvent.click(screen.getByTestId("commit-submit"));
    await waitFor(() => expect(screen.getByTestId("commit-submit").textContent).toContain("Committing"));
    expect(field("reference").disabled).toBe(false);
    // Enter in the name field: the browser submits the form.
    fireEvent.submit(field("reference").form!);
    await new Promise((r) => setTimeout(r, 50));
    expect(args("container_commit")).toHaveLength(1);
  });
});
