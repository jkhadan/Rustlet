import { describe, expect, it } from "vitest";

import { TerminalInput } from "./terminal";

describe("terminal input", () => {
  it("one call at a time, in order, joining what was typed meanwhile", async () => {
    const sent: string[] = [];
    let release: () => void = () => {};
    const input = new TerminalInput(
      (data) =>
        new Promise((resolve) => {
          sent.push(data);
          release = resolve;
        }),
    );
    input.push("l");
    input.push("s");
    input.push(" -l\r");
    expect(sent).toEqual(["l"]);
    release();
    await Promise.resolve();
    await Promise.resolve();
    expect(sent).toEqual(["l", "s -l\r"]);
    release();
    await Promise.resolve();
    input.push("x");
    expect(sent).toEqual(["l", "s -l\r", "x"]);
  });

  it("stops after a failure or a close", async () => {
    const sent: string[] = [];
    const errors: unknown[] = [];
    const input = new TerminalInput(async (d) => {
      sent.push(d);
      throw new Error("session ended");
    }, (e) => errors.push(e));
    input.push("a");
    await new Promise((r) => setTimeout(r, 0));
    input.push("b");
    expect(sent).toEqual(["a"]);
    expect(errors).toHaveLength(1);

    const closed = new TerminalInput(async (d) => void sent.push(d));
    closed.close();
    closed.push("c");
    expect(sent).toEqual(["a"]);
  });
});
