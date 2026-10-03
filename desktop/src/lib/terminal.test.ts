import { describe, expect, it } from "vitest";

import { TerminalInput } from "./terminal";

const text = (data: Uint8Array) => new TextDecoder().decode(data);

describe("terminal input", () => {
  it("one call at a time, in order, joining what was typed meanwhile", async () => {
    const sent: string[] = [];
    let release: () => void = () => {};
    const input = new TerminalInput(
      (data) =>
        new Promise((resolve) => {
          sent.push(text(data));
          release = resolve;
        }),
    );
    input.text("l");
    input.text("s");
    input.text(" -l\r");
    expect(sent).toEqual(["l"]);
    release();
    await Promise.resolve();
    await Promise.resolve();
    expect(sent).toEqual(["l", "s -l\r"]);
    release();
    await Promise.resolve();
    input.text("x");
    expect(sent).toEqual(["l", "s -l\r", "x"]);
  });

  it("stops after a failure or a close", async () => {
    const sent: string[] = [];
    const errors: unknown[] = [];
    const input = new TerminalInput(async (d) => {
      sent.push(text(d));
      throw new Error("session ended");
    }, (e) => errors.push(e));
    input.text("a");
    await new Promise((r) => setTimeout(r, 0));
    input.text("b");
    expect(sent).toEqual(["a"]);
    expect(errors).toHaveLength(1);

    const closed = new TerminalInput(async (d) => void sent.push(text(d)));
    closed.close();
    closed.text("c");
    expect(sent).toEqual(["a"]);
  });

  it("text goes as UTF-8, xterm's binary strings byte for byte", async () => {
    const sent: number[][] = [];
    let release: () => void = () => {};
    const input = new TerminalInput(
      (d) =>
        new Promise((resolve) => {
          sent.push([...d]);
          release = resolve;
        }),
    );
    input.text("é");
    // An X10 mouse report at column 130: ESC [ M, button 0 (32), x = 32 +
    // 130 = 162 (0xA2), y = 32 + 5 = 37, a byte each.
    input.binary("\x1b[M " + String.fromCharCode(162, 37));
    input.text("é");
    release();
    await Promise.resolve();
    await Promise.resolve();
    expect(sent).toEqual([[0xc3, 0xa9], [0x1b, 0x5b, 0x4d, 0x20, 0xa2, 0x25, 0xc3, 0xa9]]);
  });
});
