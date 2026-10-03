import { describe, expect, it } from "vitest";

import { color256, parseAnsi, stripAnsi } from "./ansi";

describe("ANSI colours in logs", () => {
  it("styles text between SGR sequences", () => {
    const spans = parseAnsi("plain \x1b[1;31mred bold\x1b[0m done");
    expect(spans).toEqual([
      { text: "plain " },
      { text: "red bold", bold: true, fg: "#dc2626" },
      { text: " done" },
    ]);
  });

  it("knows 256 and true colours", () => {
    expect(parseAnsi("\x1b[38;5;196mx")[0].fg).toBe(color256(196));
    expect(parseAnsi("\x1b[48;2;1;2;3mx")[0].bg).toBe("rgb(1, 2, 3)");
    expect(color256(232)).toBe("rgb(8, 8, 8)");
  });

  it("carries a style to the next line and drops other escapes", () => {
    const state = { style: {} };
    parseAnsi("\x1b[32mgreen starts", state);
    expect(parseAnsi("still green\x1b[39m", state)).toEqual([{ text: "still green", fg: "#16a34a" }]);
    expect(parseAnsi("\x1b[2K\x1b[1Gprogress", { style: {} })).toEqual([{ text: "progress" }]);
    expect(stripAnsi("\x1b]0;title\x07\x1b[33mwarn\x1b[m")).toBe("warn");
  });
});
