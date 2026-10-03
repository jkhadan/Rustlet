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

  it("reads the colon form of extended colours, the colour space given or not", () => {
    // ITU T.416, as xterm documents it and VTE and kitty write it.
    expect(parseAnsi("\x1b[38:2::255:0:0mX")).toEqual([{ text: "X", fg: "rgb(255, 0, 0)" }]);
    expect(parseAnsi("\x1b[48:2:1:10:20:30mX")[0].bg).toBe("rgb(10, 20, 30)");
    expect(parseAnsi("\x1b[38:2:10:20:30mX")[0].fg).toBe("rgb(10, 20, 30)");
    expect(parseAnsi("\x1b[38:5:196mX")[0].fg).toBe(color256(196));
    // The sub-parameters are the colour's alone: a blue of 0 is no reset.
    expect(parseAnsi("\x1b[1;38:2::0:128:0;4mX")).toEqual([{ text: "X", bold: true, underline: true, fg: "rgb(0, 128, 0)" }]);
    // An underline's colour isn't drawn, and its values are no codes.
    expect(parseAnsi("\x1b[58;2;0;0;0;31mX")).toEqual([{ text: "X", fg: "#dc2626" }]);
    expect(parseAnsi("\x1b[4:3mX\x1b[4:0mY")).toEqual([{ text: "X", underline: true }, { text: "Y" }]);
  });

  it("carries a style to the next line and drops other escapes", () => {
    const state = { style: {} };
    parseAnsi("\x1b[32mgreen starts", state);
    expect(parseAnsi("still green\x1b[39m", state)).toEqual([{ text: "still green", fg: "#16a34a" }]);
    expect(parseAnsi("\x1b[2K\x1b[1Gprogress", { style: {} })).toEqual([{ text: "progress" }]);
    expect(stripAnsi("\x1b]0;title\x07\x1b[33mwarn\x1b[m")).toBe("warn");
  });
});
