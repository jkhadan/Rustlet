import { describe, expect, it } from "vitest";

import type { LogEntry } from "@/bindings";

import { LogBuffer, MAX_LOG_CHARS, MAX_LOG_LINE_CHARS, MAX_LOG_LINES, retainLogLines } from "./logs";

const entry = (log: string, stream: LogEntry["stream"] = "stdout", ts = "2026-10-05T00:00:00Z"): LogEntry => ({ log, stream, ts });

describe("bounded container logs", () => {
  it("bounds unfinished lines on both streams and counts discarded output", () => {
    const buffer = new LogBuffer();
    const piece = "x".repeat(16 * 1024);
    for (let i = 0; i < 1024; i++) {
      expect(buffer.push([entry(piece), entry(piece, "stderr")])).toEqual([]);
      expect(buffer.pendingChars).toBeLessThanOrEqual(2 * MAX_LOG_LINE_CHARS);
    }
    const lines = buffer.push([entry("\n"), entry("\n", "stderr")]);
    expect(lines).toHaveLength(2);
    for (const line of lines) {
      expect(line.log).toHaveLength(MAX_LOG_LINE_CHARS);
      expect(line.droppedChars).toBe(1024 * piece.length - MAX_LOG_LINE_CHARS);
    }
    expect(buffer.pendingChars).toBe(0);
  });

  it("preserves a fragment's first timestamp and flushes it when the stream ends", () => {
    const buffer = new LogBuffer();
    buffer.push([entry("first", "stdout", "2026-10-05T00:00:01Z"), entry("error", "stderr")]);
    expect(buffer.push([entry(" second\r\n", "stdout", "2026-10-05T00:00:02Z")])).toEqual([
      { ...entry("first second", "stdout", "2026-10-05T00:00:01Z"), droppedChars: 0 },
    ]);
    expect(buffer.finish()).toEqual([{ ...entry("error", "stderr"), droppedChars: 0 }]);
    expect(buffer.finish()).toEqual([]);
  });

  it("keeps the newest rows within both the text and row budgets", () => {
    const large = Array.from({ length: MAX_LOG_CHARS / MAX_LOG_LINE_CHARS + 3 }, (_, i) => ({ i, chars: MAX_LOG_LINE_CHARS }));
    const kept = retainLogLines(large);
    expect(kept[0].i).toBe(3);
    expect(kept.reduce((n, line) => n + line.chars, 0)).toBe(MAX_LOG_CHARS);
    const small = Array.from({ length: MAX_LOG_LINES + 3 }, (_, i) => ({ i, chars: 1 }));
    expect(retainLogLines(small)).toEqual(small.slice(3));
  });
});
