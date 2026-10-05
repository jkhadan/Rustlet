import type { LogEntry, LogStream } from "@/bindings";

/** A logical line may span arbitrarily many of the shim's 16 KiB entries. */
export const MAX_LOG_LINE_CHARS = 64 * 1024;
export const MAX_LOG_CHARS = 8 * 1024 * 1024;
export const MAX_LOG_LINES = 50_000;

export interface BufferedLogEntry extends LogEntry {
  droppedChars: number;
}

/** Joins each stream's fragments while keeping incomplete lines bounded. */
export class LogBuffer {
  private held = new Map<LogStream, { entry: BufferedLogEntry; endsWithCR: boolean }>();

  get pendingChars(): number {
    return [...this.held.values()].reduce((n, e) => n + e.entry.log.length, 0);
  }

  push(entries: LogEntry[]): BufferedLogEntry[] {
    const whole: BufferedLogEntry[] = [];
    for (const entry of entries) {
      const pending = this.held.get(entry.stream);
      const before = pending?.entry;
      const ended = entry.log.endsWith("\n");
      let prefix = before?.log ?? "";
      let droppedChars = before?.droppedChars ?? 0;
      // CR and LF can straddle two shim fragments, including the point
      // where the retained prefix was capped. Strip the logical line's
      // terminator, and exclude a discarded terminator from its count.
      if (entry.log === "\n" && pending?.endsWithCR) {
        if (droppedChars) droppedChars--;
        else prefix = prefix.slice(0, -1);
      }
      const text = prefix + entry.log.replace(/\r?\n$/, "");
      const joined = {
        ...entry,
        ts: before?.ts ?? entry.ts,
        log: text.slice(0, MAX_LOG_LINE_CHARS),
        droppedChars: droppedChars + Math.max(0, text.length - MAX_LOG_LINE_CHARS),
      };
      if (ended) {
        this.held.delete(entry.stream);
        whole.push(joined);
      } else {
        this.held.set(entry.stream, {
          entry: joined,
          endsWithCR: entry.log ? entry.log.endsWith("\r") : (pending?.endsWithCR ?? false),
        });
      }
    }
    return whole;
  }

  finish(): BufferedLogEntry[] {
    const last = [...this.held.values()].map((p) => p.entry).sort((a, b) => a.ts.localeCompare(b.ts));
    this.held.clear();
    return last;
  }
}

/** Retains the newest rows by total text size as well as row count. */
export function retainLogLines<T extends { chars: number }>(lines: T[]): T[] {
  let chars = lines.reduce((n, line) => n + line.chars, 0);
  let start = Math.max(0, lines.length - MAX_LOG_LINES);
  for (let i = 0; i < start; i++) chars -= lines[i].chars;
  while (chars > MAX_LOG_CHARS && start < lines.length) chars -= lines[start++].chars;
  return start ? lines.slice(start) : lines;
}
