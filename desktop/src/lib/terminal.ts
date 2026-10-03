// Terminal input, in order.
//
// Each keystroke xterm.js reports becomes an `invoke("terminal_input")`.
// Tauri may run two calls of an async command at the same time, so two
// keystrokes sent back to back could reach the container in either order.
// `TerminalInput` keeps one call in flight: what is typed meanwhile waits,
// joined into one run of bytes, and goes out when the call before it
// returns. A paste or fast typing costs a few calls, not one per character.
//
// The PTY takes bytes. What is typed (xterm's `onData`) is text, sent as
// UTF-8; xterm's `onBinary` strings are bytes already, one per character
// (0–255: a mouse report past column 95, say), and are sent as they are.

/** The shell a terminal tab runs: bash if the image has it, else sh. */
export const SHELL = ["/bin/sh", "-c", 'if command -v bash >/dev/null 2>&1; then exec bash; fi; exec sh'];

const utf8 = new TextEncoder();

export class TerminalInput {
  private pending: Uint8Array[] = [];
  private flying = false;
  private closed = false;

  constructor(private readonly send: (data: Uint8Array) => Promise<void>, private readonly onError: (e: unknown) => void = () => {}) {}

  /** What is typed or pasted (xterm's `onData`). */
  text(data: string): void {
    this.push(utf8.encode(data));
  }

  /** A string of bytes (xterm's `onBinary`). */
  binary(data: string): void {
    this.push(Uint8Array.from(data, (c) => c.charCodeAt(0) & 0xff));
  }

  push(data: Uint8Array): void {
    if (this.closed || !data.length) return;
    this.pending.push(data);
    if (!this.flying) void this.flush();
  }

  close(): void {
    this.closed = true;
    this.pending = [];
  }

  private async flush(): Promise<void> {
    this.flying = true;
    try {
      while (this.pending.length && !this.closed) {
        const data = join(this.pending);
        this.pending = [];
        try {
          await this.send(data);
        } catch (e) {
          this.closed = true;
          this.onError(e);
        }
      }
    } finally {
      this.flying = false;
    }
  }
}

function join(chunks: Uint8Array[]): Uint8Array {
  if (chunks.length === 1) return chunks[0];
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}
