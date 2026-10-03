// Terminal input, in order.
//
// Each keystroke xterm.js reports becomes an `invoke("terminal_input")`.
// Tauri may run two calls of an async command at the same time, so two
// keystrokes sent back to back could reach the container in either order.
// `TerminalInput` keeps one call in flight: what is typed meanwhile waits,
// joined into one string, and goes out when the call before it returns. A
// paste or fast typing costs a few calls, not one per character.

/** The shell a terminal tab runs: bash if the image has it, else sh. */
export const SHELL = ["/bin/sh", "-c", 'if command -v bash >/dev/null 2>&1; then exec bash; fi; exec sh'];

export class TerminalInput {
  private pending = "";
  private flying = false;
  private closed = false;

  constructor(private readonly send: (data: string) => Promise<void>, private readonly onError: (e: unknown) => void = () => {}) {}

  push(data: string): void {
    if (this.closed || !data) return;
    this.pending += data;
    if (!this.flying) void this.flush();
  }

  close(): void {
    this.closed = true;
    this.pending = "";
  }

  private async flush(): Promise<void> {
    this.flying = true;
    try {
      while (this.pending && !this.closed) {
        const data = this.pending;
        this.pending = "";
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
