// A shell in the container on a terminal of its own: `rustlet exec -it
// <container> sh`, drawn by xterm.js. Leaving the tab hangs the session
// up (the shell gets SIGHUP), as closing a terminal window does. Pausing
// the container doesn't: its processes freeze, what is typed waits in the
// PTY, and the shell reads it when it resumes, as on a real terminal.

import "@xterm/xterm/css/xterm.css";

import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import { RotateCcw, SquareTerminal } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import type { ContainerInspect } from "@/bindings";
import { Button } from "@/components/ui/button";
import { Empty } from "@/components/ui/misc";
import { api, type TerminalMessage } from "@/lib/ipc";
import { SHELL, TerminalInput } from "@/lib/terminal";

type State = { s: "connecting" } | { s: "open" } | { s: "exited"; code: number } | { s: "failed"; message: string };

const THEME = {
  background: "#18181b",
  foreground: "#e4e4e7",
  cursor: "#f97316",
  selectionBackground: "#f9731655",
  black: "#27272a",
  brightBlack: "#52525b",
};

export function TerminalTab({ container, running }: { container: ContainerInspect; running: boolean }) {
  const host = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<State>({ s: "connecting" });
  const [attempt, setAttempt] = useState(0);
  const paused = container.state.status === "paused";
  // An exec can't start in a frozen container, so a tab opened while it is
  // paused starts its shell when it resumes; from then on a pause doesn't
  // touch the session.
  const [thawed, setThawed] = useState<string | null>(null);
  if (running && !paused && thawed !== container.id) setThawed(container.id);
  const ready = thawed === container.id;

  useEffect(() => {
    if (!running || !ready || !host.current) return;
    const term = new Terminal({
      fontFamily: '"JetBrains Mono", "Fira Code", "DejaVu Sans Mono", monospace',
      fontSize: 13,
      cursorBlink: true,
      scrollback: 5000,
      theme: THEME,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host.current);
    fit.fit();
    term.focus();
    setState({ s: "connecting" });

    let closed = false;
    let session: number | undefined;
    // What is typed while the shell starts waits for its session (the
    // input's one call in flight waits for it), and goes out in order.
    let opened: (id: number) => void = () => {};
    let gone: () => void = () => {};
    const started = new Promise<number>((resolve, reject) => {
      opened = resolve;
      gone = () => reject(new Error("the terminal has no session"));
    });
    started.catch(() => {});
    const input = new TerminalInput(async (data) => api.terminal.input(await started, data));
    const asked = { rows: term.rows, cols: term.cols };
    const onOutput = (m: ArrayBuffer | TerminalMessage) => {
      if (closed) return;
      if (m instanceof ArrayBuffer) {
        // xterm decodes UTF-8 itself, across chunk boundaries too.
        term.write(new Uint8Array(m));
      } else if (m.type === "exit") {
        input.close();
        setState({ s: "exited", code: m.code });
        term.write(`\r\n\x1b[2m[process exited with code ${m.code}]\x1b[0m\r\n`);
      } else {
        input.close();
        setState({ s: "failed", message: m.error.message });
      }
    };
    api.terminal
      .open({ container: container.id, cmd: SHELL, ...asked }, onOutput)
      .then((id) => {
        if (closed) {
          void api.terminal.close(id);
          return;
        }
        session = id;
        setState((s) => (s.s === "connecting" ? { s: "open" } : s));
        opened(id);
        // The pane may have changed size while the shell started (the web
        // font loads, the window grows): the session gets the last size.
        if (term.rows !== asked.rows || term.cols !== asked.cols) {
          void api.terminal.resize(id, term.rows, term.cols).catch(() => {});
        }
      })
      .catch((e: unknown) => {
        gone();
        if (!closed) setState({ s: "failed", message: e instanceof Error ? e.message : String(e) });
      });

    const typed = term.onData((data) => input.text(data));
    const binary = term.onBinary((data) => input.binary(data));
    const resized = term.onResize(({ rows, cols }) => {
      if (session != null) void api.terminal.resize(session, rows, cols).catch(() => {});
    });
    const observer = new ResizeObserver(() => {
      try {
        fit.fit();
      } catch {
        // Not laid out yet.
      }
    });
    observer.observe(host.current);

    return () => {
      closed = true;
      observer.disconnect();
      typed.dispose();
      binary.dispose();
      resized.dispose();
      input.close();
      gone();
      if (session != null) void api.terminal.close(session).catch(() => {});
      term.dispose();
    };
  }, [container.id, running, ready, attempt]);

  if (!running) {
    return (
      <Empty icon={<SquareTerminal />} title="The container isn't running">
        A terminal runs a shell inside the running container (<code className="font-mono">rustlet exec -it</code>).
      </Empty>
    );
  }
  return (
    <div className="flex min-h-0 flex-1 flex-col bg-[#18181b]">
      <div className="flex items-center gap-3 border-b border-white/10 px-4 py-2 text-xs text-zinc-400">
        <span className="font-mono" data-testid="terminal-state" data-state={state.s} data-paused={paused}>
          {paused && (state.s === "connecting" || state.s === "open") ? (
            <span className="text-amber-400">
              {ready ? "paused: what you type reaches the shell when it resumes" : "paused: a shell starts when it resumes"}
            </span>
          ) : (
            <>
              {state.s === "connecting" && "starting a shell…"}
              {state.s === "open" && `exec: bash or sh · ${container.name}`}
            </>
          )}
          {state.s === "exited" && `exited with code ${state.code}`}
          {state.s === "failed" && <span className="text-red-400">{state.message}</span>}
        </span>
        <div className="flex-1" />
        {(state.s === "exited" || state.s === "failed") && (
          <Button size="sm" variant="ghost" className="text-zinc-300 hover:bg-white/10" onClick={() => setAttempt((a) => a + 1)}>
            <RotateCcw /> New session
          </Button>
        )}
      </div>
      <div ref={host} className="min-h-0 flex-1 px-2 py-1" data-testid="terminal" />
    </div>
  );
}
