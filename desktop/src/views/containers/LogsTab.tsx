// The container's log: the last lines, then (following) each new one as
// the daemon reads it. Only the rows on screen are in the DOM, so a log of
// 100 000 lines scrolls like one of ten.

import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDownToLine, Eraser, Search } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import type { ContainerInspect, LogEntry } from "@/bindings";
import { Button } from "@/components/ui/button";
import { Checkbox, Input, Select } from "@/components/ui/input";
import { Spinner } from "@/components/ui/misc";
import { parseAnsi, type Span, stripAnsi } from "@/lib/ansi";
import { cn } from "@/lib/cn";
import { api, type StreamHandle } from "@/lib/ipc";

/** Lines kept in memory at most; older ones are dropped. */
const MAX_LINES = 50_000;

interface Line {
  n: number;
  ts: string;
  stderr: boolean;
  spans: Span[];
  plain: string;
}

export function LogsTab({ container }: { container: ContainerInspect }) {
  const [lines, setLines] = useState<Line[]>([]);
  const [follow, setFollow] = useState(true);
  const [timestamps, setTimestamps] = useState(false);
  const [tail, setTail] = useState("1000");
  const [filter, setFilter] = useState("");
  const [status, setStatus] = useState<"loading" | "following" | "ended" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const scroller = useRef<HTMLDivElement>(null);
  // Following keeps the newest line in view until the user scrolls up.
  const stick = useRef(true);
  const [atEnd, setAtEnd] = useState(true);
  const counter = useRef(0);

  // A new run (a restart) gets a new stream: following ends with each exit.
  const run = container.state.started_at ?? "";
  const live = container.state.status === "running" || container.state.status === "paused";

  useEffect(() => {
    let closed = false;
    let handle: StreamHandle | undefined;
    const style = { style: {} };
    setLines([]);
    setStatus("loading");
    setError(null);
    counter.current = 0;
    api.containers
      .logs(container.id, { follow: follow && live, tail: tail === "all" ? null : Number(tail) }, (m) => {
        if (closed) return;
        if (m.type === "items") {
          const add = m.items.map((e: LogEntry) => {
            const text = e.log.replace(/\r?\n$/, "");
            return {
              n: counter.current++,
              ts: e.ts,
              stderr: e.stream === "stderr",
              spans: parseAnsi(text, style),
              plain: stripAnsi(text),
            };
          });
          setLines((old) => {
            const next = old.concat(add);
            return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
          });
          setStatus(follow && live ? "following" : "loading");
        } else if (m.type === "end") {
          setStatus("ended");
        } else {
          setStatus("error");
          setError(m.error.message);
        }
      })
      .then((h) => {
        if (closed) h.cancel();
        else {
          handle = h;
          setStatus((s) => (s === "loading" && follow && live ? "following" : s));
        }
      })
      .catch((e: unknown) => {
        if (!closed) {
          setStatus("error");
          setError(e instanceof Error ? e.message : String(e));
        }
      });
    return () => {
      closed = true;
      handle?.cancel();
    };
  }, [container.id, run, live, follow, tail]);

  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return f ? lines.filter((l) => l.plain.toLowerCase().includes(f)) : lines;
  }, [lines, filter]);

  const virtual = useVirtualizer({
    count: shown.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => 20,
    overscan: 30,
  });

  // Following: keep the newest line in view, unless the user scrolled up.
  useEffect(() => {
    if (stick.current && shown.length) virtual.scrollToIndex(shown.length - 1, { align: "end" });
  }, [shown.length, virtual]);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex flex-wrap items-center gap-4 border-b px-6 py-2.5">
        <div className="relative w-64">
          <Search className="text-muted-foreground pointer-events-none absolute top-2 left-2.5 size-4" />
          <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter lines" className="pl-8" />
        </div>
        <Checkbox checked={follow} onChange={setFollow} label="Follow" />
        <Checkbox checked={timestamps} onChange={setTimestamps} label="Timestamps" />
        <label className="flex items-center gap-2 text-sm">
          Last
          <Select value={tail} onChange={(e) => setTail(e.target.value)} className="w-24">
            <option value="100">100</option>
            <option value="1000">1000</option>
            <option value="10000">10000</option>
            <option value="all">all</option>
          </Select>
          lines
        </label>
        <div className="flex-1" />
        <span className="text-muted-foreground flex items-center gap-2 text-xs" data-testid="logs-status">
          {status === "loading" && <Spinner className="size-3" />}
          {status === "following" && <span className="bg-success size-1.5 animate-pulse rounded-full" />}
          {status === "following" ? "following" : status === "ended" ? (live ? "end of log" : "the container isn't running") : status === "error" ? "failed" : "loading"}
          {` · ${shown.length}${filter ? ` of ${lines.length}` : ""} lines`}
        </span>
        <Button size="sm" variant="ghost" onClick={() => setLines([])} title="Clear the view (not the log)">
          <Eraser /> Clear
        </Button>
      </div>
      {error && <p className="text-destructive px-6 py-2 text-sm">{error}</p>}
      <div className="relative min-h-0 flex-1">
        <div
          ref={scroller}
          className="selectable absolute inset-0 overflow-auto bg-[oklch(0.16_0.005_286)] py-2 font-mono text-[12.5px] leading-5 text-[oklch(0.92_0_0)]"
          data-testid="logs"
          onScroll={(e) => {
            const el = e.currentTarget;
            stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
            setAtEnd(stick.current);
          }}
        >
          {shown.length === 0 && status !== "loading" && (
            <p className="px-6 py-4 text-[oklch(0.6_0_0)]">{filter ? "No line matches." : "Nothing logged yet."}</p>
          )}
          <div style={{ height: virtual.getTotalSize(), position: "relative" }}>
            {virtual.getVirtualItems().map((row) => {
              const l = shown[row.index];
              return (
                <div
                  key={l.n}
                  className={cn("absolute left-0 flex w-full gap-3 px-6 whitespace-pre-wrap", l.stderr && "bg-red-500/8")}
                  style={{ transform: `translateY(${row.start}px)` }}
                  ref={virtual.measureElement}
                  data-index={row.index}
                >
                  {timestamps && <span className="shrink-0 text-[oklch(0.55_0_0)]">{l.ts.slice(0, 23).replace("T", " ")}</span>}
                  <span className="min-w-0 break-all">
                    {l.spans.map((s, i) => (
                      <span
                        key={i}
                        style={{ color: s.fg, background: s.bg, fontWeight: s.bold ? 600 : undefined, opacity: s.dim ? 0.7 : undefined, fontStyle: s.italic ? "italic" : undefined, textDecoration: s.underline ? "underline" : undefined }}
                      >
                        {s.text}
                      </span>
                    ))}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
        {!atEnd && shown.length > 0 && (
          <Button
            size="sm"
            variant="secondary"
            className="absolute right-6 bottom-4 shadow-md"
            onClick={() => {
              stick.current = true;
              setAtEnd(true);
              virtual.scrollToIndex(shown.length - 1, { align: "end" });
            }}
          >
            <ArrowDownToLine /> Newest
          </Button>
        )}
      </div>
    </div>
  );
}
