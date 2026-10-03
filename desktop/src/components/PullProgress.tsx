import { CheckCircle2, CircleDashed, Download, PackageOpen, XCircle } from "lucide-react";

import { bytes, shortId } from "@/lib/format";
import { downloadShare, type PullState } from "@/lib/pull";

import { Spinner } from "./ui/misc";

/** A pull as it happens: overall progress, then a row per layer. */
export function PullProgress({ state }: { state: PullState }) {
  const share = downloadShare(state);
  const layers = state.blobs.filter((b) => b.kind === "layer");
  const phase = {
    resolving: "Asking the registry…",
    downloading: `Downloading ${state.layerCount ?? layers.length} layer${(state.layerCount ?? layers.length) === 1 ? "" : "s"}`,
    unpacking: "Unpacking layers into snapshots",
    ready: "Ready",
    error: "Failed",
  }[state.phase];
  return (
    <div className="flex flex-col gap-3" data-testid="pull-progress" data-phase={state.phase}>
      <div className="flex items-center justify-between gap-3 text-sm">
        <span className="flex items-center gap-2 font-medium">
          {state.phase === "ready" ? (
            <CheckCircle2 className="text-success size-4" />
          ) : state.phase === "error" ? (
            <XCircle className="text-destructive size-4" />
          ) : (
            <Spinner />
          )}
          {phase}
        </span>
        <span className="text-muted-foreground text-xs">
          {state.platform}
          {state.size != null && ` · ${bytes(state.size)}`}
        </span>
      </div>
      {state.error && <p className="text-destructive selectable text-sm break-words">{state.error}</p>}
      {layers.length > 0 && (
        <>
          <div className="bg-muted h-2 overflow-hidden rounded-full">
            <div className="bg-primary h-full transition-[width] duration-300" style={{ width: `${share * 100}%` }} />
          </div>
          <ul className="flex max-h-56 flex-col gap-1.5 overflow-y-auto text-xs">
            {layers.map((b) => {
              const unpack = state.layers.find((l) => l.blob === b.digest);
              const pct = b.total ? Math.min(100, (b.current / b.total) * 100) : 0;
              // A ready image has every layer unpacked, also one whose
              // `unpacked` the daemon dropped.
              const done = state.phase === "ready" || unpack?.state === "unpacked" || b.state === "exists";
              return (
                <li key={b.digest} className="grid grid-cols-[1.25rem_7rem_1fr_6.5rem] items-center gap-2">
                  {done ? (
                    <CheckCircle2 className="text-success size-3.5" />
                  ) : unpack?.state === "unpacking" ? (
                    <PackageOpen className="text-info size-3.5" />
                  ) : b.state === "downloaded" ? (
                    <Download className="text-muted-foreground size-3.5" />
                  ) : b.state === "downloading" ? (
                    <Spinner className="size-3.5" />
                  ) : (
                    <CircleDashed className="text-muted-foreground size-3.5" />
                  )}
                  <span className="font-mono">{shortId(b.digest)}</span>
                  <div className="bg-muted h-1.5 overflow-hidden rounded-full">
                    <div
                      className={b.state === "exists" ? "bg-success h-full" : "bg-primary/80 h-full transition-[width]"}
                      style={{ width: `${b.state === "exists" ? 100 : pct}%` }}
                    />
                  </div>
                  <span className="text-muted-foreground text-right tabular-nums">
                    {b.state === "exists"
                      ? "already here"
                      : unpack?.state === "unpacking"
                        ? "unpacking…"
                        : unpack?.state === "unpacked"
                          ? unpack.bytes != null
                            ? `${bytes(unpack.bytes)} unpacked`
                            : "unpacked"
                          : `${bytes(b.current)} / ${bytes(b.total)}`}
                  </span>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </div>
  );
}
