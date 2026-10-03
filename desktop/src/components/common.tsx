// Pieces every view uses: the page header, a container's status, errors,
// confirmations, copy buttons.

import { AlertTriangle, Check, Copy, PlugZap, Power } from "lucide-react";
import { type ReactNode, useCallback, useState } from "react";
import { toast } from "sonner";

import type { ContainerStatus } from "@/bindings";
import { cn } from "@/lib/cn";
import { useDaemon } from "@/lib/daemon";
import { api, CommandFailed } from "@/lib/ipc";

import { Badge, type Tone } from "./ui/badge";
import { Button } from "./ui/button";
import { Dialog } from "./ui/dialog";
import { Spinner } from "./ui/misc";

export function PageHeader({
  title,
  subtitle,
  actions,
  children,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <header className="bg-background/80 sticky top-0 z-10 border-b px-6 pt-5 pb-4 backdrop-blur">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="truncate text-xl font-semibold tracking-tight">{title}</h1>
          {subtitle && <div className="text-muted-foreground mt-1 text-sm">{subtitle}</div>}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
      {children}
    </header>
  );
}

const statusTone: Record<ContainerStatus, Tone> = {
  running: "success",
  paused: "warning",
  restarting: "info",
  created: "neutral",
  exited: "neutral",
  removing: "warning",
  dead: "destructive",
};

export function StatusDot({ status, className }: { status: ContainerStatus; className?: string }) {
  const color = {
    running: "bg-success",
    paused: "bg-warning",
    restarting: "bg-info animate-pulse",
    created: "bg-muted-foreground/40",
    exited: "bg-muted-foreground/40",
    removing: "bg-warning animate-pulse",
    dead: "bg-destructive",
  }[status];
  return <span className={cn("inline-block size-2 shrink-0 rounded-full", color, className)} />;
}

export function StatusBadge({ status, exitCode }: { status: ContainerStatus; exitCode?: number | null }) {
  const failed = status === "exited" && exitCode != null && exitCode !== 0;
  return (
    <Badge tone={failed ? "destructive" : statusTone[status]}>
      <StatusDot status={status} className={failed ? "bg-destructive" : undefined} />
      {status}
      {status === "exited" && exitCode != null && ` (${exitCode})`}
    </Badge>
  );
}

/** A failed query: the daemon being away gets its own explanation. */
export function ErrorState({ error, what }: { error: unknown; what?: string }) {
  if (error instanceof CommandFailed && (error.kind === "unreachable" || error.kind === "denied")) {
    return <DaemonDown />;
  }
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className="flex flex-col items-center gap-2 px-6 py-14 text-center">
      <AlertTriangle className="text-destructive size-8" />
      <p className="font-medium">{what ? `Couldn't load ${what}` : "Something went wrong"}</p>
      <p className="text-muted-foreground selectable max-w-xl text-sm break-words">{message}</p>
    </div>
  );
}

/** Starts the installed service through pkexec. */
export function useStartDaemon() {
  const [starting, setStarting] = useState(false);
  const start = useCallback(async () => {
    setStarting(true);
    try {
      await api.daemon.start();
      toast.success("rustletd started");
    } catch (e) {
      toast.error("Couldn't start rustletd", { description: e instanceof Error ? e.message : String(e) });
    } finally {
      setStarting(false);
    }
  }, []);
  return { start, starting };
}

/** The whole view, when the daemon can't be used. */
export function DaemonDown() {
  const { connection } = useDaemon();
  const { start, starting } = useStartDaemon();
  const error = connection.state === "disconnected" ? connection.error : null;
  const socket = connection.state === "disconnected" ? connection.socket : "/run/rustlet/rustlet.sock";
  if (connection.state === "connecting") {
    return (
      <div className="flex items-center justify-center gap-2 py-20">
        <Spinner /> Connecting to rustletd…
      </div>
    );
  }
  const denied = error?.kind === "denied";
  return (
    <div className="mx-auto flex max-w-lg flex-col items-center gap-3 px-6 py-16 text-center">
      <div className="bg-muted rounded-full p-4">
        <PlugZap className="text-muted-foreground size-8" />
      </div>
      <h2 className="text-lg font-semibold">{denied ? "rustletd's socket isn't yours to use" : "rustletd isn't running"}</h2>
      <p className="text-muted-foreground text-sm">
        {denied ? (
          <>
            The daemon's socket <code className="font-mono">{socket}</code> belongs to root and the{" "}
            <code className="font-mono">rustlet</code> group. Membership is as powerful as root: whoever can create
            containers can mount the host's <code className="font-mono">/</code> into one.
          </>
        ) : (
          <>
            Nothing answers on <code className="font-mono">{socket}</code>. Start the installed service, or set{" "}
            <code className="font-mono">RUSTLET_HOST</code> to another daemon's socket before launching the app.
          </>
        )}
      </p>
      {denied ? (
        <pre className="bg-muted selectable w-full rounded-md p-3 text-left font-mono text-xs">
          {"sudo groupadd --system rustlet\nsudo usermod -aG rustlet $USER\nsudo systemctl restart rustletd\n# then log out and in again"}
        </pre>
      ) : (
        <Button variant="primary" onClick={start} disabled={starting}>
          {starting ? <Spinner className="text-primary-foreground" /> : <Power />}
          Start rustletd
        </Button>
      )}
      {error && <p className="text-muted-foreground/80 selectable text-xs break-all">{error.message}</p>}
    </div>
  );
}

export interface ConfirmOptions {
  title: ReactNode;
  body?: ReactNode;
  confirm: string;
  destructive?: boolean;
}

/** `const [dialog, ask] = useConfirm()`: render `dialog`, then
 * `if (await ask({...}))`. */
export function useConfirm(): [ReactNode, (o: ConfirmOptions) => Promise<boolean>] {
  const [state, setState] = useState<(ConfirmOptions & { resolve: (ok: boolean) => void }) | null>(null);
  const ask = useCallback(
    (o: ConfirmOptions) => new Promise<boolean>((resolve) => setState({ ...o, resolve })),
    [],
  );
  const close = (ok: boolean) => {
    state?.resolve(ok);
    setState(null);
  };
  const dialog = (
    <Dialog
      open={state != null}
      onOpenChange={(open) => !open && close(false)}
      title={state?.title}
      className="w-[min(440px,92vw)]"
      footer={
        <>
          <Button onClick={() => close(false)}>Cancel</Button>
          <Button variant={state?.destructive ? "destructive" : "primary"} onClick={() => close(true)} autoFocus>
            {state?.confirm}
          </Button>
        </>
      }
    >
      <div className="text-muted-foreground text-sm">{state?.body}</div>
    </Dialog>
  );
  return [dialog, ask];
}

export function CopyButton({ text, className }: { text: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className={cn("text-muted-foreground hover:text-foreground inline-flex items-center rounded p-0.5", className)}
      title="Copy"
      onClick={(e) => {
        e.stopPropagation();
        e.preventDefault();
        void navigator.clipboard.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        });
      }}
    >
      {done ? <Check className="text-success size-3.5" /> : <Copy className="size-3.5" />}
    </button>
  );
}

/** Runs an action, reporting failure in a toast. Resolves to whether it
 * worked. */
export async function attempt(what: string, f: () => Promise<unknown>): Promise<boolean> {
  try {
    await f();
    return true;
  } catch (e) {
    toast.error(what, { description: e instanceof Error ? e.message : String(e) });
    return false;
  }
}
