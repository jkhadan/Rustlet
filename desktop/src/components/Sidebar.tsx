import { Blocks, Boxes, Hammer, HardDrive, Layers, LayoutDashboard, Network, Power } from "lucide-react";
import { NavLink } from "react-router";

import { cn } from "@/lib/cn";
import { useDaemon } from "@/lib/daemon";

import { useStartDaemon } from "./common";
import { Button } from "./ui/button";
import { Spinner } from "./ui/misc";
import { Tooltip } from "./ui/tooltip";

const nav = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/containers", label: "Containers", icon: Boxes },
  { to: "/stacks", label: "Stacks", icon: Blocks },
  { to: "/images", label: "Images", icon: Layers },
  { to: "/build", label: "Build", icon: Hammer },
  { to: "/networks", label: "Networks", icon: Network },
  { to: "/volumes", label: "Volumes", icon: HardDrive },
];

export function Sidebar() {
  return (
    <aside className="bg-sidebar flex w-56 shrink-0 flex-col border-r">
      <div className="flex items-center gap-2.5 px-4 pt-5 pb-4">
        <Logo />
        <div className="leading-tight">
          <div className="font-semibold tracking-tight">Rustlets</div>
          <div className="text-muted-foreground text-[11px]">containers, by hand</div>
        </div>
      </div>
      <nav className="flex flex-1 flex-col gap-0.5 px-2">
        {nav.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm font-medium transition-colors",
                isActive ? "bg-primary/12 text-primary" : "text-muted-foreground hover:bg-accent hover:text-foreground",
              )
            }
          >
            <Icon className="size-4" />
            {label}
          </NavLink>
        ))}
      </nav>
      <ConnectionIndicator />
    </aside>
  );
}

function Logo() {
  return (
    <svg viewBox="0 0 32 32" className="size-8" aria-hidden>
      <rect x="2" y="2" width="28" height="28" rx="7" className="fill-primary" />
      <path d="M9 11.5 16 8l7 3.5v9L16 24l-7-3.5z" fill="none" stroke="white" strokeWidth="1.8" strokeLinejoin="round" />
      <path d="M9 11.5 16 15l7-3.5M16 15v9" fill="none" stroke="white" strokeWidth="1.8" strokeLinejoin="round" />
    </svg>
  );
}

/** The footer: is the daemon there, which one, and a way to start it. */
function ConnectionIndicator() {
  const { connection, generation } = useDaemon();
  const { start, starting, offered } = useStartDaemon();
  return (
    <div className="border-t px-3 py-3 text-xs">
      {connection.state === "connecting" && (
        <div className="text-muted-foreground flex items-center gap-2">
          <Spinner className="size-3" /> Connecting…
        </div>
      )}
      {connection.state === "connected" && (
        <Tooltip content={`${connection.socket} · API ${connection.version.api_version}`} side="right">
          <div className="flex items-center gap-2" data-testid="connection" data-state="connected" data-generation={generation}>
            <span className="bg-success relative inline-flex size-2 rounded-full">
              <span className="bg-success absolute inline-flex size-full animate-ping rounded-full opacity-40" />
            </span>
            <div className="min-w-0 leading-tight">
              <div className="font-medium">rustletd {connection.version.version}</div>
              <div className="text-muted-foreground truncate">Linux {connection.version.kernel}</div>
            </div>
          </div>
        </Tooltip>
      )}
      {connection.state === "disconnected" && (
        <div className="flex flex-col gap-2" data-testid="connection" data-state="disconnected">
          <Tooltip content={connection.error.message} side="right">
            <div className="flex items-center gap-2">
              <span className="bg-destructive inline-flex size-2 rounded-full" />
              <span className="font-medium">{connection.error.kind === "denied" ? "Permission denied" : "Not connected"}</span>
            </div>
          </Tooltip>
          {offered && (connection.error.kind === "unreachable" || connection.error.kind === "denied") && (
            <Button size="sm" onClick={start} disabled={starting} className="w-full">
              {starting ? <Spinner className="size-3" /> : <Power />} Start daemon
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
