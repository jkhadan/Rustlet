// Start, stop, restart, pause/resume, kill and remove, for whatever state
// the container is in. The lists refresh from the daemon's events, as they
// do when the CLI does the same thing, so nothing here updates the cache.

import { MoreHorizontal, Pause, Play, RotateCw, Square, Trash2, Zap } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router";

import type { ContainerState } from "@/bindings";
import { api } from "@/lib/ipc";

import { attempt, useConfirm } from "./common";
import { Button } from "./ui/button";
import { Checkbox } from "./ui/input";
import { Menu, MenuItem, MenuSeparator } from "./ui/menu";
import { Spinner } from "./ui/misc";
import { Tooltip } from "./ui/tooltip";

interface Target {
  id: string;
  name: string;
  state: ContainerState;
}

export function ContainerActions({ container, compact, navigateOnRemove }: { container: Target; compact?: boolean; navigateOnRemove?: boolean }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [dialog, ask] = useConfirm();
  const navigate = useNavigate();
  const { id, name, state } = container;
  const live = state.status === "running" || state.status === "paused";

  const run = async (what: string, f: () => Promise<unknown>) => {
    setBusy(what);
    try {
      return await attempt(`${what} ${name} failed`, f);
    } finally {
      setBusy(null);
    }
  };

  const remove = async () => {
    let volumes = false;
    const ok = await ask({
      title: `Remove ${name}?`,
      body: (
        <div className="flex flex-col gap-3">
          <p>
            {live ? "It is running: it will be killed first. " : ""}Its writable layer and logs go with it.
          </p>
          <Option onChange={(v) => (volumes = v)} />
        </div>
      ),
      confirm: "Remove",
      destructive: true,
    });
    if (!ok) return;
    if (await run("Remove", () => api.containers.remove(id, { force: live, volumes }))) {
      if (navigateOnRemove) navigate("/containers");
    }
  };

  const button = (label: string, icon: React.ReactNode, onClick: () => void, variant: "outline" | "primary" | "ghost" = "outline") => {
    const spinning = busy === label;
    if (compact) {
      return (
        <Tooltip content={label}>
          <Button size="icon-sm" variant="ghost" onClick={onClick} disabled={busy != null} aria-label={label}>
            {spinning ? <Spinner className="size-3.5" /> : icon}
          </Button>
        </Tooltip>
      );
    }
    return (
      <Button size="md" variant={variant} onClick={onClick} disabled={busy != null}>
        {spinning ? <Spinner /> : icon}
        {label}
      </Button>
    );
  };

  return (
    <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
      {dialog}
      {(state.status === "created" || state.status === "exited") &&
        button("Start", <Play />, () => void run("Start", () => api.containers.start(id)), "primary")}
      {state.status === "paused" &&
        button("Resume", <Play />, () => void run("Resume", () => api.containers.unpause(id)), "primary")}
      {(live || state.status === "restarting") &&
        button("Stop", <Square />, () => void run("Stop", () => api.containers.stop(id)))}
      {state.status === "running" &&
        !compact &&
        button("Restart", <RotateCw />, () => void run("Restart", () => api.containers.restart(id)))}
      {state.status === "running" && button("Pause", <Pause />, () => void run("Pause", () => api.containers.pause(id)))}
      {compact ? (
        button("Remove", <Trash2 />, () => void remove())
      ) : (
        <Menu
          trigger={
            <Button size="icon" variant="ghost" aria-label="More actions">
              <MoreHorizontal />
            </Button>
          }
        >
          <MenuItem disabled={state.status !== "running"} onSelect={() => void run("Restart", () => api.containers.restart(id))}>
            <RotateCw /> Restart
          </MenuItem>
          <MenuItem disabled={!live} onSelect={() => void run("Kill", () => api.containers.kill(id, "KILL"))}>
            <Zap /> Kill (SIGKILL)
          </MenuItem>
          <MenuSeparator />
          <MenuItem destructive onSelect={() => void remove()}>
            <Trash2 /> Remove…
          </MenuItem>
        </Menu>
      )}
    </div>
  );
}

/** The confirmation's checkbox: its own state, since the dialog's body is
 * made once. */
function Option({ onChange }: { onChange: (v: boolean) => void }) {
  const [checked, setChecked] = useState(false);
  return (
    <Checkbox
      checked={checked}
      onChange={(v) => {
        setChecked(v);
        onChange(v);
      }}
      label="Also remove its anonymous volumes"
      hint="Named volumes always stay."
    />
  );
}
