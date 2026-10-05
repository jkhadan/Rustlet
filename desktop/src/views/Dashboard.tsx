import { Activity, Boxes, Download, HardDrive, Layers, Network, Plus } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import type { Event } from "@/bindings";
import { ErrorState, HealthBadge, PageHeader, StatusDot } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Facts, Mono, Spinner } from "@/components/ui/misc";
import { cn } from "@/lib/cn";
import { countsLessBuilds, hideBuildContainers } from "@/lib/containers";
import { useDaemon, useNow } from "@/lib/daemon";
import { describeEvent } from "@/lib/events";
import { ago, bytes, imageName, isLive, plural, statusText } from "@/lib/format";
import { shownHealth } from "@/lib/health";
import { useContainers, useInfo } from "@/lib/queries";

import { RunDialog } from "./containers/RunDialog";
import { PullDialog } from "./images/PullDialog";

export function Dashboard() {
  const info = useInfo();
  const containers = useContainers(true);
  const { connection, events } = useDaemon();
  const [running, setRunning] = useState(false);
  const [pulling, setPulling] = useState(false);
  const [builds, setBuilds] = useState(false);
  const now = useNow(5_000);

  if (info.error) {
    return (
      <div>
        <PageHeader title="Dashboard" />
        <ErrorState error={info.error} what="the daemon's state" />
      </div>
    );
  }
  // A build's RUN steps run in containers of their own, for a step each:
  // left out of the counts too, as of the list below (until the list is
  // here to say which they are).
  const i = info.data && containers.data && !builds ? countsLessBuilds(info.data, containers.data) : info.data;
  const { shown: live, hidden } = hideBuildContainers((containers.data ?? []).filter(isLive), builds);
  // Network events name containers by id: the names come from the
  // containers' own events (removed ones too) and from those still here.
  const names = new Map<string, string>();
  for (const e of events) if (e.kind === "container" && e.attributes.name) names.set(e.id, e.attributes.name);
  for (const c of containers.data ?? []) names.set(c.id, c.name);
  const nameOf = (id: string) => names.get(id);

  return (
    <div>
      <PageHeader
        title="Dashboard"
        subtitle={connection.state === "connected" ? `rustletd ${connection.version.version} on Linux ${connection.version.kernel}` : " "}
        actions={
          <>
            <Button onClick={() => setPulling(true)}>
              <Download /> Pull an image
            </Button>
            <Button variant="primary" onClick={() => setRunning(true)}>
              <Plus /> Run a container
            </Button>
          </>
        }
      />
      <div className="flex flex-col gap-4 p-6">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4" data-testid="counts">
          <Stat to="/containers" icon={<Boxes />} label="Containers" value={i?.containers} sub={i && `${i.running} running${i.paused ? `, ${i.paused} paused` : ""}, ${i.stopped} stopped`} />
          <Stat to="/images" icon={<Layers />} label="Images" value={i?.images} />
          <Stat to="/networks" icon={<Network />} label="Networks" value={i?.networks} />
          <Stat to="/volumes" icon={<HardDrive />} label="Volumes" value={i?.volumes} />
        </div>
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1fr_26rem]">
          <div className="flex flex-col gap-4">
            <Card>
              <CardHeader
                title="Running"
                description="Containers whose processes exist right now."
                actions={
                  (hidden > 0 || builds) && (
                    <Button size="sm" variant="ghost" onClick={() => setBuilds((b) => !b)} data-testid="toggle-build-containers">
                      {builds ? "Hide build containers" : `Show ${plural(hidden, "build container")}`}
                    </Button>
                  )
                }
              />
              <CardContent className="p-0">
                {containers.isPending ? (
                  <div className="flex justify-center py-8">
                    <Spinner />
                  </div>
                ) : live.length === 0 ? (
                  <p className="text-muted-foreground px-4 py-6 text-sm">
                    {hidden ? "Only a build's step containers are running." : "Nothing is running."}
                  </p>
                ) : (
                  <ul className="divide-y" data-testid="running">
                    {live.map((c) => {
                      const health = shownHealth(c.state);
                      return (
                        <li key={c.id}>
                          <Link to={`/containers/${c.id}`} className="hover:bg-muted/40 flex items-center gap-3 px-4 py-2.5">
                            <StatusDot status={c.state.status} />
                            <span className="font-medium">{c.name}</span>
                            <span className="text-muted-foreground truncate text-sm">{imageName(c.image)}</span>
                            <span className="ml-auto flex items-center gap-2">
                              {health && <HealthBadge health={health} />}
                              <span className="text-muted-foreground text-xs whitespace-nowrap">{statusText(c.state, now)}</span>
                            </span>
                          </Link>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader title="Host" description="What the daemon runs on, and where it keeps things." />
              <CardContent>
                {i ? (
                  <Facts
                    rows={[
                      ["Kernel", i.kernel],
                      ["CPUs", i.cpus],
                      ["Memory", bytes(i.memory)],
                      ["Storage", `${i.storage_driver} in ${i.data_root}`],
                      ["Runtime state", <Mono key="r">{i.run_root}</Mono>],
                      ["Cgroups", <Mono key="c" className="break-all">{i.cgroup_parent}</Mono>],
                      ["OCI runtime", <Mono key="o">{i.runtime}</Mono>],
                      ["Shim", <Mono key="s">{i.shim}</Mono>],
                    ]}
                  />
                ) : (
                  <Spinner />
                )}
              </CardContent>
            </Card>
          </div>
          <Card className="flex max-h-[38rem] flex-col">
            <CardHeader title="Activity" description="Live from the daemon: whatever does it, here, the CLI or a restart policy." />
            <ul className="min-h-0 flex-1 overflow-y-auto" data-testid="activity">
              {events.length === 0 && (
                <li className="text-muted-foreground flex items-center gap-2 px-4 py-6 text-sm">
                  <Activity className="size-4" /> Waiting for something to happen…
                </li>
              )}
              {events.map((e, n) => (
                <EventRow key={`${e.time}-${n}`} event={e} now={now} nameOf={nameOf} />
              ))}
            </ul>
          </Card>
        </div>
      </div>
      <RunDialog open={running} onOpenChange={setRunning} />
      <PullDialog open={pulling} onOpenChange={setPulling} />
    </div>
  );
}

function Stat({ to, icon, label, value, sub }: { to: string; icon: React.ReactNode; label: string; value?: number; sub?: string | null }) {
  return (
    <Link to={to}>
      <Card className="hover:border-primary/40 flex h-full items-center gap-4 p-4 transition-colors">
        <div className="bg-primary/10 text-primary rounded-lg p-2.5 [&_svg]:size-5">{icon}</div>
        <div className="min-w-0">
          <div className="text-muted-foreground text-xs font-medium">{label}</div>
          <div className="text-2xl font-semibold tabular-nums">{value ?? "–"}</div>
          {sub && <div className="text-muted-foreground truncate text-xs">{sub}</div>}
        </div>
      </Card>
    </Link>
  );
}

const DOT: Record<string, string> = {
  start: "bg-success",
  unpause: "bg-success",
  create: "bg-info",
  pull: "bg-info",
  tag: "bg-info",
  load: "bg-info",
  commit: "bg-info",
  connect: "bg-info",
  die: "bg-muted-foreground",
  stop: "bg-muted-foreground",
  pause: "bg-warning",
  kill: "bg-warning",
  oom: "bg-destructive",
  destroy: "bg-destructive",
  delete: "bg-destructive",
};

function EventRow({ event: e, now, nameOf }: { event: Event; now: number; nameOf: (id: string) => string | undefined }) {
  const failed =
    (e.action === "die" && e.attributes.exit_code && e.attributes.exit_code !== "0") ||
    (e.action === "health_status" && e.attributes.health_status === "unhealthy");
  const healthy = e.action === "health_status" && e.attributes.health_status === "healthy";
  const link = e.kind === "container" && e.action !== "destroy" ? `/containers/${e.id}` : e.kind === "image" ? null : `/${e.kind}s`;
  const body = (
    <div className="flex items-start gap-3 px-4 py-2">
      <span
        className={cn(
          "mt-1.5 size-2 shrink-0 rounded-full",
          failed ? "bg-destructive" : healthy ? "bg-success" : (DOT[e.action] ?? "bg-muted-foreground/50"),
        )}
      />
      <div className="min-w-0 flex-1">
        <div className="text-sm break-words">{describeEvent(e, nameOf)}</div>
        <div className="text-muted-foreground text-[11px]">
          {e.kind} {e.action} · {ago(e.time, now)}
        </div>
      </div>
    </div>
  );
  return <li data-testid="event">{link ? <Link to={link} className="hover:bg-muted/40 block">{body}</Link> : body}</li>;
}
