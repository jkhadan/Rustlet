import { Boxes, Plus, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router";

import { ErrorState, HealthBadge, PageHeader, StatusDot } from "@/components/common";
import { ContainerActions } from "@/components/ContainerActions";
import { Button } from "@/components/ui/button";
import { Checkbox, Input } from "@/components/ui/input";
import { Empty, Mono, Spinner } from "@/components/ui/misc";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { Tooltip } from "@/components/ui/tooltip";
import { hideBuildContainers } from "@/lib/containers";
import { useNow } from "@/lib/daemon";
import { ago, commandText, imageName, isLive, plural, portsText, shortId, statusText } from "@/lib/format";
import { shownHealth } from "@/lib/health";
import { useContainers } from "@/lib/queries";

import { RunDialog } from "./RunDialog";

export function ContainersPage() {
  const [all, setAll] = useState(true);
  const [builds, setBuilds] = useState(false);
  const [filter, setFilter] = useState("");
  const [running, setRunning] = useState(false);
  const containers = useContainers(all);
  const now = useNow();
  const navigate = useNavigate();

  // A build's RUN steps are containers too, each gone again within the
  // step: hidden unless asked for.
  const { shown, hidden } = useMemo(() => hideBuildContainers(containers.data ?? [], builds), [containers.data, builds]);
  const rows = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return shown.filter(
      (c) => !f || c.name.toLowerCase().includes(f) || c.image.toLowerCase().includes(f) || c.id.startsWith(f),
    );
  }, [shown, filter]);
  const live = shown.filter(isLive).length;
  // With stopped ones hidden, the daemon lists only live ones: how many are
  // stopped isn't known here.
  const stopped = all ? ` · ${shown.length - live} stopped` : " · stopped ones hidden";
  const hiddenBuilds = hidden ? ` · ${plural(hidden, "build container")} hidden` : "";

  return (
    <div>
      <PageHeader
        title="Containers"
        subtitle={containers.data ? `${live} running${stopped}${hiddenBuilds}` : " "}
        actions={
          <Button variant="primary" onClick={() => setRunning(true)} data-testid="open-run">
            <Plus /> Run a container
          </Button>
        }
      >
        <div className="mt-4 flex items-center gap-4">
          <div className="relative w-72">
            <Search className="text-muted-foreground pointer-events-none absolute top-2 left-2.5 size-4" />
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by name, image or id"
              className="pl-8"
            />
          </div>
          <Checkbox checked={all} onChange={setAll} label="Show stopped containers" />
          <Checkbox checked={builds} onChange={setBuilds} label="Show build containers" />
        </div>
      </PageHeader>

      <div className="px-6 py-4">
        {containers.isPending ? (
          <div className="flex justify-center py-16">
            <Spinner />
          </div>
        ) : containers.error ? (
          <ErrorState error={containers.error} what="containers" />
        ) : rows.length === 0 ? (
          <Empty
            icon={<Boxes />}
            title={
              filter
                ? "No container matches"
                : hidden
                  ? "Only a build's containers, hidden"
                  : all
                    ? "No containers yet"
                    : "No container is running"
            }
          >
            {!filter && !hidden && (
              <>
                Run one here, or with <code className="font-mono">rustlet run -d nginx</code>: it shows up at once.
              </>
            )}
            {!filter && hidden > 0 && "A build runs each RUN step in a container of its own, removed after the step."}
          </Empty>
        ) : (
          <div className="bg-card overflow-hidden rounded-lg border">
            <Table data-testid="containers-table">
              <thead>
                <tr>
                  <Th className="w-[22%]">Name</Th>
                  <Th>Image</Th>
                  <Th>Command</Th>
                  <Th>Ports</Th>
                  <Th>Created</Th>
                  <Th>Status</Th>
                  <Th className="w-0 text-right">Actions</Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((c) => {
                  const health = shownHealth(c.state);
                  return (
                    <Tr
                      key={c.id}
                      className="cursor-pointer"
                      onClick={() => navigate(`/containers/${c.id}`)}
                      data-testid="container-row"
                      data-name={c.name}
                      data-status={c.state.status}
                      data-health={health ?? undefined}
                    >
                      <Td>
                        <div className="flex items-center gap-2.5">
                          <StatusDot status={c.state.status} />
                          <div className="min-w-0">
                            <Link
                              to={`/containers/${c.id}`}
                              className="block truncate font-medium hover:underline"
                              onClick={(e) => e.stopPropagation()}
                            >
                              {c.name}
                            </Link>
                            <Mono className="text-muted-foreground text-[11px]">{shortId(c.id)}</Mono>
                          </div>
                        </div>
                      </Td>
                      <Td className="max-w-48 truncate" title={c.image}>
                        {imageName(c.image)}
                      </Td>
                      <Td className="max-w-56">
                        <Mono className="text-muted-foreground block truncate">{commandText(c.command)}</Mono>
                      </Td>
                      <Td>
                        <div className="flex flex-col">
                          {portsText(c.ports).map((p) => (
                            <Mono key={p} className="text-xs">
                              {p}
                            </Mono>
                          ))}
                        </div>
                      </Td>
                      <Td className="text-muted-foreground whitespace-nowrap">{ago(c.created, now)}</Td>
                      <Td className="whitespace-nowrap">
                        <span className="flex items-center gap-2">
                          <Tooltip content={c.state.error}>
                            <span className={c.state.error ? "text-destructive" : undefined}>{statusText(c.state, now)}</span>
                          </Tooltip>
                          {health && <HealthBadge health={health} />}
                        </span>
                      </Td>
                      <Td className="text-right">
                        <ContainerActions container={c} compact />
                      </Td>
                    </Tr>
                  );
                })}
              </tbody>
            </Table>
          </div>
        )}
      </div>
      <RunDialog open={running} onOpenChange={setRunning} />
    </div>
  );
}
