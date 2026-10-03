import { ArrowLeft, Boxes, FileJson, Gauge, Info, ScrollText, ShieldCheck, SquareTerminal } from "lucide-react";
import { Link, useNavigate, useParams } from "react-router";

import { ErrorState, PageHeader, StatusBadge } from "@/components/common";
import { ContainerActions } from "@/components/ContainerActions";
import { Empty, Mono, Spinner } from "@/components/ui/misc";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useNow } from "@/lib/daemon";
import { imageName, shortId, statusText } from "@/lib/format";
import { CommandFailed } from "@/lib/ipc";
import { useContainer } from "@/lib/queries";

import { InspectTab } from "./InspectTab";
import { IsolationTab } from "./IsolationTab";
import { LogsTab } from "./LogsTab";
import { OverviewTab } from "./OverviewTab";
import { StatsTab } from "./StatsTab";
import { TerminalTab } from "./TerminalTab";

const TABS = ["overview", "logs", "terminal", "stats", "inspect", "isolation"] as const;
type Tab = (typeof TABS)[number];

export function ContainerPage() {
  const { id = "", tab } = useParams();
  const current: Tab = TABS.includes(tab as Tab) ? (tab as Tab) : "overview";
  const navigate = useNavigate();
  const container = useContainer(id);
  const now = useNow();

  if (container.isPending) {
    return (
      <div className="flex justify-center py-20">
        <Spinner />
      </div>
    );
  }
  if (container.error) {
    if (container.error instanceof CommandFailed && container.error.kind === "no_such_container") {
      return (
        <Empty icon={<Boxes />} title="This container is gone">
          It was removed (from here, the CLI, or by <code className="font-mono">--rm</code>).{" "}
          <Link to="/containers" className="text-primary hover:underline">
            Back to the containers
          </Link>
        </Empty>
      );
    }
    return <ErrorState error={container.error} what="the container" />;
  }
  const c = container.data;
  const running = c.state.status === "running" || c.state.status === "paused";

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title={
          <span className="flex items-center gap-3">
            <Link to="/containers" className="text-muted-foreground hover:text-foreground" aria-label="Back">
              <ArrowLeft className="size-5" />
            </Link>
            <span data-testid="container-name">{c.name}</span>
            <StatusBadge status={c.state.status} exitCode={c.state.exit_code} />
          </span>
        }
        subtitle={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <Link to={`/images/${encodeURIComponent(c.image_id)}`} className="hover:text-foreground hover:underline">
              {imageName(c.image)}
            </Link>
            <span>·</span>
            <Mono>{shortId(c.id)}</Mono>
            <span>·</span>
            <span data-testid="container-status">{statusText(c.state, now)}</span>
          </span>
        }
        actions={<ContainerActions container={c} navigateOnRemove />}
      />
      <Tabs
        value={current}
        onValueChange={(t) => navigate(`/containers/${id}/${t}`, { replace: true })}
        className="flex min-h-0 flex-1 flex-col"
      >
        <TabsList className="px-5">
          <TabsTrigger value="overview">
            <Info /> Overview
          </TabsTrigger>
          <TabsTrigger value="logs">
            <ScrollText /> Logs
          </TabsTrigger>
          <TabsTrigger value="terminal">
            <SquareTerminal /> Terminal
          </TabsTrigger>
          <TabsTrigger value="stats">
            <Gauge /> Stats
          </TabsTrigger>
          <TabsTrigger value="inspect">
            <FileJson /> Inspect
          </TabsTrigger>
          <TabsTrigger value="isolation">
            <ShieldCheck /> Isolation
          </TabsTrigger>
        </TabsList>
        <TabsContent value="overview" className="overflow-y-auto">
          <OverviewTab container={c} />
        </TabsContent>
        <TabsContent value="logs" className="flex flex-col">
          <LogsTab container={c} />
        </TabsContent>
        <TabsContent value="terminal" className="flex flex-col">
          <TerminalTab container={c} running={running} />
        </TabsContent>
        <TabsContent value="stats" className="overflow-y-auto">
          <StatsTab container={c} running={running} />
        </TabsContent>
        <TabsContent value="inspect" className="overflow-y-auto">
          <InspectTab value={c} />
        </TabsContent>
        <TabsContent value="isolation" className="overflow-y-auto">
          <IsolationTab container={c} running={running} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
