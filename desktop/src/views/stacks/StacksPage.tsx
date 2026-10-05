// The compose projects the daemon has containers of, as `rustlet compose
// ls` lists them: from their containers' labels, since the daemon knows
// nothing of projects. Every card is live: each container event refreshes
// the stacks (lib/events.ts), so a service that turns healthy, or a
// project the CLI brings down, shows at once.

import { ArrowUpFromLine, Blocks, FileUp, Power } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { toast } from "sonner";

import { attempt, ErrorState, HealthBadge, PageHeader, StatusBadge, useConfirm } from "@/components/common";
import { Badge, type Tone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/input";
import { Empty, Mono, Spinner } from "@/components/ui/misc";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { Tooltip } from "@/components/ui/tooltip";
import { plural, portsText } from "@/lib/format";
import { shownHealth } from "@/lib/health";
import { api, type Stack } from "@/lib/ipc";
import { useStacks } from "@/lib/queries";
import { runningText, servicesOf, sortStacks, type StackState, stackSummary, upAgainFiles } from "@/lib/stacks";

import { ComposeUpDialog, type UpRequest, useComposeUp } from "./ComposeUpDialog";

const stateTone: Record<StackState, Tone> = { running: "success", partial: "warning", stopped: "neutral" };

export function StacksPage() {
  const stacks = useStacks();
  const up = useComposeUp();
  // The dialog's request, and a count that makes each opening a fresh one.
  const [dialog, setDialog] = useState<{ request: UpRequest; n: number } | null>(null);
  const list = sortStacks(stacks.data ?? []);
  const containers = list.reduce((n, s) => n + s.containers.length, 0);
  const running = list.reduce((n, s) => n + stackSummary(s).running, 0);

  const open = (request: UpRequest, start: boolean) => {
    up.reset();
    setDialog((d) => ({ request, n: (d?.n ?? 0) + 1 }));
    if (start) up.start(request);
  };
  const close = () => {
    up.reset();
    setDialog(null);
  };

  return (
    <div>
      <PageHeader
        title="Stacks"
        subtitle={stacks.data ? `${plural(list.length, "project")} · ${running} of ${plural(containers, "container")} running` : " "}
        actions={
          <Button variant="primary" onClick={() => open({ files: [], projectName: "", projectDir: null }, false)} data-testid="open-compose-up">
            <FileUp /> Up from file…
          </Button>
        }
      />
      <div className="flex flex-col gap-4 px-6 py-4">
        {stacks.isPending ? (
          <div className="flex justify-center py-16">
            <Spinner />
          </div>
        ) : stacks.error ? (
          <ErrorState error={stacks.error} what="the stacks" />
        ) : list.length === 0 ? (
          <Empty icon={<Blocks />} title="No stacks yet">
            A compose project shows here once it has containers: bring one up from its file, or run{" "}
            <code className="font-mono">rustlet compose up -d</code> in its directory.
          </Empty>
        ) : (
          list.map((s) => (
            <StackCard
              key={s.name}
              stack={s}
              onUp={(files) => open({ files, projectName: s.name, projectDir: s.working_dir }, true)}
            />
          ))
        )}
      </div>
      {dialog && <ComposeUpDialog key={dialog.n} request={dialog.request} up={up} onClose={close} />}
    </div>
  );
}

function StackCard({ stack, onUp }: { stack: Stack; onUp: (files: string[]) => void }) {
  const [dialog, ask] = useConfirm();
  const [busy, setBusy] = useState(false);
  const summary = stackSummary(stack);
  const files = upAgainFiles(stack);

  const down = async () => {
    let volumes = false;
    const ok = await ask({
      title: `Take ${stack.name} down?`,
      body: (
        <div className="flex flex-col gap-3">
          <p>Its containers are stopped and removed, and its networks with them. Its images stay.</p>
          <RemoveVolumes onChange={(v) => (volumes = v)} />
        </div>
      ),
      confirm: "Down",
      destructive: true,
    });
    if (!ok) return;
    setBusy(true);
    try {
      // The card goes with the stack's last container, from the events.
      let stayed: string[] = [];
      const done = await attempt(`Taking ${stack.name} down failed`, async () => {
        stayed = (await api.compose.down(stack.name, volumes)) ?? [];
      });
      // A network or volume something else still uses stays: no failure,
      // but not to go unsaid ("Down and its volumes" with one left behind).
      if (done && stayed.length) toast.warning(`${stack.name} is down, but not all of it`, { description: stayed.join("\n") });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="stack" data-name={stack.name} data-state={summary.state}>
      {dialog}
      <CardHeader
        title={
          <span className="flex flex-wrap items-center gap-2">
            <Blocks className="text-muted-foreground size-4" />
            <span className="text-base">{stack.name}</span>
            <Badge tone={stateTone[summary.state]} data-testid="stack-running">
              {runningText(summary)}
            </Badge>
            {summary.unhealthy > 0 && <Badge tone="destructive">{summary.unhealthy} unhealthy</Badge>}
            {summary.starting > 0 && <Badge tone="warning">{summary.starting} starting</Badge>}
          </span>
        }
        description={
          stack.working_dir ? (
            <Mono className="break-all">{stack.working_dir}</Mono>
          ) : (
            "Its containers don't say where it was brought up from."
          )
        }
        actions={
          <>
            <Tooltip content={files ? `compose up -d with ${files.join(", ")}` : "Its containers don't name the compose file they came from"}>
              <span>
                <Button size="sm" onClick={() => files && onUp(files)} disabled={!files || busy} data-testid="stack-up">
                  <ArrowUpFromLine /> Up
                </Button>
              </span>
            </Tooltip>
            <Button size="sm" onClick={() => void down()} disabled={busy} data-testid="stack-down">
              {busy ? <Spinner className="size-3.5" /> : <Power />} Down…
            </Button>
          </>
        }
      />
      <CardContent className="p-0">
        <Table>
          <thead>
            <tr>
              <Th className="pl-4">Service</Th>
              <Th>Container</Th>
              <Th>Status</Th>
              <Th>Ports</Th>
            </tr>
          </thead>
          <tbody>
            {servicesOf(stack).flatMap((g) =>
              g.containers.map((sc, i) => {
                const c = sc.container;
                const health = shownHealth(c.state);
                const ports = portsText(c.ports);
                return (
                  <Tr
                    key={c.id}
                    data-testid="stack-container"
                    data-name={c.name}
                    data-service={sc.service}
                    data-status={c.state.status}
                    data-health={health ?? undefined}
                  >
                    {i === 0 && (
                      <Td rowSpan={g.containers.length} className="pl-4 align-top font-medium">
                        {g.service}
                      </Td>
                    )}
                    <Td>
                      <Link to={`/containers/${c.id}`} className="hover:underline">
                        {c.name}
                      </Link>
                      <span className="text-muted-foreground ml-1.5 text-xs" title="Its number within the service">
                        #{sc.number}
                      </span>
                    </Td>
                    <Td>
                      <span className="flex items-center gap-2">
                        <StatusBadge status={c.state.status} exitCode={c.state.exit_code} />
                        {health && <HealthBadge health={health} />}
                      </span>
                    </Td>
                    <Td>
                      {ports.length ? (
                        <span className="flex flex-col">
                          {ports.map((p) => (
                            <Mono key={p} className="text-xs">
                              {p}
                            </Mono>
                          ))}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">–</span>
                      )}
                    </Td>
                  </Tr>
                );
              }),
            )}
          </tbody>
        </Table>
      </CardContent>
    </Card>
  );
}

/** The confirmation's checkbox: its own state, since the dialog's body is
 * made once. */
function RemoveVolumes({ onChange }: { onChange: (v: boolean) => void }) {
  const [checked, setChecked] = useState(false);
  return (
    <Checkbox
      checked={checked}
      onChange={(v) => {
        setChecked(v);
        onChange(v);
      }}
      label="Also remove its volumes"
      hint="The named volumes it made (not external ones), and its containers' anonymous volumes: their data is deleted."
    />
  );
}
