// Live resource usage: the daemon samples the container's cgroup (and its
// network namespace's interfaces) once a second; this keeps the last two
// minutes and plots them.

import { Gauge } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import type { ContainerInspect, Pressure } from "@/bindings";
import { Chart } from "@/components/Chart";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Empty, Meter, Spinner } from "@/components/ui/misc";
import { useDaemon } from "@/lib/daemon";
import { bytes, percent } from "@/lib/format";
import { api, type StreamHandle } from "@/lib/ipc";
import { blockTotals, networkTotals, Series } from "@/lib/stats";

const COLORS = { cpu: "#f97316", memory: "#3b82f6", rx: "#14b8a6", tx: "#a855f7", read: "#eab308", write: "#ef4444" };

export function StatsTab({ container, running }: { container: ContainerInspect; running: boolean }) {
  const series = useRef(new Series(120));
  const [version, setVersion] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const run = container.state.started_at ?? "";
  // rustletd going away cuts the stream short (it fails, or ends while the
  // container still runs); the next connection (a new `generation`) starts
  // the charts again.
  const { generation } = useDaemon();
  const latestGeneration = useRef(generation);
  latestGeneration.current = generation;
  const cut = useRef(false);
  const [reopened, setReopened] = useState(0);
  useEffect(() => {
    if (cut.current) setReopened((n) => n + 1);
  }, [generation]);

  useEffect(() => {
    if (!running) return;
    let closed = false;
    let handle: StreamHandle | undefined;
    series.current = new Series(120);
    setVersion(0);
    setError(null);
    cut.current = false;
    // The first connection belongs to the stream opened at app startup.
    const openedGeneration = Math.max(1, latestGeneration.current);
    const markCut = () => {
      cut.current = true;
      // The watch can reconnect before this connection notices EOF.
      if (latestGeneration.current > openedGeneration) setReopened((n) => n + 1);
    };
    const fail = (message: string) => {
      markCut();
      setError(message);
    };
    api.containers
      .stats(container.id, (m) => {
        if (closed) return;
        if (m.type === "items") {
          for (const s of m.items) series.current.push(s);
          setVersion((v) => v + 1);
        } else if (m.type === "error") {
          fail(m.error.message);
        } else {
          markCut();
        }
      })
      .then((h) => (closed ? h.cancel() : (handle = h)))
      .catch((e: unknown) => !closed && fail(e instanceof Error ? e.message : String(e)));
    return () => {
      closed = true;
      handle?.cancel();
    };
  }, [container.id, running, run, reopened]);

  const s = series.current;
  const latest = s.latest;
  const point = s.points[s.points.length - 1];
  const charts = useMemo(
    () => ({
      cpu: s.columns("cpu"),
      memory: s.columns("memory"),
      net: s.columns("rx", "tx"),
      blk: s.columns("read", "write"),
    }),
    // A new sample is a new version.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [version],
  );

  if (!running) {
    return (
      <Empty icon={<Gauge />} title="The container isn't running">
        Its cgroup only counts while it runs; start it to see live usage.
      </Empty>
    );
  }
  if (error) return <p className="text-destructive p-6 text-sm">{error}</p>;
  if (!latest || !point) {
    return (
      <div className="flex items-center justify-center gap-2 py-20 text-sm">
        <Spinner /> Waiting for the first sample…
      </div>
    );
  }
  const net = networkTotals(latest);
  const blk = blockTotals(latest);
  const cpuMax = (container.config.cpus ?? latest.cpus_online) * 100;

  return (
    <div className="flex flex-col gap-4 p-6" data-testid="stats">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Tile label="CPU" value={percent(point.cpu)} sub={`of ${cpuMax}% (${container.config.cpus ?? latest.cpus_online} CPUs)`}>
          <Meter value={point.cpu} max={cpuMax} />
        </Tile>
        <Tile label="Memory" value={bytes(point.memory)} sub={latest.memory_max ? `of ${bytes(latest.memory_max)}` : "no limit"}>
          <Meter value={point.memory} max={latest.memory_max} />
        </Tile>
        <Tile label="Network" value={`${bytes(point.rx)}/s ↓`} sub={`${bytes(point.tx)}/s ↑ · ${bytes(net.rx)} / ${bytes(net.tx)} total`} />
        <Tile label="Block I/O" value={`${bytes(point.read)}/s`} sub={`${bytes(point.write)}/s written · ${bytes(blk.read)} / ${bytes(blk.write)} total`} />
        <Tile label="PIDs" value={String(point.pids)} sub={point.pidsLimit ? `of ${point.pidsLimit}` : "no limit"}>
          <Meter value={point.pids} max={point.pidsLimit} />
        </Tile>
      </div>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartCard title="CPU" legend={[["CPU", COLORS.cpu, percent(point.cpu)]]}>
          <Chart data={charts.cpu} series={[{ label: "CPU", color: COLORS.cpu }]} format={(v) => `${v.toFixed(v < 10 ? 1 : 0)}%`} floor={5} />
        </ChartCard>
        <ChartCard title="Memory" legend={[["in use", COLORS.memory, bytes(point.memory)]]}>
          <Chart data={charts.memory} series={[{ label: "Memory", color: COLORS.memory }]} format={(v) => bytes(v, 0)} max={latest.memory_max ?? undefined} floor={16 << 20} />
        </ChartCard>
        <ChartCard
          title="Network"
          legend={[
            ["received", COLORS.rx, `${bytes(point.rx)}/s`],
            ["sent", COLORS.tx, `${bytes(point.tx)}/s`],
          ]}
        >
          <Chart
            data={charts.net}
            series={[
              { label: "rx", color: COLORS.rx },
              { label: "tx", color: COLORS.tx },
            ]}
            format={(v) => `${bytes(v, 0)}/s`}
            floor={4096}
          />
        </ChartCard>
        <ChartCard
          title="Block I/O"
          legend={[
            ["read", COLORS.read, `${bytes(point.read)}/s`],
            ["written", COLORS.write, `${bytes(point.write)}/s`],
          ]}
        >
          <Chart
            data={charts.blk}
            series={[
              { label: "read", color: COLORS.read },
              { label: "write", color: COLORS.write },
            ]}
            format={(v) => `${bytes(v, 0)}/s`}
            floor={4096}
          />
        </ChartCard>
      </div>
      <Card>
        <CardHeader
          title="Pressure (PSI)"
          description="Share of time some (or all) of its tasks were stalled waiting for a resource, averaged over 10 and 60 seconds."
        />
        <CardContent className="grid grid-cols-3 gap-6">
          {(["cpu", "memory", "io"] as const).map((r) => (
            <PressureBox key={r} name={r} lines={latest.pressure[r]} />
          ))}
        </CardContent>
      </Card>
      <p className="text-muted-foreground text-xs">
        CPU counts 100% per CPU, as <code className="font-mono">rustlet stats</code> does; memory leaves out the
        inactive page cache. Sampled from <code className="font-mono">{container.cgroup}</code>.
      </p>
    </div>
  );
}

function Tile({ label, value, sub, children }: { label: string; value: string; sub: string; children?: React.ReactNode }) {
  return (
    <Card className="flex flex-col gap-1.5 p-3.5">
      <span className="text-muted-foreground text-xs font-medium">{label}</span>
      <span className="text-lg font-semibold tabular-nums">{value}</span>
      {children}
      <span className="text-muted-foreground truncate text-xs" title={sub}>
        {sub}
      </span>
    </Card>
  );
}

function ChartCard({ title, legend, children }: { title: string; legend: [string, string, string][]; children: React.ReactNode }) {
  return (
    <Card>
      <div className="flex items-center justify-between px-4 pt-3">
        <h3 className="text-sm font-semibold">{title}</h3>
        <div className="flex gap-3 text-xs">
          {legend.map(([l, c, v]) => (
            <span key={l} className="flex items-center gap-1.5">
              <span className="size-2 rounded-full" style={{ background: c }} />
              <span className="text-muted-foreground">{l}</span>
              <span className="font-medium tabular-nums">{v}</span>
            </span>
          ))}
        </div>
      </div>
      <div className="px-2 pb-2">{children}</div>
    </Card>
  );
}

function PressureBox({ name, lines }: { name: string; lines?: { [key in string]?: Pressure } }) {
  if (!lines) return <div className="text-muted-foreground text-sm">{name}: not available</div>;
  return (
    <div className="flex flex-col gap-2">
      <span className="text-sm font-medium">{name}</span>
      {(["some", "full"] as const).map((l) =>
        lines[l] ? (
          <div key={l} className="flex flex-col gap-1">
            <div className="flex justify-between text-xs">
              <span className="text-muted-foreground">{l}</span>
              <span className="tabular-nums">
                {lines[l]!.avg10.toFixed(2)}% · {lines[l]!.avg60.toFixed(2)}%
              </span>
            </div>
            <Meter value={lines[l]!.avg10} max={100} />
          </div>
        ) : null,
      )}
    </div>
  );
}
