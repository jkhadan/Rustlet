import "@xyflow/react/dist/style.css";

import { Background, Controls, type Edge, Handle, MarkerType, type Node, type NodeProps, Position, ReactFlow } from "@xyflow/react";
import { Box, Monitor, Network as NetworkIcon } from "lucide-react";
import { useMemo } from "react";
import { useNavigate } from "react-router";

import type { ContainerSummary, Network } from "@/bindings";
import { StatusDot } from "@/components/common";
import { cn } from "@/lib/cn";
import { buildTopology, LAYOUT, type TopoNode } from "@/lib/topology";

type Data = { node: TopoNode; selected: boolean };

function Shell({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("bg-card rounded-lg border px-3 py-2 shadow-sm", className)} style={{ width: LAYOUT.nodeWidth }}>
      <Handle type="target" position={Position.Top} className="!bg-muted-foreground/40 !size-1.5 !border-0" />
      {children}
      <Handle type="source" position={Position.Bottom} className="!bg-muted-foreground/40 !size-1.5 !border-0" />
    </div>
  );
}

function HostNode() {
  return (
    <Shell className="border-primary/40 bg-primary/5">
      <div className="flex items-center gap-2 font-semibold">
        <Monitor className="text-primary size-4" /> This host
      </div>
      <div className="text-muted-foreground text-[11px]">routes, NAT and published ports</div>
    </Shell>
  );
}

function NetworkNode({ data }: NodeProps<Node<Data>>) {
  const n = data.node;
  return (
    <Shell className={cn("cursor-pointer", data.selected && "ring-primary ring-2")}>
      <div className="flex items-center gap-2 font-semibold">
        <NetworkIcon className="text-info size-4" />
        <span className="truncate">{n.label}</span>
      </div>
      {n.detail.map((d) => (
        <div key={d} className="text-muted-foreground truncate font-mono text-[11px]">
          {d}
        </div>
      ))}
      {n.flags && n.flags.length > 0 && (
        <div className="mt-1 flex gap-1">
          {n.flags.map((f) => (
            <span key={f} className="bg-muted rounded px-1 text-[10px]">
              {f}
            </span>
          ))}
        </div>
      )}
    </Shell>
  );
}

function ContainerNode({ data }: NodeProps<Node<Data>>) {
  const n = data.node;
  return (
    <Shell className={cn("cursor-pointer hover:border-primary/60", n.flags?.length && "border-dashed")}>
      <div className="flex items-center gap-2 font-semibold">
        <Box className="text-muted-foreground size-4" />
        <span className="truncate">{n.label}</span>
        {n.status && <StatusDot status={n.status as "running"} className="ml-auto" />}
      </div>
      {n.detail.map((d, i) => (
        <div key={d + i} className={cn("truncate text-[11px]", i === 0 ? "text-muted-foreground" : "text-info font-mono")}>
          {d}
        </div>
      ))}
      {n.flags?.map((f) => (
        <div key={f} className="text-muted-foreground text-[11px] italic">
          {f}
        </div>
      ))}
    </Shell>
  );
}

const nodeTypes = { host: HostNode, network: NetworkNode, container: ContainerNode };

export function TopologyGraph({
  networks,
  containers,
  selected,
  onSelect,
}: {
  networks: Network[];
  containers: ContainerSummary[];
  selected: string | null;
  onSelect: (networkId: string) => void;
}) {
  const navigate = useNavigate();
  const { nodes, edges } = useMemo(() => {
    const t = buildTopology(networks, containers);
    const nodes: Node<Data>[] = t.nodes.map((n) => ({
      id: n.id,
      type: n.kind,
      position: { x: n.x - LAYOUT.nodeWidth / 2, y: n.y },
      data: { node: n, selected: n.kind === "network" && n.ref === selected },
      draggable: true,
    }));
    const edges: Edge[] = t.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      type: "smoothstep",
      style: e.dashed ? { strokeDasharray: "5 4" } : { strokeWidth: 1.5 },
      labelStyle: { fontFamily: "var(--font-mono)", fontSize: 10, fill: "var(--muted-foreground)" },
      labelBgStyle: { fill: "var(--card)" },
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
    }));
    return { nodes, edges };
  }, [networks, containers, selected]);

  return (
    <div className="h-[480px]" data-testid="topology">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2, maxZoom: 1.1 }}
        proOptions={{ hideAttribution: true }}
        nodesConnectable={false}
        onNodeClick={(_, node) => {
          const n = (node.data as Data).node;
          if (n.kind === "container") navigate(`/containers/${n.ref}`);
          if (n.kind === "network") onSelect(n.ref);
        }}
        colorMode="system"
      >
        <Background gap={20} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
