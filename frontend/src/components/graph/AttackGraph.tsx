import dagre from "dagre";
import { Download, Maximize2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
  Position,
  useReactFlow,
} from "@xyflow/react";

import { scansApi } from "@/api/scans";
import { GraphLegend } from "@/components/graph/GraphLegend";
import { useUIStore } from "@/store/uiStore";
import type { GraphEdge, GraphNode } from "@/types";

function applyDagreLayout(nodes: Node[], edges: Edge[], rankdir: "LR" | "TB") {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir, nodesep: 80, ranksep: 120, marginx: 40, marginy: 40 });
  g.setDefaultEdgeLabel(() => ({}));

  nodes.forEach((n) => g.setNode(n.id, { width: 180, height: 60 }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);

  return nodes.map((n) => {
    const p = g.node(n.id);
    return {
      ...n,
      position: { x: p.x - 90, y: p.y - 30 },
      sourcePosition: rankdir === "LR" ? Position.Right : Position.Bottom,
      targetPosition: rankdir === "LR" ? Position.Left : Position.Top,
    };
  });
}

function toRfNodes(nodes: GraphNode[]): Node[] {
  return nodes.map((n) => ({
    id: n.id,
    type: "default",
    position: { x: 0, y: 0 },
    data: {
      label: (
        <div className="rounded border border-bg-tertiary bg-bg-secondary px-3 py-2 text-xs">
          {String((n.data?.label as string) || n.type)}
        </div>
      ),
    },
  }));
}

function toRfEdges(edges: GraphEdge[]): Edge[] {
  return edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.label,
    animated: true,
    style: { strokeDasharray: "5 5", stroke: "#64748B" },
  }));
}

export function AttackGraph({ scanId }: { scanId: string }) {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [loading, setLoading] = useState(true);
  const [rankdir, setRankdir] = useState<"LR" | "TB">("LR");
  const { fitView } = useReactFlow();
  const layout = useUIStore((s) => s.graphLayout);

  useEffect(() => {
    const run = async () => {
      setLoading(true);
      try {
        const { data } = await scansApi.graph(scanId);
        const baseNodes = toRfNodes(data.nodes || []);
        const baseEdges = toRfEdges(data.edges || []);
        setNodes(applyDagreLayout(baseNodes, baseEdges, rankdir));
        setEdges(baseEdges);
      } finally {
        setLoading(false);
      }
    };
    void run();
  }, [scanId, rankdir, layout]);

  const nodeColor = useMemo(
    () => (n: Node) => {
      const label = String((n.data as { label?: string })?.label || "").toLowerCase();
      if (label.includes("impact")) return "#EF4444";
      if (label.includes("asset")) return "#22C55E";
      if (label.includes("vuln")) return "#F97316";
      return "#3B82F6";
    },
    []
  );

  const downloadSvg = () => {
    const svg = document.querySelector(".react-flow__viewport")?.closest("svg");
    if (!svg) return;
    const blob = new Blob([svg.outerHTML], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `asre-graph-${scanId}.svg`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return <div className="rounded border border-bg-tertiary bg-bg-secondary p-6 text-text-secondary">Loading graph...</div>;
  }

  return (
    <div className="relative h-[70vh] overflow-hidden rounded border border-bg-tertiary">
      <div className="absolute left-4 top-4 z-10 flex gap-2">
        <button type="button" className="rounded bg-bg-secondary px-2 py-1 text-xs" onClick={() => fitView({ padding: 0.2 })}>
          <Maximize2 className="mr-1 inline h-3 w-3" /> Fit View
        </button>
        <button type="button" className="rounded bg-bg-secondary px-2 py-1 text-xs" onClick={downloadSvg}>
          <Download className="mr-1 inline h-3 w-3" /> Download SVG
        </button>
        <button type="button" className="rounded bg-bg-secondary px-2 py-1 text-xs" onClick={() => setRankdir((v) => (v === "LR" ? "TB" : "LR"))}>
          Layout: {rankdir}
        </button>
      </div>
      <GraphLegend />
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.1}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#334155" gap={20} />
        <Controls />
        <MiniMap nodeColor={nodeColor} bgColor="#1E293B" maskColor="rgba(0,0,0,0.3)" />
      </ReactFlow>
    </div>
  );
}
