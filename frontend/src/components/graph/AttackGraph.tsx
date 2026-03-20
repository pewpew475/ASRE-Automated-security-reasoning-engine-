import dagre from "dagre";
import { Download, Lock, Maximize2, Minus, Move, Palette, Plus, Unlock } from "lucide-react";
import { memo, useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  Handle,
  MiniMap,
  NodeResizer,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
  Position,
  useReactFlow,
} from "@xyflow/react";

import { scansApi } from "@/api/scans";
import { GraphLegend } from "@/components/graph/GraphLegend";
import { useUIStore } from "@/store/uiStore";
import type { GraphEdge, GraphNode } from "@/types";

type GraphTheme = "neon" | "ocean" | "sunset";

type ResizableNodeData = {
  label: string;
  bgColor: string;
  textColor: "#000000" | "#FFFFFF";
  borderColor: string;
  fontSize: number;
};

const THEMES: Record<
  GraphTheme,
  {
    surface: string;
    edge: string;
    grid: string;
    minimapBg: string;
    minimapMask: string;
  }
> = {
  neon: {
    surface: "linear-gradient(135deg, rgba(15,23,42,0.95), rgba(10,10,24,0.98))",
    edge: "#2DD4BF",
    grid: "#334155",
    minimapBg: "#0F172A",
    minimapMask: "rgba(8,12,24,0.45)",
  },
  ocean: {
    surface: "linear-gradient(135deg, rgba(12,34,56,0.95), rgba(5,23,41,0.98))",
    edge: "#38BDF8",
    grid: "#1E3A8A",
    minimapBg: "#082032",
    minimapMask: "rgba(5,18,30,0.4)",
  },
  sunset: {
    surface: "linear-gradient(135deg, rgba(59,23,11,0.95), rgba(31,17,55,0.98))",
    edge: "#FB7185",
    grid: "#7C2D12",
    minimapBg: "#2A1A2E",
    minimapMask: "rgba(20,10,30,0.4)",
  },
};

function toHex(value: string): string {
  const normalized = value.trim();
  if (!normalized.startsWith("#")) {
    return "#334155";
  }
  if (normalized.length === 4) {
    return `#${normalized[1]}${normalized[1]}${normalized[2]}${normalized[2]}${normalized[3]}${normalized[3]}`;
  }
  return normalized.slice(0, 7);
}

function pickTextColor(bgHex: string): "#000000" | "#FFFFFF" {
  const hex = toHex(bgHex).replace("#", "");
  const r = Number.parseInt(hex.slice(0, 2), 16);
  const g = Number.parseInt(hex.slice(2, 4), 16);
  const b = Number.parseInt(hex.slice(4, 6), 16);
  const luminance = (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
  return luminance > 0.55 ? "#000000" : "#FFFFFF";
}

function applyDagreLayout(nodes: Node[], edges: Edge[], rankdir: "LR" | "TB") {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir, nodesep: 80, ranksep: 120, marginx: 40, marginy: 40 });
  g.setDefaultEdgeLabel(() => ({}));

  nodes.forEach((n) => g.setNode(n.id, { width: 180, height: 60 }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);

  return nodes.map((n) => {
    const p = g.node(n.id);
    const style = n.style as Record<string, unknown> | undefined;
    const width = typeof style?.width === "number" ? style.width : 220;
    const height = typeof style?.height === "number" ? style.height : 90;

    return {
      ...n,
      position: { x: p.x - width / 2, y: p.y - height / 2 },
      sourcePosition: rankdir === "LR" ? Position.Right : Position.Bottom,
      targetPosition: rankdir === "LR" ? Position.Left : Position.Top,
    };
  });
}

const ResizableNode = memo(({ data, selected }: NodeProps) => {
  const typed = data as ResizableNodeData;
  return (
    <>
      <Handle
        type="target"
        position={Position.Left}
        style={{ width: 8, height: 8, background: "#FFFFFF", border: "1px solid #0F172A" }}
      />
      <NodeResizer
        isVisible={selected}
        minWidth={140}
        minHeight={56}
        lineStyle={{ borderColor: "#FFFFFF" }}
        handleStyle={{ background: "#FFFFFF", width: 8, height: 8, borderRadius: 999 }}
      />
      <div
        className="h-full w-full rounded-xl border px-3 py-2 shadow"
        style={{
          color: typed.textColor,
          borderColor: typed.borderColor,
          background: `${typed.bgColor}E6`,
          fontSize: `${typed.fontSize}px`,
          backdropFilter: "blur(2px)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          textAlign: "center",
          fontWeight: 700,
          lineHeight: 1.2,
          userSelect: "none",
        }}
      >
        {typed.label}
      </div>
      <Handle
        type="source"
        position={Position.Right}
        style={{ width: 8, height: 8, background: "#FFFFFF", border: "1px solid #0F172A" }}
      />
    </>
  );
});

const nodeTypes: NodeTypes = { resizable: ResizableNode };

function toRfNodes(nodes: GraphNode[], nodeScale: number): Node[] {
  const labelSize = Math.max(10, Math.round(11 * (nodeScale / 100)));
  const width = Math.max(160, Math.round(220 * (nodeScale / 100)));
  const height = Math.max(64, Math.round(90 * (nodeScale / 100)));

  return nodes.map((n) => ({
    id: n.id,
    type: "resizable",
    position: { x: 0, y: 0 },
    data: {
      label: String((n.data?.label as string) || n.type),
      bgColor: String((n.data?.color as string) || "#334155"),
      textColor: pickTextColor(String((n.data?.color as string) || "#334155")),
      borderColor:
        pickTextColor(String((n.data?.color as string) || "#334155")) === "#000000"
          ? "rgba(0,0,0,0.35)"
          : "rgba(255,255,255,0.35)",
      fontSize: labelSize,
    },
    style: {
      width,
      height,
    },
    draggable: true,
    selectable: true,
  }));
}

function toRfEdges(edges: GraphEdge[], edgeColor: string): Edge[] {
  return edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.label,
    animated: true,
    style: { strokeDasharray: "5 5", stroke: edgeColor, strokeWidth: 1.6 },
    labelStyle: { fill: "#000000", fontSize: 10, fontWeight: 700 },
    labelShowBg: true,
    labelBgStyle: { fill: "#FFFFFF", fillOpacity: 0.98, stroke: "#0F172A", strokeWidth: 0.6 },
    labelBgPadding: [6, 3],
    labelBgBorderRadius: 6,
  }));
}

function AttackGraphInner({ scanId }: { scanId: string }) {
  const [rawNodes, setRawNodes] = useState<GraphNode[]>([]);
  const [rawEdges, setRawEdges] = useState<GraphEdge[]>([]);
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [loading, setLoading] = useState(true);
  const [rankdir, setRankdir] = useState<"LR" | "TB">("LR");
  const [theme, setTheme] = useState<GraphTheme>("neon");
  const [nodeScale, setNodeScale] = useState(100);
  const [locked, setLocked] = useState(false);
  const { fitView, zoomIn, zoomOut } = useReactFlow();
  const layout = useUIStore((s) => s.graphLayout);

  useEffect(() => {
    const run = async () => {
      setLoading(true);
      try {
        const { data } = await scansApi.graph(scanId);
        setRawNodes(data.nodes || []);
        setRawEdges(data.edges || []);
      } finally {
        setLoading(false);
      }
    };
    void run();
  }, [scanId, layout]);

  useEffect(() => {
    const themed = THEMES[theme];
    const baseNodes = toRfNodes(rawNodes, nodeScale);
    const baseEdges = toRfEdges(rawEdges, themed.edge);
    setNodes(applyDagreLayout(baseNodes, baseEdges, rankdir));
    setEdges(baseEdges);
  }, [rawNodes, rawEdges, rankdir, nodeScale, theme, setEdges, setNodes]);

  const nodeColor = useMemo(
    () => (n: Node) => {
      const label = String((n.data as { label?: string })?.label || "").toLowerCase();
      if (label.includes("impact")) return "#F43F5E";
      if (label.includes("asset")) return "#22C55E";
      if (label.includes("vuln")) return "#F59E0B";
      return "#38BDF8";
    },
    []
  );

  const themed = THEMES[theme];

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

  if (!rawNodes.length && !rawEdges.length) {
    return <div className="rounded border border-bg-tertiary bg-bg-secondary p-6 text-text-secondary">No graph data generated for this scan yet.</div>;
  }

  return (
    <div className="relative h-[72vh] overflow-hidden rounded border border-bg-tertiary" style={{ background: themed.surface }}>
      <div className="absolute left-4 top-4 z-10 flex flex-wrap gap-2">
        <button type="button" className="rounded border border-slate-300 bg-white px-2 py-1 text-xs text-black" onClick={() => fitView({ padding: 0.2 })}>
          <Maximize2 className="mr-1 inline h-3 w-3" /> Fit View
        </button>
        <button type="button" className="rounded border border-slate-300 bg-white px-2 py-1 text-xs text-black" onClick={() => zoomIn({ duration: 120 })}>
          <Plus className="mr-1 inline h-3 w-3" /> Zoom In
        </button>
        <button type="button" className="rounded border border-slate-300 bg-white px-2 py-1 text-xs text-black" onClick={() => zoomOut({ duration: 120 })}>
          <Minus className="mr-1 inline h-3 w-3" /> Zoom Out
        </button>
        <button type="button" className="rounded border border-slate-300 bg-white px-2 py-1 text-xs text-black" onClick={downloadSvg}>
          <Download className="mr-1 inline h-3 w-3" /> Download SVG
        </button>
        <button type="button" className="rounded border border-slate-300 bg-white px-2 py-1 text-xs text-black" onClick={() => setRankdir((v) => (v === "LR" ? "TB" : "LR"))}>
          Layout: {rankdir}
        </button>
        <button type="button" className="rounded border border-slate-300 bg-white px-2 py-1 text-xs text-black" onClick={() => setLocked((v) => !v)}>
          {locked ? <Lock className="mr-1 inline h-3 w-3" /> : <Unlock className="mr-1 inline h-3 w-3" />} {locked ? "Locked" : "Unlocked"}
        </button>
      </div>

      <div className="absolute bottom-4 left-4 z-10 flex items-center gap-2 rounded border border-slate-300 bg-white/95 px-3 py-2 text-xs text-black backdrop-blur">
        <Move className="h-3 w-3" />
        <span>Node Size</span>
        <input
          type="range"
          min={80}
          max={160}
          step={5}
          value={nodeScale}
          onChange={(e) => setNodeScale(Number(e.target.value))}
        />
        <span className="w-8 text-right">{nodeScale}%</span>
        <Palette className="ml-2 h-3 w-3" />
        <select
          value={theme}
          onChange={(e) => setTheme(e.target.value as GraphTheme)}
          className="rounded border border-slate-300 bg-white px-2 py-1 text-xs text-black"
        >
          <option value="neon">Neon</option>
          <option value="ocean">Ocean</option>
          <option value="sunset">Sunset</option>
        </select>
        <span className="ml-2 text-[11px] font-semibold text-black">Select box, then drag corners to resize</span>
      </div>

      <GraphLegend />
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodesDraggable={!locked}
        nodesConnectable={false}
        elementsSelectable={!locked}
        panOnDrag
        panOnScroll
        zoomOnScroll
        zoomOnPinch
        zoomOnDoubleClick
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.1}
        maxZoom={2.5}
        proOptions={{ hideAttribution: true }}
      >
        <Background color={themed.grid} gap={20} />
        <Controls />
        <MiniMap nodeColor={nodeColor} bgColor={themed.minimapBg} maskColor={themed.minimapMask} />
      </ReactFlow>
    </div>
  );
}

export function AttackGraph({ scanId }: { scanId: string }) {
  return (
    <ReactFlowProvider>
      <AttackGraphInner scanId={scanId} />
    </ReactFlowProvider>
  );
}
