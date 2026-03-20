import { AlertTriangle } from "lucide-react";

import type { ChainData } from "@/types";

export function ChainCard({ chain }: { chain: ChainData }) {
  const nodePath = Array.isArray(chain.nodes)
    ? chain.nodes.filter((item) => typeof item === "string" && item.trim().length > 0)
    : [];

  return (
    <article className="rounded border border-bg-tertiary bg-bg-secondary p-3">
      <div className="mb-2 flex items-center justify-between">
        <span className="rounded bg-red-900/30 px-2 py-1 text-xs">{chain.severity_score}/10</span>
        <span className="text-xs text-text-secondary">{chain.length} hops</span>
      </div>
      <div className="mb-2 text-sm font-semibold">{chain.entry_point} → {chain.final_impact}</div>
      <div className="text-xs text-text-secondary">{nodePath.length ? nodePath.join(" → ") : "Chain path unavailable"}</div>
      <div className="mt-2 rounded border-l-2 border-brand bg-bg-primary p-2 text-xs italic text-text-secondary">
        {chain.llm_analysis || "Analysis pending"}
      </div>
      <div className="mt-2 inline-flex items-center gap-1 text-xs text-text-secondary"><AlertTriangle className="h-3 w-3" /> urgency: high</div>
    </article>
  );
}
