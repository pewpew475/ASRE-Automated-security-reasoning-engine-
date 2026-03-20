import { AlertTriangle } from "lucide-react";
import { useMemo, useState } from "react";

import type { ChainData } from "@/types";

export function ChainCard({ chain }: { chain: ChainData }) {
  const [expanded, setExpanded] = useState(false);
  const nodePath = Array.isArray(chain.nodes)
    ? chain.nodes.filter((item) => typeof item === "string" && item.trim().length > 0)
    : [];

  const urgency = useMemo(() => {
    if (chain.severity_score >= 8) return "critical";
    if (chain.severity_score >= 6.5) return "high";
    if (chain.severity_score >= 4.5) return "medium";
    return "low";
  }, [chain.severity_score]);

  const analysisText =
    (chain.llm_analysis || "").trim() ||
    "Chain narrative is not generated in this run. The path and severity are available for prioritization.";

  return (
    <article className="rounded-xl border border-bg-tertiary bg-bg-secondary/90 p-3 shadow-sm shadow-black/20 transition hover:border-brand/60">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="rounded bg-red-900/30 px-2 py-1 text-xs font-semibold">{chain.severity_score.toFixed(1)}/10</span>
        <span className="text-xs text-text-secondary">{chain.length} hops</span>
      </div>
      <div className="mb-2 line-clamp-2 text-sm font-semibold">{chain.entry_point} → {chain.final_impact}</div>
      <div className="text-xs text-text-secondary">{nodePath.length ? nodePath.join(" → ") : "Chain path unavailable"}</div>
      <div className="mt-2 rounded border-l-2 border-brand bg-bg-primary p-2 text-xs text-text-secondary">
        {expanded ? analysisText : `${analysisText.slice(0, 165)}${analysisText.length > 165 ? "..." : ""}`}
      </div>
      <div className="mt-2 flex items-center justify-between">
        <div className="inline-flex items-center gap-1 text-xs text-text-secondary">
          <AlertTriangle className="h-3 w-3" /> urgency: {urgency}
        </div>
        {analysisText.length > 165 ? (
          <button
            type="button"
            onClick={() => setExpanded((prev) => !prev)}
            className="text-xs text-brand hover:text-text-primary"
          >
            {expanded ? "Show less" : "Read analysis"}
          </button>
        ) : null}
      </div>
    </article>
  );
}
