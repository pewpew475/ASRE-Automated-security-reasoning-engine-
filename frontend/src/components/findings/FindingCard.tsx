import { CheckCircle2 } from "lucide-react";

import { SeverityBadge } from "@/components/ui/SeverityBadge";
import type { Finding } from "@/types";

export function FindingCard({ finding, onClick }: { finding: Finding; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="w-full rounded border-l-4 border-l-brand border border-bg-tertiary bg-bg-secondary p-3 text-left hover:bg-bg-tertiary/40"
    >
      <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
        <SeverityBadge severity={finding.severity} />
        <span className="rounded bg-bg-tertiary px-2 py-1">{finding.vuln_type}</span>
        <span className="rounded bg-bg-tertiary px-2 py-1">{finding.owasp_category || "N/A"}</span>
        <span className="rounded bg-bg-tertiary px-2 py-1">{finding.mitre_id || "N/A"}</span>
      </div>
      <div className="truncate text-sm font-semibold">{finding.title}</div>
      <div className="truncate font-mono text-xs text-text-secondary">{finding.endpoint_url}</div>
      <div className="mt-1 line-clamp-2 text-xs italic text-text-secondary">{finding.llm_impact || "Analysis not available"}</div>
      <div className="mt-1 flex items-center justify-between text-xs text-text-secondary">
        <span>{Math.round((finding.confidence || 0) * 100)}% confidence</span>
        {finding.is_confirmed ? <CheckCircle2 className="h-4 w-4 text-green-400" /> : null}
      </div>
    </button>
  );
}
