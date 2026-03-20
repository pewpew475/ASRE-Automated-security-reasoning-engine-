import type { Finding } from "@/types";
import { SeverityBadge } from "@/components/ui/SeverityBadge";

export function LiveFindingsFeed({ findings }: { findings: Finding[] }) {
  return (
    <div className="rounded-lg border border-bg-tertiary bg-bg-secondary p-3">
      <div className="mb-2 text-xs text-text-secondary">Showing {findings.length} live findings</div>
      <div className="max-h-72 space-y-2 overflow-auto pr-1">
        {findings.map((f) => (
          <div key={f.id} className="animate-[fadeIn_0.2s_ease] rounded border border-bg-tertiary p-2 text-xs">
            <div className="mb-1 flex items-center gap-2">
              <SeverityBadge severity={f.severity} />
              <span className="text-text-secondary">{f.vuln_type}</span>
            </div>
            <div className="truncate font-medium">{f.title}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
