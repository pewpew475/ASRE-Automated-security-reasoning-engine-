import { Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { FindingCard } from "@/components/findings/FindingCard";
import { FindingDetail } from "@/components/findings/FindingDetail";
import { EmptyState } from "@/components/ui/EmptyState";
import { useScanStore } from "@/store/scanStore";
import type { Finding } from "@/types";

const severityOrder: Array<Finding["severity"]> = ["critical", "high", "medium", "low", "info"];

export function FindingsList({ scanId }: { scanId: string }) {
  const findings = useScanStore((s) => s.findings);
  const fetchFindings = useScanStore((s) => s.fetchFindings);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [severity, setSeverity] = useState<string>("all");
  const [vulnType, setVulnType] = useState<string>("all");
  const [query, setQuery] = useState("");

  useEffect(() => {
    void fetchFindings(scanId);
  }, [fetchFindings, scanId]);

  const vulnTypes = useMemo(() => ["all", ...Array.from(new Set(findings.map((f) => f.vuln_type)))], [findings]);

  const filtered = useMemo(
    () =>
      findings.filter((f) => {
        const severityMatch = severity === "all" || f.severity === severity;
        const typeMatch = vulnType === "all" || f.vuln_type === vulnType;
        const q = query.toLowerCase();
        const queryMatch = !q || f.title.toLowerCase().includes(q) || f.endpoint_url.toLowerCase().includes(q);
        return severityMatch && typeMatch && queryMatch;
      }),
    [findings, query, severity, vulnType]
  );

  if (!findings.length) {
    return <EmptyState icon={Search} title="No findings" description="This scan has no findings yet." />;
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-2 rounded border border-bg-tertiary bg-bg-secondary p-3 md:grid-cols-3">
        <div className="flex flex-wrap gap-1">
          {["all", ...severityOrder].map((s) => (
            <button key={s} type="button" onClick={() => setSeverity(s)} className={`rounded px-2 py-1 text-xs ${severity === s ? "bg-brand text-bg-primary" : "bg-bg-tertiary"}`}>
              {s}
            </button>
          ))}
        </div>
        <select value={vulnType} onChange={(e) => setVulnType(e.target.value)} className="rounded bg-bg-primary px-2 py-1 text-xs">
          {vulnTypes.map((v) => (
            <option key={v} value={v}>{v}</option>
          ))}
        </select>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search title or URL"
          className="rounded bg-bg-primary px-2 py-1 text-xs"
        />
      </div>

      {severityOrder.map((s) => {
        const list = filtered.filter((f) => f.severity === s);
        if (!list.length) {
          return null;
        }
        return (
          <section key={s} className="space-y-2">
            <h3 className="text-sm font-semibold">{s.toUpperCase()} ({list.length})</h3>
            {list.map((f) => (
              <FindingCard key={f.id} finding={f} onClick={() => setSelected(f)} />
            ))}
          </section>
        );
      })}

      <FindingDetail finding={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
