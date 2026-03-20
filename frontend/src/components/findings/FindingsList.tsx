import { Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { FindingCard } from "@/components/findings/FindingCard";
import { FindingDetail } from "@/components/findings/FindingDetail";
import { EmptyState } from "@/components/ui/EmptyState";
import { useScanStore } from "@/store/scanStore";
import type { Finding } from "@/types";

const severityOrder: Array<Finding["severity"]> = ["critical", "high", "medium", "low", "info"];
const severityRank: Record<Finding["severity"], number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function FindingsList({ scanId }: { scanId: string }) {
  const findings = useScanStore((s) => s.findings);
  const fetchFindings = useScanStore((s) => s.fetchFindings);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [severity, setSeverity] = useState<string>("all");
  const [vulnType, setVulnType] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [sortBy, setSortBy] = useState<"severity" | "confidence" | "recent">("severity");

  useEffect(() => {
    void fetchFindings(scanId);
  }, [fetchFindings, scanId]);

  const vulnTypes = useMemo(() => ["all", ...Array.from(new Set(findings.map((f) => f.vuln_type)))], [findings]);

  const filtered = useMemo(
    () => {
      const base = findings.filter((f) => {
        const severityMatch = severity === "all" || f.severity === severity;
        const typeMatch = vulnType === "all" || f.vuln_type === vulnType;
        const q = query.toLowerCase();
        const queryMatch = !q || f.title.toLowerCase().includes(q) || f.endpoint_url.toLowerCase().includes(q);
        return severityMatch && typeMatch && queryMatch;
      });

      const sorted = [...base];
      if (sortBy === "severity") {
        sorted.sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);
      } else if (sortBy === "confidence") {
        sorted.sort((a, b) => Number(b.confidence || 0) - Number(a.confidence || 0));
      } else {
        sorted.sort((a, b) => String(b.id).localeCompare(String(a.id)));
      }
      return sorted;
    },
    [findings, query, severity, sortBy, vulnType]
  );

  const counts = useMemo(() => {
    return {
      total: findings.length,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length,
    };
  }, [findings]);

  if (!findings.length) {
    return <EmptyState icon={Search} title="No findings" description="This scan has no findings yet." />;
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-2 md:grid-cols-6">
        <SummaryCard label="Total" value={counts.total} />
        <SummaryCard label="Critical" value={counts.critical} intent="critical" />
        <SummaryCard label="High" value={counts.high} intent="high" />
        <SummaryCard label="Medium" value={counts.medium} intent="medium" />
        <SummaryCard label="Low" value={counts.low} intent="low" />
        <SummaryCard label="Info" value={counts.info} intent="info" />
      </div>

      <div className="grid gap-2 rounded-xl border border-bg-tertiary bg-bg-secondary p-3 md:grid-cols-4">
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
        <select value={sortBy} onChange={(e) => setSortBy(e.target.value as "severity" | "confidence" | "recent")} className="rounded bg-bg-primary px-2 py-1 text-xs">
          <option value="severity">Sort: Severity</option>
          <option value="confidence">Sort: Confidence</option>
          <option value="recent">Sort: Newest</option>
        </select>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search title or URL"
          className="rounded bg-bg-primary px-2 py-1 text-xs"
        />
      </div>

      <div className="text-xs text-text-secondary">Showing {filtered.length} of {findings.length} findings</div>

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

function SummaryCard({
  label,
  value,
  intent = "default",
}: {
  label: string;
  value: number;
  intent?: "critical" | "high" | "medium" | "low" | "info" | "default";
}) {
  const intentClass: Record<string, string> = {
    default: "border-bg-tertiary text-text-primary",
    critical: "border-severity-critical/40 text-severity-criticalFg",
    high: "border-severity-high/40 text-severity-highFg",
    medium: "border-severity-medium/40 text-severity-mediumFg",
    low: "border-severity-low/40 text-severity-lowFg",
    info: "border-severity-info/40 text-severity-infoFg",
  };

  return (
    <article className={`rounded-lg border bg-bg-secondary p-3 ${intentClass[intent] || intentClass.default}`}>
      <div className="text-xs uppercase tracking-wide text-text-secondary">{label}</div>
      <div className="mt-1 text-lg font-semibold">{value}</div>
    </article>
  );
}
