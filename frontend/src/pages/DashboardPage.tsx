import { AlertTriangle, Activity, Bug, Shield } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { type ComponentType, useEffect, useMemo } from "react";
import { Link, useNavigate } from "react-router-dom";
import toast from "react-hot-toast";

import { reportsApi } from "@/api/reports";
import { useScanStore } from "@/store/scanStore";
import { useUIStore } from "@/store/uiStore";
import { StatusBadge } from "@/components/ui/StatusBadge";
import type { Scan } from "@/types";

export function DashboardPage() {
  const navigate = useNavigate();
  const scans = useScanStore((s) => s.scans);
  const fetchScans = useScanStore((s) => s.fetchScans);
  const deleteScan = useScanStore((s) => s.deleteScan);
  const llmStatus = useUIStore((s) => s.llmStatus);
  const fetchLLMStatus = useUIStore((s) => s.fetchLLMStatus);

  useEffect(() => {
    void fetchScans();
    void fetchLLMStatus();
  }, [fetchScans, fetchLLMStatus]);

  const stats = useMemo(() => {
    const active = scans.filter((s) => ["pending", "crawling", "scanning", "chaining", "analyzing", "generating_poc", "reporting"].includes(s.status)).length;
    const totalFindings = scans.reduce((acc, s) => acc + Number(s.vulns_found || 0), 0);
    const critical = scans.reduce((acc, s) => acc + ((Number(s.vulns_found || 0) > 0 && s.status === "completed") ? 1 : 0), 0);
    return { total: scans.length, active, totalFindings, critical };
  }, [scans]);

  const onDownload = async (scan: Scan) => {
    if (scan.status !== "completed") {
      toast.error("Report is available only after scan completion");
      return;
    }

    try {
      const blob = await reportsApi.download(scan.id);
      const url = URL.createObjectURL(blob.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = `asre-report-${scan.id}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      toast.error("Report download failed");
    }
  };

  return (
    <div className="space-y-6">
      {!llmStatus?.configured ? (
        <div className="rounded-lg border border-yellow-400/40 bg-yellow-500/10 p-3 text-sm text-yellow-100">
          ⚠ No LLM configured - analysis features disabled. <Link to="/settings" className="text-brand">Open Settings</Link>
        </div>
      ) : null}

      <div className="grid gap-3 md:grid-cols-4">
        <StatCard icon={Shield} title="Total Scans" value={stats.total} />
        <StatCard icon={Activity} title="Active Scans" value={stats.active} pulse={stats.active > 0} />
        <StatCard icon={Bug} title="Total Findings" value={stats.totalFindings} />
        <StatCard icon={AlertTriangle} title="Critical Findings" value={stats.critical} danger />
      </div>

      <div className="rounded-xl border border-bg-tertiary bg-bg-secondary p-4">
        <h2 className="mb-3 text-lg font-semibold">Recent Scans</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-text-secondary">
              <tr>
                <th className="pb-2">Target</th>
                <th className="pb-2">Mode</th>
                <th className="pb-2">Status</th>
                <th className="pb-2">Findings</th>
                <th className="pb-2">Chains</th>
                <th className="pb-2">Started</th>
                <th className="pb-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id} className="border-t border-bg-tertiary/70 hover:bg-bg-primary/40">
                  <td className="py-2 font-mono text-xs">{scan.target_url}</td>
                  <td className="py-2">
                    <span className={`rounded px-2 py-1 text-xs ${scan.mode === "hardcore" ? "bg-severity-critical/25 text-severity-criticalFg" : "bg-brand/20 text-brand"}`}>
                      {scan.mode.toUpperCase()}
                    </span>
                  </td>
                  <td className="py-2"><StatusBadge status={scan.status} /></td>
                  <td className="py-2">{scan.vulns_found}</td>
                  <td className="py-2">{scan.chains_found}</td>
                  <td className="py-2 text-text-secondary">{scan.started_at ? formatDistanceToNow(new Date(scan.started_at), { addSuffix: true }) : "-"}</td>
                  <td className="py-2">
                    <div className="flex gap-2 text-xs">
                      <button type="button" className="rounded bg-bg-primary px-2 py-1" onClick={() => navigate(`/scans/${scan.id}`)}>View</button>
                      <button type="button" className="rounded bg-bg-primary px-2 py-1" onClick={() => onDownload(scan)}>Report</button>
                      <button
                        type="button"
                        className="rounded bg-severity-critical/25 px-2 py-1 text-severity-criticalFg"
                        onClick={() => {
                          void deleteScan(scan.id).catch(() => {
                            toast.error("Delete failed");
                          });
                        }}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function StatCard({
  icon: Icon,
  title,
  value,
  pulse,
  danger,
}: {
  icon: ComponentType<{ className?: string }>;
  title: string;
  value: number;
  pulse?: boolean;
  danger?: boolean;
}) {
  return (
    <div className="rounded-lg border border-bg-tertiary bg-bg-secondary p-4">
      <div className="mb-2 flex items-center justify-between text-text-secondary">
        <span className="text-sm">{title}</span>
        <Icon className={`h-4 w-4 ${danger ? "text-severity-high" : "text-brand"} ${pulse ? "animate-pulse" : ""}`} />
      </div>
      <div className={`text-2xl font-bold ${danger ? "text-severity-high" : "text-text-primary"}`}>{value}</div>
    </div>
  );
}
