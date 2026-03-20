import { Download } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useParams } from "react-router-dom";
import toast from "react-hot-toast";

import { reportsApi } from "@/api/reports";
import { AttackGraph } from "@/components/graph/AttackGraph";
import { ChainCard } from "@/components/graph/ChainCard";
import { FindingsList } from "@/components/findings/FindingsList";
import { ScanProgressPanel } from "@/components/scan/ScanProgressPanel";
import { CodeBlock } from "@/components/ui/CodeBlock";
import { EmptyState } from "@/components/ui/EmptyState";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { scansApi } from "@/api/scans";
import { useScanStore } from "@/store/scanStore";
import type { ChainData } from "@/types";

const tabs = ["findings", "graph", "chains", "raw"] as const;

type TabType = (typeof tabs)[number];

const graphReadyStatuses = new Set([
  "completed",
  "analyzing",
  "chaining",
  "generating_poc",
  "reporting",
]);

export function ScanDetailPage() {
  const { scanId = "" } = useParams();
  const activeScan = useScanStore((s) => s.activeScan);
  const fetchScan = useScanStore((s) => s.fetchScan);
  const [chains, setChains] = useState<ChainData[]>([]);
  const [tab, setTab] = useState<TabType>("findings");
  const [minSeverity, setMinSeverity] = useState(0);

  useEffect(() => {
    if (scanId) {
      void fetchScan(scanId);
    }
  }, [fetchScan, scanId]);

  useEffect(() => {
    if (!scanId || !activeScan || activeScan.id !== scanId) {
      setChains([]);
      return;
    }

    if (!graphReadyStatuses.has(activeScan.status)) {
      setChains([]);
      return;
    }

    let cancelled = false;
    void scansApi
      .chains(scanId)
      .then((r) => {
        if (!cancelled) {
          setChains(r.data);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setChains([]);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [activeScan, scanId]);

  const isRunning = useMemo(
    () => Boolean(activeScan && ["pending", "crawling", "scanning", "chaining", "analyzing", "generating_poc", "reporting"].includes(activeScan.status)),
    [activeScan]
  );

  const visibleChains = useMemo(
    () => chains.filter((chain) => Number(chain.severity_score || 0) >= minSeverity),
    [chains, minSeverity]
  );

  const onDownload = async () => {
    if (!scanId) return;
    try {
      const blob = await reportsApi.download(scanId);
      const url = URL.createObjectURL(blob.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = `asre-report-${scanId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      toast.error("Unable to download report");
    }
  };

  if (!activeScan) {
    return <EmptyState icon={Download} title="Loading scan" description="Fetching scan details..." />;
  }

  if (isRunning) {
    return <ScanProgressPanel scanId={scanId} />;
  }

  if (activeScan.status === "failed") {
    return (
      <div className="rounded-lg border border-severity-high/40 bg-severity-high/10 p-4">
        <h2 className="text-lg font-semibold text-severity-high">Scan failed</h2>
        <p className="mt-1 text-text-secondary">{activeScan.error_message || "Unknown error"}</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-bg-tertiary bg-bg-secondary p-4">
        <div>
          <h1 className="font-mono text-sm text-text-secondary">{activeScan.target_url}</h1>
          <div className="mt-1 flex items-center gap-2 text-sm">
            <span className={`rounded px-2 py-0.5 ${activeScan.mode === "hardcore" ? "bg-severity-critical/25 text-severity-criticalFg" : "bg-brand/20 text-brand"}`}>
              {activeScan.mode.toUpperCase()}
            </span>
            <StatusBadge status={activeScan.status} />
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Link to={`/scans/${scanId}/report`} className="rounded border border-brand/40 bg-bg-primary px-3 py-2 text-sm font-medium text-text-primary hover:border-brand">
            Open Report
          </Link>
          <button type="button" onClick={onDownload} className="rounded bg-brand px-3 py-2 text-sm font-medium text-bg-primary">
            <Download className="mr-1 inline h-4 w-4" /> Download PDF
          </button>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 rounded-lg border border-bg-tertiary bg-bg-secondary p-2">
        {tabs.map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`rounded px-3 py-1.5 text-sm capitalize ${tab === t ? "bg-brand text-bg-primary" : "bg-bg-primary text-text-secondary hover:text-text-primary"}`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "findings" ? <FindingsList scanId={scanId} /> : null}
      {tab === "graph" ? <AttackGraph scanId={scanId} /> : null}
      {tab === "chains" ? (
        <section className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-bg-tertiary bg-bg-secondary p-3">
            <div>
              <h3 className="text-sm font-semibold">Attack Chains</h3>
              <p className="text-xs text-text-secondary">Showing {visibleChains.length} of {chains.length} chains</p>
            </div>
            <label className="flex items-center gap-2 text-xs text-text-secondary">
              Min severity score
              <input
                type="range"
                min={0}
                max={10}
                step={0.5}
                value={minSeverity}
                onChange={(event) => setMinSeverity(Number(event.target.value))}
              />
              <span className="w-8 text-right text-text-primary">{minSeverity.toFixed(1)}</span>
            </label>
          </div>
          {visibleChains.length ? <div className="grid gap-3 md:grid-cols-2">{visibleChains.map((c) => <ChainCard key={c.path_id} chain={c} />)}</div> : <EmptyState icon={Download} title="No chains for this filter" description="Lower the severity threshold to reveal additional chains." />}
        </section>
      ) : null}
      {tab === "raw" ? (
        <CodeBlock language="json" code={JSON.stringify({ scan: activeScan, chains }, null, 2)} filename={`scan-${scanId}.json`} />
      ) : null}
    </div>
  );
}
