import { Download } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
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

export function ScanDetailPage() {
  const { scanId = "" } = useParams();
  const activeScan = useScanStore((s) => s.activeScan);
  const fetchScan = useScanStore((s) => s.fetchScan);
  const [chains, setChains] = useState<ChainData[]>([]);
  const [tab, setTab] = useState<TabType>("findings");

  useEffect(() => {
    if (scanId) {
      void fetchScan(scanId);
      void scansApi.chains(scanId).then((r) => setChains(r.data)).catch(() => setChains([]));
    }
  }, [fetchScan, scanId]);

  const isRunning = useMemo(
    () => Boolean(activeScan && ["pending", "crawling", "scanning", "chaining", "analyzing", "generating_poc", "reporting"].includes(activeScan.status)),
    [activeScan]
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
        <button type="button" onClick={onDownload} className="rounded bg-brand px-3 py-2 text-sm font-medium text-bg-primary">
          <Download className="mr-1 inline h-4 w-4" /> Download PDF
        </button>
      </div>

      <div className="flex gap-2">
        {tabs.map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`rounded px-3 py-1.5 text-sm ${tab === t ? "bg-brand text-bg-primary" : "bg-bg-secondary text-text-secondary"}`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "findings" ? <FindingsList scanId={scanId} /> : null}
      {tab === "graph" ? <AttackGraph scanId={scanId} /> : null}
      {tab === "chains" ? <div className="grid gap-3 md:grid-cols-2">{chains.map((c) => <ChainCard key={c.path_id} chain={c} />)}</div> : null}
      {tab === "raw" ? (
        <CodeBlock language="json" code={JSON.stringify({ scan: activeScan, chains }, null, 2)} filename={`scan-${scanId}.json`} />
      ) : null}
    </div>
  );
}
