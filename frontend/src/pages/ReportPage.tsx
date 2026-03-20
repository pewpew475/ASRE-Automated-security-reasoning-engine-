import { type ReactNode, useEffect } from "react";
import { AlertTriangle, Download, ShieldAlert, Workflow } from "lucide-react";
import { useParams } from "react-router-dom";
import toast from "react-hot-toast";

import { reportsApi } from "@/api/reports";
import { FindingsList } from "@/components/findings/FindingsList";
import { ReportAssistantPanel } from "@/components/report/ReportAssistantPanel";
import { useScanStore } from "@/store/scanStore";

export function ReportPage() {
  const { scanId = "" } = useParams();
  const activeScan = useScanStore((s) => s.activeScan);
  const fetchScan = useScanStore((s) => s.fetchScan);

  useEffect(() => {
    if (scanId) {
      void fetchScan(scanId);
    }
  }, [fetchScan, scanId]);

  const onDownload = async () => {
    try {
      const blob = await reportsApi.download(scanId);
      const url = URL.createObjectURL(blob.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = `asre-report-${scanId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      toast.error("Download failed");
    }
  };

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-bg-tertiary bg-bg-secondary/90 p-5 shadow-lg shadow-black/20 backdrop-blur">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-semibold">Security Report Preview</h1>
            <p className="text-sm text-text-secondary">Interactive report review for scan {scanId}</p>
          </div>
          <button type="button" onClick={onDownload} className="rounded-md bg-brand px-3 py-2 text-sm font-medium text-bg-primary">
            <Download className="mr-1 inline h-4 w-4" /> Download PDF
          </button>
        </div>
        {activeScan ? (
          <div className="mt-4 grid gap-3 md:grid-cols-4">
            <MetricCard title="Total Findings" value={activeScan.vulns_found} icon={<ShieldAlert className="h-4 w-4" />} />
            <MetricCard title="Attack Chains" value={activeScan.chains_found} icon={<Workflow className="h-4 w-4" />} />
            <MetricCard title="Scan Mode" value={String(activeScan.mode).toUpperCase()} icon={<AlertTriangle className="h-4 w-4" />} />
            <MetricCard title="Status" value={String(activeScan.status).toUpperCase()} icon={<ShieldAlert className="h-4 w-4" />} />
          </div>
        ) : null}
      </div>

      <div className="flex flex-col gap-4 xl:flex-row">
        <section className="space-y-4">
          <FindingsList scanId={scanId} />
        </section>
        <section className="min-h-[calc(100vh-12rem)] w-full overflow-auto xl:min-w-[360px] xl:max-w-[820px] xl:resize-x xl:w-[460px]">
          <ReportAssistantPanel scanId={scanId} />
        </section>
      </div>
    </div>
  );
}

function MetricCard({ title, value, icon }: { title: string; value: string | number; icon: ReactNode }) {
  return (
    <article className="rounded-lg border border-bg-tertiary bg-bg-primary/70 p-3">
      <div className="mb-2 flex items-center justify-between text-xs uppercase tracking-wide text-text-secondary">
        <span>{title}</span>
        {icon}
      </div>
      <div className="text-lg font-semibold text-text-primary">{value}</div>
    </article>
  );
}
