import { useEffect } from "react";
import { Download } from "lucide-react";
import { useParams } from "react-router-dom";
import toast from "react-hot-toast";

import { reportsApi } from "@/api/reports";
import { FindingsList } from "@/components/findings/FindingsList";
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
      <div className="rounded-lg border border-bg-tertiary bg-bg-secondary p-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-semibold">Security Report Preview</h1>
            <p className="text-sm text-text-secondary">Read-only web view for scan {scanId}</p>
          </div>
          <button type="button" onClick={onDownload} className="rounded bg-brand px-3 py-2 text-sm font-medium text-bg-primary">
            <Download className="mr-1 inline h-4 w-4" /> Download PDF
          </button>
        </div>
        {activeScan ? (
          <div className="mt-3 grid gap-2 text-sm text-text-secondary md:grid-cols-4">
            <div>Total Findings: {activeScan.vulns_found}</div>
            <div>Chains: {activeScan.chains_found}</div>
            <div>Mode: {activeScan.mode}</div>
            <div>Status: {activeScan.status}</div>
          </div>
        ) : null}
      </div>

      <FindingsList scanId={scanId} />
    </div>
  );
}
