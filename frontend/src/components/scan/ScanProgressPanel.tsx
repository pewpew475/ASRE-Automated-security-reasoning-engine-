import { useMemo } from "react";

import { LiveFindingsFeed } from "@/components/scan/LiveFindingsFeed";
import { ScanPhaseTimeline } from "@/components/scan/ScanPhaseTimeline";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { useScanProgress } from "@/hooks/useScanProgress";
import { useScanWebSocket } from "@/hooks/useScanWebSocket";
import { useScanStore } from "@/store/scanStore";

export function ScanProgressPanel({ scanId }: { scanId: string }) {
  const progress = useScanStore((s) => s.progress);
  const liveFindings = useScanStore((s) => s.liveFindings);
  const { connected } = useScanWebSocket(scanId);
  const { percentComplete, elapsedSeconds } = useScanProgress();

  const completedPhases = useMemo(() => {
    const order = ["crawling", "scanning", "chaining", "analyzing", "generating_poc", "reporting"];
    const idx = order.indexOf(progress.phase);
    return idx > 0 ? order.slice(0, idx) : [];
  }, [progress.phase]);

  return (
    <section className="space-y-4 rounded-lg border border-bg-tertiary bg-bg-secondary p-4">
      <div className="flex items-center justify-between text-xs text-text-secondary">
        <span>WebSocket: {connected ? "connected" : "disconnected"}</span>
        <span>Elapsed: {elapsedSeconds}s</span>
      </div>
      <ScanPhaseTimeline currentPhase={progress.phase} completedPhases={completedPhases} />
      <ProgressBar value={percentComplete} label={`Phase: ${progress.phase}`} />
      <div className="grid grid-cols-2 gap-2 text-sm md:grid-cols-4">
        <Stat label="Endpoints" value={progress.endpoints_found} />
        <Stat label="Findings" value={progress.vulns_found} />
        <Stat label="Chains" value={progress.chains_found} />
        <Stat label="Live" value={liveFindings.length} />
      </div>
      <LiveFindingsFeed findings={liveFindings} />
    </section>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded border border-bg-tertiary bg-bg-primary p-2">
      <div className="text-xs text-text-secondary">{label}</div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  );
}
