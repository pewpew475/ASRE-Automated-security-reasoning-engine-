import { useEffect, useMemo, useState } from "react";

import { phaseOrder } from "@/utils";
import { useScanStore } from "@/store/scanStore";

const phaseLabels: Record<string, string> = {
  crawling: "Phase 1: Crawling endpoints",
  scanning: "Phase 2: Running vulnerability probes",
  chaining: "Phase 3: Building attack chains",
  analyzing: "Phase 4: LLM impact analysis",
  generating_poc: "Phase 5: Generating PoC evidence",
  reporting: "Phase 6: Generating PDF report",
  completed: "Scan complete",
  failed: "Scan failed",
  cancelled: "Scan cancelled",
};

export function useScanProgress() {
  const progress = useScanStore((s) => s.progress);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const currentPhaseIndex = useMemo(() => {
    const i = phaseOrder.indexOf(progress.phase as (typeof phaseOrder)[number]);
    return i >= 0 ? i : 0;
  }, [progress.phase]);

  const percentComplete = useMemo(() => {
    const done = Math.max(0, currentPhaseIndex);
    return Math.min(100, Math.round((done / phaseOrder.length) * 100));
  }, [currentPhaseIndex]);

  const elapsedSeconds = Math.max(0, Math.floor((now - progress.phase_started_at) / 1000));
  const isRunning = !["completed", "failed", "cancelled"].includes(progress.phase);

  return {
    currentPhaseIndex,
    currentPhaseLabel: phaseLabels[progress.phase] || progress.phase,
    percentComplete,
    isRunning,
    elapsedSeconds,
  };
}
