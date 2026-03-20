import { CheckCircle, LoaderCircle } from "lucide-react";

import { ProgressBar } from "@/components/ui/ProgressBar";

const phases = ["crawling", "scanning", "chaining", "analyzing", "generating_poc", "reporting"];
const phaseLabels: Record<string, string> = {
  crawling: "Crawling",
  scanning: "Scanning",
  chaining: "Chaining",
  analyzing: "Analyzing",
  generating_poc: "Generating",
  reporting: "Reporting",
};

interface ScanPhaseTimelineProps {
  currentPhase: string;
  completedPhases: string[];
}

export function ScanPhaseTimeline({ currentPhase, completedPhases }: ScanPhaseTimelineProps) {
  const currentIndex = phases.indexOf(currentPhase);

  return (
    <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
      {phases.map((phase, index) => {
        const done = completedPhases.includes(phase);
        const active = currentPhase === phase;
        const value = done ? 100 : active ? 60 : index < currentIndex ? 100 : 0;
        return (
          <div key={phase} className="rounded border border-bg-tertiary bg-bg-secondary p-2 text-xs">
            <div className="mb-1 flex items-center gap-1">
              {done ? <CheckCircle className="h-3.5 w-3.5 text-green-400" /> : null}
              {active ? <LoaderCircle className="h-3.5 w-3.5 animate-spin text-brand" /> : null}
              {!done && !active ? <span className="h-2 w-2 rounded-full bg-bg-tertiary" /> : null}
              <span className={active ? "font-semibold" : "text-text-secondary"}>{phaseLabels[phase] || phase}</span>
            </div>
            <ProgressBar value={value} color={done ? "bg-green-500" : "bg-brand"} />
          </div>
        );
      })}
    </div>
  );
}
