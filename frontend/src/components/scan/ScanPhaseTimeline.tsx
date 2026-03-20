import { CheckCircle, LoaderCircle } from "lucide-react";

const phases = ["crawling", "scanning", "chaining", "analyzing", "generating_poc", "reporting"];

interface ScanPhaseTimelineProps {
  currentPhase: string;
  completedPhases: string[];
}

export function ScanPhaseTimeline({ currentPhase, completedPhases }: ScanPhaseTimelineProps) {
  return (
    <div className="grid gap-2 md:grid-cols-6">
      {phases.map((phase) => {
        const done = completedPhases.includes(phase);
        const active = currentPhase === phase;
        return (
          <div key={phase} className="rounded border border-bg-tertiary bg-bg-secondary p-2 text-xs">
            <div className="mb-1 flex items-center gap-1">
              {done ? <CheckCircle className="h-3.5 w-3.5 text-green-400" /> : null}
              {active ? <LoaderCircle className="h-3.5 w-3.5 animate-spin text-brand" /> : null}
              {!done && !active ? <span className="h-2 w-2 rounded-full bg-bg-tertiary" /> : null}
              <span className={active ? "font-semibold" : "text-text-secondary"}>{phase}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
