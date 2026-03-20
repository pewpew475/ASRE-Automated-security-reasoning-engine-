import { cn } from "@/utils";

interface ProgressBarProps {
  value: number;
  color?: string;
  label?: string;
}

export function ProgressBar({ value, color = "bg-brand", label }: ProgressBarProps) {
  const pct = Math.max(0, Math.min(100, value));
  return (
    <div className="w-full">
      {label ? <div className="mb-1 text-xs text-text-secondary">{label}</div> : null}
      <div className="h-3 overflow-hidden rounded-full bg-bg-tertiary">
        <div
          className={cn("h-full transition-all duration-500", color, pct < 100 ? "bg-[length:20px_20px] bg-[linear-gradient(-45deg,rgba(255,255,255,0.15)_25%,transparent_25%,transparent_50%,rgba(255,255,255,0.15)_50%,rgba(255,255,255,0.15)_75%,transparent_75%,transparent)]" : "")}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
