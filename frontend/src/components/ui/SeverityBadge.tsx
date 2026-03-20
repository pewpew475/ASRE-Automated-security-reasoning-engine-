import { cn } from "@/utils";

type Severity = "critical" | "high" | "medium" | "low" | "info";

const styles: Record<Severity, string> = {
  critical: "bg-severity-critical text-severity-criticalFg animate-pulse",
  high: "bg-severity-high/30 text-severity-highFg",
  medium: "bg-severity-medium/30 text-severity-mediumFg",
  low: "bg-severity-low/30 text-severity-lowFg",
  info: "bg-severity-info/30 text-severity-infoFg",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={cn("rounded-full px-2 py-1 text-[10px] font-bold uppercase", styles[severity])}>{severity}</span>;
}
