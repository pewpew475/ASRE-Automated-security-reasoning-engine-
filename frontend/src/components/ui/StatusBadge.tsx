import {
  Brain,
  CheckCircle,
  Clock,
  Code,
  FileText,
  GitBranch,
  Globe,
  Search,
  StopCircle,
  XCircle,
} from "lucide-react";

import { cn } from "@/utils";

const map = {
  pending: { cls: "bg-bg-tertiary text-text-secondary", icon: Clock },
  crawling: { cls: "bg-blue-900/40 text-blue-200", icon: Globe },
  scanning: { cls: "bg-orange-900/40 text-orange-200", icon: Search },
  chaining: { cls: "bg-purple-900/40 text-purple-200", icon: GitBranch },
  analyzing: { cls: "bg-indigo-900/40 text-indigo-200", icon: Brain },
  generating_poc: { cls: "bg-cyan-900/40 text-cyan-200", icon: Code },
  reporting: { cls: "bg-green-900/40 text-green-200", icon: FileText },
  completed: { cls: "bg-green-900/40 text-green-200", icon: CheckCircle },
  failed: { cls: "bg-red-900/40 text-red-200", icon: XCircle },
  cancelled: { cls: "bg-bg-tertiary text-text-secondary", icon: StopCircle },
} as const;

export function StatusBadge({ status }: { status: string }) {
  const cfg = map[status as keyof typeof map] ?? map.pending;
  const Icon = cfg.icon;
  const active = ["crawling", "scanning", "chaining", "analyzing", "generating_poc", "reporting"].includes(status);

  return (
    <span className={cn("inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs", cfg.cls)}>
      <Icon className={cn("h-3.5 w-3.5", active ? "animate-pulse" : "")} />
      {status}
    </span>
  );
}
