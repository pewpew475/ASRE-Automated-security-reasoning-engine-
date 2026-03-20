import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description: string;
  action?: ReactNode;
}

export function EmptyState({ icon: Icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-bg-tertiary bg-bg-secondary p-10 text-center">
      <Icon className="mb-3 h-10 w-10 text-text-secondary" />
      <h3 className="text-lg font-semibold text-text-primary">{title}</h3>
      <p className="mt-2 max-w-lg text-sm text-text-secondary">{description}</p>
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}
