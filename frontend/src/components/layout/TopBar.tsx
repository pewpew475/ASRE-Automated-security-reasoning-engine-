import { Bell } from "lucide-react";
import { useLocation } from "react-router-dom";

import { useScanStore } from "@/store/scanStore";

const routeTitle: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/scan/new": "New Scan",
  "/settings": "Settings",
};

export function TopBar() {
  const location = useLocation();
  const active = useScanStore((s) => s.activeScan);

  const title = routeTitle[location.pathname] || "ASRE";
  const running = active && !["completed", "failed", "cancelled"].includes(active.status);

  return (
    <header className="flex h-14 items-center justify-between border-b border-bg-tertiary bg-bg-secondary/85 px-4 backdrop-blur">
      <h1 className="text-sm font-semibold uppercase tracking-wide text-text-primary">{title}</h1>
      <div className="flex items-center gap-4 text-xs text-text-secondary">
        {running ? (
          <div className="flex items-center gap-2 rounded-full border border-brand/40 bg-brand/10 px-3 py-1">
            <span className="h-2 w-2 animate-pulse rounded-full bg-brand" />
            <span>Scanning {active.target_url}...</span>
          </div>
        ) : null}
        <button className="rounded-md p-1 hover:bg-bg-tertiary" aria-label="notifications">
          <Bell className="h-4 w-4" />
        </button>
      </div>
    </header>
  );
}
