import { History, LayoutDashboard, LogOut, Plus, Settings, Shield } from "lucide-react";
import { NavLink } from "react-router-dom";

import { cn } from "@/utils";
import { useAuthStore } from "@/store/authStore";
import { useUIStore } from "@/store/uiStore";

const nav = [
  { to: "/dashboard", label: "Home", icon: LayoutDashboard },
  { to: "/scan/new", label: "New Scan", icon: Plus },
  { to: "/scans", label: "Scan History", icon: History },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const sidebarOpen = useUIStore((s) => s.sidebarOpen);
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);
  const llmStatus = useUIStore((s) => s.llmStatus);
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);

  return (
    <aside className={cn("flex h-full flex-col border-r border-bg-tertiary bg-bg-secondary", sidebarOpen ? "w-60" : "w-16")}>
      <button
        className="flex items-center gap-2 border-b border-bg-tertiary p-4 text-left"
        onClick={toggleSidebar}
        type="button"
      >
        <Shield className="h-5 w-5 text-brand" />
        {sidebarOpen ? <span className="font-semibold">ASRE</span> : null}
      </button>

      <nav className="flex-1 p-2">
        {nav.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                cn(
                  "mb-1 flex items-center gap-2 rounded-md border-l-2 p-2 text-sm text-text-secondary hover:bg-bg-tertiary",
                  isActive ? "border-brand bg-brand/10 text-text-primary" : "border-transparent"
                )
              }
            >
              <Icon className="h-4 w-4" />
              {sidebarOpen ? item.label : null}
            </NavLink>
          );
        })}
      </nav>

      <div className="border-t border-bg-tertiary p-3 text-xs text-text-secondary">
        <div className="mb-3 flex items-center gap-2">
          <span className={cn("h-2 w-2 rounded-full", llmStatus ? (llmStatus.configured ? "bg-green-500" : "bg-red-500") : "bg-yellow-500")} />
          {sidebarOpen ? <span>{llmStatus ? `${llmStatus.provider} / ${llmStatus.model}` : "Checking LLM..."}</span> : null}
        </div>
        {sidebarOpen ? <div className="truncate">{user?.email || "anonymous"}</div> : null}
        <button type="button" className="mt-2 flex items-center gap-2 text-text-secondary hover:text-text-primary" onClick={logout}>
          <LogOut className="h-4 w-4" />
          {sidebarOpen ? "Logout" : null}
        </button>
      </div>
    </aside>
  );
}
