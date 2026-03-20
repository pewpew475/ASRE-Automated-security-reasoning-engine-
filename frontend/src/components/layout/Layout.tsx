import { Outlet } from "react-router-dom";

import { Sidebar } from "@/components/layout/Sidebar";
import { TopBar } from "@/components/layout/TopBar";

export function Layout() {
  return (
    <div className="asre-grid-bg flex h-screen overflow-hidden bg-bg-primary">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <TopBar />
        <main className="relative flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
