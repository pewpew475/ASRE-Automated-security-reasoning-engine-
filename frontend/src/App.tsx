import { lazy, Suspense } from "react";
import { BrowserRouter, Navigate, Outlet, Route, Routes } from "react-router-dom";
import { Toaster } from "react-hot-toast";

import { useAuthStore } from "@/store/authStore";
import { Layout } from "@/components/layout/Layout";
import { DashboardPage } from "@/pages/DashboardPage";
import { LoginPage } from "@/pages/LoginPage";
import { NewScanPage } from "@/pages/NewScanPage";
import { NotFoundPage } from "@/pages/NotFoundPage";
import { RegisterPage } from "@/pages/RegisterPage";
import { ScanDetailPage } from "@/pages/ScanDetailPage";
import { SettingsPage } from "@/pages/SettingsPage";

const GraphPage = lazy(() => import("@/pages/GraphPage").then((m) => ({ default: m.GraphPage })));
const ReportPage = lazy(() => import("@/pages/ReportPage").then((m) => ({ default: m.ReportPage })));

function isExpired(token: string): boolean {
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))) as { exp?: number };
    if (!payload.exp) {
      return false;
    }
    return payload.exp < Date.now() / 1000;
  } catch {
    return false;
  }
}

function ProtectedRoute() {
  const token = useAuthStore((s) => s.token);
  const logout = useAuthStore((s) => s.logout);

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  if (isExpired(token)) {
    logout();
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Toaster position="bottom-right" />
      <Suspense fallback={<div className="p-6 text-text-secondary">Loading...</div>}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          <Route element={<ProtectedRoute />}>
            <Route element={<Layout />}>
              <Route path="/" element={<Navigate to="/dashboard" />} />
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/scan/new" element={<NewScanPage />} />
              <Route path="/scans" element={<DashboardPage />} />
              <Route path="/scans/:scanId" element={<ScanDetailPage />} />
              <Route path="/scans/:scanId/graph" element={<GraphPage />} />
              <Route path="/scans/:scanId/report" element={<ReportPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Route>
          </Route>

          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
