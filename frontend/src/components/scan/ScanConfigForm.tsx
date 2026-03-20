import { ChevronDown } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";

import { HardcoreConsentGate } from "@/components/scan/HardcoreConsentGate";
import { ModeToggle } from "@/components/scan/ModeToggle";
import { useScanStore } from "@/store/scanStore";
import type { ScanConfig } from "@/types";

export function ScanConfigForm() {
  const startScan = useScanStore((s) => s.startScan);
  const navigate = useNavigate();

  const [config, setConfig] = useState<ScanConfig>({
    target_url: "",
    mode: "normal",
    max_depth: 5,
    max_pages: 100,
  });
  const [loading, setLoading] = useState(false);
  const [showAuth, setShowAuth] = useState(false);
  const [cookieHeader, setCookieHeader] = useState("");
  const [scopeLocked, setScopeLocked] = useState(false);

  const domain = useMemo(() => {
    try {
      return new URL(config.target_url).hostname;
    } catch {
      return "your-domain.com";
    }
  }, [config.target_url]);

  const canSubmit = Boolean(config.target_url) && (config.mode === "normal" || scopeLocked);

  const onSubmit = async () => {
    if (!canSubmit) {
      return;
    }
    setLoading(true);
    try {
      const payload = { ...config };
      if (cookieHeader.trim()) {
        payload.credentials = {
          login_url: config.credentials?.login_url || config.target_url,
          username: config.credentials?.username || "cookie",
          password: cookieHeader,
        };
      }
      const scan = await startScan(payload);
      toast.success("Scan queued");
      navigate(`/scans/${scan.id}`);
    } catch {
      toast.error("Failed to start scan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4 rounded-lg border border-bg-tertiary bg-bg-secondary p-4">
      <h2 className="text-lg font-semibold">Step 1 - Mode Selection</h2>
      <ModeToggle value={config.mode} onChange={(mode) => setConfig((prev) => ({ ...prev, mode }))} />

      {config.mode === "hardcore" ? <HardcoreConsentGate domain={domain} onLocked={setScopeLocked} /> : null}

      <h2 className="text-lg font-semibold">Step 2 - Target Configuration</h2>
      <div className="grid gap-3 md:grid-cols-3">
        <label className="text-sm">
          Target URL
          <input
            className="mt-1 w-full rounded border border-bg-tertiary bg-bg-primary px-3 py-2"
            placeholder="https://example.com"
            value={config.target_url}
            onChange={(e) => setConfig((prev) => ({ ...prev, target_url: e.target.value }))}
          />
        </label>
        <label className="text-sm">
          Max Depth
          <input
            type="range"
            min={1}
            max={10}
            value={config.max_depth}
            onChange={(e) => setConfig((prev) => ({ ...prev, max_depth: Number(e.target.value) }))}
            className="mt-3 w-full"
          />
          <div className="text-xs text-text-secondary">{config.max_depth}</div>
        </label>
        <label className="text-sm">
          Max Pages
          <input
            type="number"
            min={10}
            max={500}
            value={config.max_pages}
            onChange={(e) => setConfig((prev) => ({ ...prev, max_pages: Number(e.target.value) }))}
            className="mt-1 w-full rounded border border-bg-tertiary bg-bg-primary px-3 py-2"
          />
        </label>
      </div>

      <button type="button" onClick={() => setShowAuth((v) => !v)} className="inline-flex items-center gap-1 text-sm text-brand">
        <ChevronDown className={`h-4 w-4 transition-transform ${showAuth ? "rotate-180" : ""}`} />
        Add Credentials (optional)
      </button>

      {showAuth ? (
        <div className="grid gap-3 md:grid-cols-2">
          <input
            className="rounded border border-bg-tertiary bg-bg-primary px-3 py-2"
            placeholder="Login URL"
            value={config.credentials?.login_url || ""}
            onChange={(e) =>
              setConfig((prev) => ({
                ...prev,
                credentials: {
                  login_url: e.target.value,
                  username: prev.credentials?.username || "",
                  password: prev.credentials?.password || "",
                },
              }))
            }
          />
          <input
            className="rounded border border-bg-tertiary bg-bg-primary px-3 py-2"
            placeholder="Username / Email"
            value={config.credentials?.username || ""}
            onChange={(e) =>
              setConfig((prev) => ({
                ...prev,
                credentials: {
                  login_url: prev.credentials?.login_url || "",
                  username: e.target.value,
                  password: prev.credentials?.password || "",
                },
              }))
            }
          />
          <input
            type="password"
            className="rounded border border-bg-tertiary bg-bg-primary px-3 py-2"
            placeholder="Password"
            value={config.credentials?.password || ""}
            onChange={(e) =>
              setConfig((prev) => ({
                ...prev,
                credentials: {
                  login_url: prev.credentials?.login_url || "",
                  username: prev.credentials?.username || "",
                  password: e.target.value,
                },
              }))
            }
          />
          <textarea
            className="rounded border border-bg-tertiary bg-bg-primary px-3 py-2"
            placeholder="Or paste Cookie header"
            value={cookieHeader}
            onChange={(e) => setCookieHeader(e.target.value)}
          />
        </div>
      ) : null}

      <div className="rounded border border-bg-tertiary bg-bg-primary p-3 text-sm text-text-secondary">
        <div>Mode: {config.mode}</div>
        <div>Target: {config.target_url || "not set"}</div>
        <div>Depth/Pages: {config.max_depth}/{config.max_pages}</div>
      </div>

      <button
        type="button"
        onClick={onSubmit}
        disabled={!canSubmit || loading}
        className="rounded bg-brand px-4 py-2 font-medium text-bg-primary disabled:opacity-50"
      >
        {loading ? "Queuing scan..." : "Start Scan"}
      </button>
    </div>
  );
}
