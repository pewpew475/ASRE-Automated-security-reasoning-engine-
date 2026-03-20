import { useEffect, useMemo, useState } from "react";
import toast from "react-hot-toast";

import { llmApi } from "@/api/llm";
import apiClient from "@/api/client";

type HealthPayload = {
  status: string;
  services?: Record<string, string | { status?: string }>;
};

type PublicSettingsPayload = {
  default_max_depth?: number;
  default_max_pages?: number;
  default_rate_limit?: number;
};

export function SettingsPage() {
  const [provider, setProvider] = useState("openai");
  const [model, setModel] = useState("gpt-4o");
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  const [scannerDefaults, setScannerDefaults] = useState<PublicSettingsPayload>({});
  const [health, setHealth] = useState<HealthPayload | null>(null);

  useEffect(() => {
    const run = async () => {
      try {
        const [providersRes, settingsRes, healthRes] = await Promise.all([
          llmApi.providers(),
          apiClient.get<PublicSettingsPayload>("/settings/public"),
          apiClient.get<HealthPayload>("/health"),
        ]);
        const current = providersRes.data.current;
        if (current) {
          setProvider(current.provider || "openai");
          setModel(current.model || "gpt-4o");
          if (current.base_url && current.base_url !== "default") {
            setBaseUrl(current.base_url);
          }
        }
        setScannerDefaults(settingsRes.data || {});
        setHealth(healthRes.data || null);
      } catch {
        toast.error("Failed to load settings");
      }
    };

    void run();
  }, []);

  const showBaseUrl = useMemo(() => ["ollama", "custom", "openrouter"].includes(provider), [provider]);

  const onTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const { data } = await llmApi.test({
        provider,
        model,
        api_key: apiKey || undefined,
        base_url: baseUrl || undefined,
      });
      if (data.status === "ok") {
        setTestResult(`✓ Connected: ${String(data.response || "OK")}`);
      } else {
        setTestResult(`✗ Error: ${String(data.error || "Unknown error")}`);
      }
    } catch {
      setTestResult("✗ Error: Request failed");
    } finally {
      setTesting(false);
    }
  };

  const serviceStatus = (name: string): "ok" | "fail" => {
    const value = health?.services?.[name];
    if (!value) return "fail";
    if (typeof value === "string") return value === "ok" ? "ok" : "fail";
    return value.status === "ok" ? "ok" : "fail";
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-bg-tertiary bg-bg-secondary p-4">
        <h2 className="text-lg font-semibold">LLM Configuration</h2>
        <p className="mb-4 text-sm text-text-secondary">Values are environment-driven. Test Connection validates current settings.</p>

        <div className="grid gap-3 md:grid-cols-2">
          <label className="text-sm text-text-secondary">
            Provider
            <select value={provider} onChange={(e) => setProvider(e.target.value)} className="mt-1 w-full rounded border border-bg-tertiary bg-bg-primary px-3 py-2">
              {[
                "openai",
                "anthropic",
                "deepseek",
                "groq",
                "ollama",
                "mistral",
                "together",
                "openrouter",
                "cohere",
                "custom",
              ].map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </label>
          <label className="text-sm text-text-secondary">
            Model
            <input value={model} onChange={(e) => setModel(e.target.value)} className="mt-1 w-full rounded border border-bg-tertiary bg-bg-primary px-3 py-2" />
          </label>
          <label className="text-sm text-text-secondary md:col-span-2">
            API Key
            <input type="password" placeholder="sk-..." value={apiKey} onChange={(e) => setApiKey(e.target.value)} className="mt-1 w-full rounded border border-bg-tertiary bg-bg-primary px-3 py-2" />
          </label>
          {showBaseUrl ? (
            <label className="text-sm text-text-secondary md:col-span-2">
              Base URL
              <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} className="mt-1 w-full rounded border border-bg-tertiary bg-bg-primary px-3 py-2" />
            </label>
          ) : null}
        </div>

        <div className="mt-4 flex items-center gap-3">
          <button type="button" onClick={onTest} disabled={testing} className="rounded bg-brand px-3 py-2 text-sm font-medium text-bg-primary disabled:opacity-60">
            {testing ? "Testing..." : "Test Connection"}
          </button>
          {testResult ? <span className="text-sm text-text-secondary">{testResult}</span> : null}
        </div>
        <p className="mt-3 text-xs text-text-secondary">Changes require updating .env and restarting backend containers.</p>
      </section>

      <section className="rounded-xl border border-bg-tertiary bg-bg-secondary p-4">
        <h2 className="text-lg font-semibold">Scanner Defaults</h2>
        <div className="mt-2 grid gap-2 text-sm text-text-secondary md:grid-cols-3">
          <div>Default max depth: {scannerDefaults.default_max_depth ?? "-"}</div>
          <div>Default max pages: {scannerDefaults.default_max_pages ?? "-"}</div>
          <div>Default rate limit: {scannerDefaults.default_rate_limit ?? "-"}</div>
        </div>
      </section>

      <section className="rounded-xl border border-bg-tertiary bg-bg-secondary p-4">
        <h2 className="text-lg font-semibold">About</h2>
        <div className="mt-2 space-y-2 text-sm text-text-secondary">
          <div>Backend health: {health?.status || "unknown"}</div>
          <div className="flex gap-4">
            <ServiceDot label="PostgreSQL" ok={serviceStatus("postgresql") === "ok"} />
            <ServiceDot label="Neo4j" ok={serviceStatus("neo4j") === "ok"} />
            <ServiceDot label="Redis" ok={serviceStatus("redis") === "ok"} />
          </div>
        </div>
      </section>
    </div>
  );
}

function ServiceDot({ label, ok }: { label: string; ok: boolean }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`h-2.5 w-2.5 rounded-full ${ok ? "bg-emerald-400" : "bg-red-400"}`} />
      {label}
    </span>
  );
}
