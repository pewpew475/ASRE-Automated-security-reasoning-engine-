import { useEffect, useRef, useState } from "react";
import toast from "react-hot-toast";

import { useScanStore } from "@/store/scanStore";

interface WsEnvelope {
  event?: string;
  type?: string;
  payload?: unknown;
  data?: unknown;
}

const terminalStatuses = new Set(["completed", "failed", "cancelled"]);

function toSeverity(value: unknown): "critical" | "high" | "medium" | "low" | "info" {
  const normalized = String(value || "info").toLowerCase();
  if (normalized === "critical") return "critical";
  if (normalized === "high") return "high";
  if (normalized === "medium") return "medium";
  if (normalized === "low") return "low";
  return "info";
}

export function useScanWebSocket(scanId: string | null) {
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reconnectCount, setReconnectCount] = useState(0);
  const wsRef = useRef<WebSocket | null>(null);
  const attemptsRef = useRef(0);

  const updateProgress = useScanStore((s) => s.updateProgress);
  const addLiveFinding = useScanStore((s) => s.addLiveFinding);
  const fetchScan = useScanStore((s) => s.fetchScan);
  const setWsConnected = useScanStore((s) => s.setWsConnected);

  useEffect(() => {
    if (!scanId) {
      return;
    }

    let cancelled = false;
    const wsBase = import.meta.env.VITE_WS_URL || "ws://localhost:8000";

    const connect = () => {
      if (cancelled) {
        return;
      }
      const ws = new WebSocket(`${wsBase}/ws/scan/${scanId}`);
      wsRef.current = ws;

      ws.onopen = () => {
        attemptsRef.current = 0;
        setConnected(true);
        setError(null);
        setWsConnected(true);
      };

      ws.onmessage = (event) => {
        let msg: WsEnvelope;
        try {
          msg = JSON.parse(event.data as string) as WsEnvelope;
        } catch {
          return;
        }

        const eventType = String(msg.event || msg.type || "");
        const payload = (msg.payload ?? msg.data ?? {}) as Record<string, unknown>;

        if (eventType === "scan.phase_change") {
          updateProgress({ phase: String(payload.status || payload.phase || "pending") });
        } else if (eventType === "scan.progress") {
          updateProgress({
            endpoints_found: Number(payload.endpoints_found || 0),
            vulns_found: Number(payload.vulns_found || 0),
            chains_found: Number(payload.chains_found || 0),
          });
        } else if (eventType === "scan.finding") {
          const severity = toSeverity(payload.severity);
          const finding = {
            id: crypto.randomUUID(),
            vuln_type: String(payload.vuln_type || "unknown"),
            severity,
            title: String(payload.title || "Live finding"),
            description: "",
            endpoint_url: String(payload.url || ""),
            parameter: null,
            payload_used: null,
            poc_curl: null,
            poc_fetch: null,
            llm_impact: null,
            fix_suggestion: null,
            owasp_category: null,
            mitre_id: null,
            confidence: 0,
            is_confirmed: false,
          };
          addLiveFinding(finding);
          if (finding.severity === "critical" || finding.severity === "high") {
            toast(`${finding.severity.toUpperCase()}: ${finding.title}`);
          }
        } else if (eventType === "scan.completed") {
          toast.success("Scan complete!");
          void fetchScan(scanId);
          ws.close(1000, "completed");
        } else if (eventType === "scan.failed") {
          toast.error(`Scan failed: ${String(payload.reason || "unknown")}`);
          ws.close(1000, "failed");
        } else if (eventType === "chain.built") {
          updateProgress({ chains_found: Number(payload.chains_found || 0) });
        } else if (eventType === "hardcore.complete") {
          toast(`Hardcore scan complete: ${String(payload.total_hardcore_findings || 0)} findings`);
        }
      };

      ws.onclose = (e) => {
        setConnected(false);
        setWsConnected(false);
        if (cancelled || e.code === 1000) {
          return;
        }
        if (attemptsRef.current >= 5) {
          setError("WebSocket reconnect limit reached");
          return;
        }
        attemptsRef.current += 1;
        setReconnectCount(attemptsRef.current);
        const timeout = Math.min(10000, 2000 * 2 ** (attemptsRef.current - 1));
        window.setTimeout(() => {
          if (!terminalStatuses.has(useScanStore.getState().activeScan?.status || "")) {
            connect();
          }
        }, timeout);
      };

      ws.onerror = () => {
        setError("WebSocket error");
      };
    };

    connect();

    return () => {
      cancelled = true;
      wsRef.current?.close(1000, "cleanup");
    };
  }, [scanId, addLiveFinding, fetchScan, setWsConnected, updateProgress]);

  return { connected, error, reconnectCount };
}
