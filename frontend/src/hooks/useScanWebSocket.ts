import { useEffect, useRef, useState } from "react";
import toast from "react-hot-toast";

import apiClient, { getValidAccessToken } from "@/api/client";
import { useScanStore } from "@/store/scanStore";

interface WsEnvelope {
  event?: string;
  type?: string;
  payload?: unknown;
  data?: unknown;
}

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
  const pingIntervalRef = useRef<number | null>(null);
  const heartbeatTimeoutRef = useRef<number | null>(null);
  const apiKeepAliveRef = useRef<number | null>(null);

  const updateProgress = useScanStore((s) => s.updateProgress);
  const addLiveFinding = useScanStore((s) => s.addLiveFinding);
  const fetchScan = useScanStore((s) => s.fetchScan);
  const setWsConnected = useScanStore((s) => s.setWsConnected);

  useEffect(() => {
    if (!scanId) {
      return;
    }

    let cancelled = false;
    const apiBase = import.meta.env.VITE_API_URL || "http://localhost:8010/api";
    const wsBase =
      import.meta.env.VITE_WS_URL ||
      apiBase.replace(/^http:/, "ws:").replace(/^https:/, "wss:").replace(/\/api\/?$/, "");

    const clearHeartbeatTimers = () => {
      if (pingIntervalRef.current !== null) {
        window.clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = null;
      }
      if (heartbeatTimeoutRef.current !== null) {
        window.clearTimeout(heartbeatTimeoutRef.current);
        heartbeatTimeoutRef.current = null;
      }
      if (apiKeepAliveRef.current !== null) {
        window.clearInterval(apiKeepAliveRef.current);
        apiKeepAliveRef.current = null;
      }
    };

    const resetHeartbeatTimeout = () => {
      if (heartbeatTimeoutRef.current !== null) {
        window.clearTimeout(heartbeatTimeoutRef.current);
      }
      heartbeatTimeoutRef.current = window.setTimeout(() => {
        const ws = wsRef.current;
        if (ws && ws.readyState === WebSocket.OPEN && !cancelled) {
          setError("WebSocket heartbeat timed out. Reconnecting...");
          ws.close(4000, "heartbeat-timeout");
        }
      }, 65000);
    };

    const connect = () => {
      if (cancelled) {
        return;
      }
      const ws = new WebSocket(`${wsBase}/ws/scan/${scanId}`);
      wsRef.current = ws;

      ws.onopen = () => {
        void (async () => {
          const token = await getValidAccessToken();
          if (!token) {
            setError("Authentication expired. Please log in again.");
            ws.close(4001, "missing-token");
            return;
          }

          ws.send(JSON.stringify({ token }));
          attemptsRef.current = 0;
          setConnected(true);
          setError(null);
          setWsConnected(true);

          clearHeartbeatTimers();
          resetHeartbeatTimeout();
          pingIntervalRef.current = window.setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ event: "client.ping", ts: Date.now() }));
            }
          }, 20000);

          // Keep backend API session hot during long-running scans.
          apiKeepAliveRef.current = window.setInterval(() => {
            void apiClient
              .get(`/scan/${scanId}/status`, {
                params: { heartbeat: Date.now() },
              })
              .catch(() => {
                // Best-effort keepalive; websocket reconnection handles outages.
              });
          }, 25000);
        })();
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

        if (eventType === "ping") {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ event: "pong", ts: Date.now() }));
          }
          resetHeartbeatTimeout();
          return;
        }

        if (eventType === "pong") {
          resetHeartbeatTimeout();
          return;
        }

        resetHeartbeatTimeout();

        if (eventType === "scan.phase_change") {
          const phase = String(payload.status || payload.phase || "pending");
          const detailByPhase: Record<string, string> = {
            crawling: "Crawler is mapping reachable pages and endpoints",
            scanning: "Security probes are testing discovered endpoints",
            chaining: "Attack chains are being correlated",
            analyzing: "LLM is analyzing risk and exploitability",
            generating_poc: "Generating proof-of-concept payloads",
            reporting: "Compiling final report",
            completed: "Scan completed successfully",
            failed: "Scan failed",
            cancelled: "Scan was cancelled",
          };
          updateProgress({
            phase,
            phase_detail: detailByPhase[phase] || "Processing scan",
          });
        } else if (eventType === "scan.progress") {
          updateProgress({
            phase: String(payload.status || useScanStore.getState().progress.phase || "pending"),
            endpoints_found: Number(payload.endpoints_found || 0),
            vulns_found: Number(payload.vulns_found || 0),
            chains_found: Number(payload.chains_found || 0),
          });
        } else if (eventType === "crawl.endpoint") {
          updateProgress({
            current_url: String(payload.url || ""),
            phase_detail: `Crawling ${String(payload.url || "target")}`,
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
        } else if (eventType === "scan.failed") {
          toast.error(`Scan failed: ${String(payload.reason || "unknown")}`);
        } else if (eventType === "chain.built") {
          updateProgress({ chains_found: Number(payload.chains_found || 0) });
        } else if (eventType === "hardcore.complete") {
          toast(`Hardcore scan complete: ${String(payload.total_hardcore_findings || 0)} findings`);
        }
      };

      ws.onclose = (e) => {
        clearHeartbeatTimers();
        setConnected(false);
        setWsConnected(false);
        if (cancelled) {
          return;
        }
        attemptsRef.current += 1;
        setReconnectCount(attemptsRef.current);
        const timeout = Math.min(30000, 1000 * 2 ** Math.min(attemptsRef.current - 1, 5));
        setError(`WebSocket disconnected (code ${e.code}). Reconnecting...`);
        window.setTimeout(() => {
          if (!cancelled) {
            connect();
          }
        }, timeout);
      };

      ws.onerror = () => {
        clearHeartbeatTimers();
        setError("WebSocket error");
      };
    };

    connect();

    return () => {
      cancelled = true;
      const ws = wsRef.current;
      wsRef.current = null;
      if (!ws) {
        return;
      }

      ws.onopen = null;
      ws.onmessage = null;
      ws.onclose = null;
      ws.onerror = null;
      clearHeartbeatTimers();

      // Avoid explicit close while CONNECTING in dev StrictMode/HMR to prevent
      // "closed before connection is established" console warnings.
      if (ws.readyState === WebSocket.OPEN) {
        ws.close(1000, "cleanup");
      }
    };
  }, [scanId, addLiveFinding, fetchScan, setWsConnected, updateProgress]);

  return { connected, error, reconnectCount };
}
