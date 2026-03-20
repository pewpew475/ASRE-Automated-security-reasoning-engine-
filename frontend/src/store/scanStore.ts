import { create } from "zustand";

import { scansApi } from "@/api/scans";
import type { Finding, Scan, ScanConfig } from "@/types";

interface ProgressState {
  phase: string;
  phase_detail: string;
  current_url: string;
  endpoints_found: number;
  vulns_found: number;
  chains_found: number;
  phase_started_at: number;
}

interface ScanState {
  scans: Scan[];
  activeScan: Scan | null;
  findings: Finding[];
  liveFindings: Finding[];
  progress: ProgressState;
  wsConnected: boolean;
  wsError: string | null;
  fetchScans: () => Promise<void>;
  fetchScan: (id: string) => Promise<void>;
  fetchFindings: (id: string) => Promise<void>;
  startScan: (config: ScanConfig) => Promise<Scan>;
  cancelScan: (id: string) => Promise<void>;
  deleteScan: (id: string) => Promise<void>;
  addLiveFinding: (finding: Finding) => void;
  updateProgress: (data: Partial<ProgressState>) => void;
  setWsConnected: (v: boolean) => void;
  resetLive: () => void;
}

const initialProgress: ProgressState = {
  phase: "pending",
  phase_detail: "Waiting to start",
  current_url: "",
  endpoints_found: 0,
  vulns_found: 0,
  chains_found: 0,
  phase_started_at: Date.now(),
};

export const useScanStore = create<ScanState>((set, get) => ({
  scans: [],
  activeScan: null,
  findings: [],
  liveFindings: [],
  progress: initialProgress,
  wsConnected: false,
  wsError: null,
  fetchScans: async () => {
    const { data } = await scansApi.list();
    set(() => ({ scans: data }));
  },
  fetchScan: async (id) => {
    const { data } = await scansApi.get(id);
    set(() => ({ activeScan: data }));
  },
  fetchFindings: async (id) => {
    const { data } = await scansApi.findings(id);
    set(() => ({ findings: data }));
  },
  startScan: async (config) => {
    const { data } = await scansApi.start(config);
    const status = await scansApi.get(data.scan_id);
    set(() => ({
      activeScan: status.data,
      scans: [status.data, ...get().scans.filter((s) => s.id !== status.data.id)],
      liveFindings: [],
      progress: {
        phase: "crawling",
        phase_detail: "Crawler is mapping reachable pages and endpoints",
        current_url: "",
        endpoints_found: 0,
        vulns_found: 0,
        chains_found: 0,
        phase_started_at: Date.now(),
      },
    }));
    return status.data;
  },
  cancelScan: async (id) => {
    await scansApi.cancel(id);
    await get().fetchScan(id);
  },
  deleteScan: async (id) => {
    await scansApi.delete(id);
    set(() => ({ scans: get().scans.filter((s) => s.id !== id) }));
  },
  addLiveFinding: (finding) => {
    set(() => ({ liveFindings: [finding, ...get().liveFindings] }));
  },
  updateProgress: (data) => {
    const current = get().progress;
    const nextPhase = data.phase ?? current.phase;
    set(() => ({
      progress: {
        phase: nextPhase,
        phase_detail: data.phase_detail ?? current.phase_detail,
        current_url: data.current_url ?? current.current_url,
        endpoints_found: data.endpoints_found ?? current.endpoints_found,
        vulns_found: data.vulns_found ?? current.vulns_found,
        chains_found: data.chains_found ?? current.chains_found,
        phase_started_at: nextPhase !== current.phase ? Date.now() : current.phase_started_at,
      },
    }));
  },
  setWsConnected: (v) => {
    set(() => ({ wsConnected: v, wsError: v ? null : get().wsError }));
  },
  resetLive: () => {
    set(() => ({ liveFindings: [] }));
  },
}));
