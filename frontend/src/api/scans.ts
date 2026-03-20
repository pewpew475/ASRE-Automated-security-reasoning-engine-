import apiClient from "@/api/client";
import type { ChainData, Finding, GraphEdge, GraphNode, Scan, ScanConfig } from "@/types";

export type ScanGraphResponse = {
  nodes: GraphNode[];
  edges: GraphEdge[];
};

type ScanListResponse = {
  scans: Array<Scan & { scan_id?: string }>;
};

type ScanStatusResponse = Scan & { scan_id?: string };

type ScanStartResponse = {
  scan_id: string;
  status: string;
  message: string;
};

type FindingsResponse = {
  findings: Finding[];
};

type ChainsResponse = {
  chains: ChainData[];
};

function normalizeScan<T extends { id?: string; scan_id?: string }>(scan: T): T & { id: string } {
  return {
    ...scan,
    id: scan.id ?? scan.scan_id ?? "",
  };
}

export const scansApi = {
  start: async (config: ScanConfig) => {
    const response = await apiClient.post<ScanStartResponse>("/scan/start", config);
    return response;
  },
  list: async () => {
    const response = await apiClient.get<ScanListResponse>("/scan/history");
    return {
      ...response,
      data: response.data.scans.map(normalizeScan),
    };
  },
  get: async (id: string) => {
    const response = await apiClient.get<ScanStatusResponse>(`/scan/${id}/status`);
    return {
      ...response,
      data: normalizeScan(response.data),
    };
  },
  cancel: (id: string) => apiClient.post(`/scan/${id}/cancel`),
  delete: (id: string) => apiClient.delete(`/scan/${id}`),
  findings: async (id: string) => {
    const response = await apiClient.get<FindingsResponse>(`/scan/${id}/findings`);
    return {
      ...response,
      data: response.data.findings,
    };
  },
  graph: (id: string) => apiClient.get<ScanGraphResponse>(`/scans/${id}/graph`),
  chains: async (id: string) => {
    const response = await apiClient.get<ChainsResponse>(`/scans/${id}/graph/chains`);
    return {
      ...response,
      data: response.data.chains,
    };
  },
};
