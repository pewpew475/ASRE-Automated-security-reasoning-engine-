import apiClient from "@/api/client";
import type { ChainData, Finding, GraphEdge, GraphNode, Scan, ScanConfig } from "@/types";

export type ScanGraphResponse = {
  nodes: GraphNode[];
  edges: GraphEdge[];
};

export const scansApi = {
  start: (config: ScanConfig) => apiClient.post<Scan>("/scans/start", config),
  list: () => apiClient.get<Scan[]>("/scans"),
  get: (id: string) => apiClient.get<Scan>(`/scans/${id}`),
  cancel: (id: string) => apiClient.post(`/scans/${id}/cancel`),
  delete: (id: string) => apiClient.delete(`/scans/${id}`),
  findings: (id: string) => apiClient.get<Finding[]>(`/scans/${id}/findings`),
  graph: (id: string) => apiClient.get<ScanGraphResponse>(`/scans/${id}/graph`),
  chains: (id: string) => apiClient.get<ChainData[]>(`/scans/${id}/graph/chains`),
};
