export interface User {
  id: string;
  email: string;
  full_name: string;
  is_admin: boolean;
}

export interface ScanCredentials {
  login_url: string;
  username: string;
  password: string;
}

export interface ScanConfig {
  target_url: string;
  mode: "normal" | "hardcore";
  max_depth: number;
  max_pages: number;
  credentials?: ScanCredentials;
}

export interface Scan {
  id: string;
  target_url: string;
  mode: string;
  status: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  endpoints_found: number;
  vulns_found: number;
  chains_found: number;
  error_message: string | null;
}

export interface Finding {
  id: string;
  vuln_type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  endpoint_url: string;
  parameter: string | null;
  payload_used: string | null;
  poc_curl: string | null;
  poc_fetch: string | null;
  poc_notes?: string | null;
  llm_impact: string | null;
  fix_suggestion: string | null;
  owasp_category: string | null;
  mitre_id: string | null;
  confidence: number;
  is_confirmed: boolean;
}

export interface ChainData {
  path_id: string;
  nodes: string[];
  entry_point: string;
  final_impact: string;
  severity_score: number;
  length: number;
  llm_analysis?: string | null;
}

export interface GraphNode {
  id: string;
  type: "endpoint" | "vulnerability" | "asset" | "impact" | string;
  data: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  data?: Record<string, unknown>;
}

export interface HealthStatus {
  status: string;
  services?: Record<string, string>;
}
