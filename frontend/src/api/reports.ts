import apiClient from "@/api/client";

export type ReportAssistantMessage = {
  role: "user" | "assistant";
  content: string;
};

export type ReportAssistantResponse = {
  answer: string;
  scan_id: string;
};

export const reportsApi = {
  get: (scanId: string) => apiClient.get(`/reports/${scanId}`),
  download: (scanId: string) =>
    apiClient.get(`/reports/${scanId}/download`, {
      responseType: "blob",
    }),
  askAssistant: (scanId: string, payload: { question: string; history: ReportAssistantMessage[] }) =>
    apiClient.post<ReportAssistantResponse>(`/reports/${scanId}/assistant`, payload),
};
