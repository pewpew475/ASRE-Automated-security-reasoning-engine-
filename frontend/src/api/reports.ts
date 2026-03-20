import apiClient from "@/api/client";

export const reportsApi = {
  get: (scanId: string) => apiClient.get(`/reports/${scanId}`),
  download: (scanId: string) =>
    apiClient.get(`/reports/${scanId}/download`, {
      responseType: "blob",
    }),
};
