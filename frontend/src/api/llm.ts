import apiClient from "@/api/client";

export const llmApi = {
  status: () => apiClient.get("/llm/status"),
  providers: () => apiClient.get("/llm/providers"),
  test: (payload: { provider?: string; model?: string; api_key?: string; base_url?: string }) =>
    apiClient.post("/llm/test", payload),
};
