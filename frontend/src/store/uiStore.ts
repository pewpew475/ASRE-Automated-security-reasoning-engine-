import { create } from "zustand";

import { llmApi } from "@/api/llm";

interface UIState {
  sidebarOpen: boolean;
  activeTheme: "dark";
  graphLayout: "dagre" | "force";
  llmStatus: {
    configured: boolean;
    provider: string;
    model: string;
  } | null;
  toggleSidebar: () => void;
  setGraphLayout: (layout: string) => void;
  fetchLLMStatus: () => Promise<void>;
}

export const useUIStore = create<UIState>((set, get) => ({
  sidebarOpen: true,
  activeTheme: "dark",
  graphLayout: "dagre",
  llmStatus: null,
  toggleSidebar: () => set(() => ({ sidebarOpen: !get().sidebarOpen })),
  setGraphLayout: (layout) => {
    set(() => ({ graphLayout: layout === "force" ? "force" : "dagre" }));
  },
  fetchLLMStatus: async () => {
    const { data } = await llmApi.status();
    set(() => ({
      llmStatus: {
        configured: Boolean(data.configured),
        provider: String(data.provider || "unknown"),
        model: String(data.model || "unknown"),
      },
    }));
  },
}));
