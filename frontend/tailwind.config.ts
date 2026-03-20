import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: {
          primary: "#0F172A",
          secondary: "#1E293B",
          tertiary: "#334155",
        },
        text: {
          primary: "#F1F5F9",
          secondary: "#94A3B8",
          accent: "#38BDF8",
        },
        severity: {
          critical: "#7F1D1D",
          criticalFg: "#FCA5A5",
          high: "#EF4444",
          highFg: "#FEF2F2",
          medium: "#F97316",
          mediumFg: "#FFF7ED",
          low: "#EAB308",
          lowFg: "#FEFCE8",
          info: "#6B7280",
          infoFg: "#F9FAFB",
        },
        brand: {
          DEFAULT: "#38BDF8",
          dark: "#0EA5E9",
        },
      },
    },
  },
  plugins: [],
};

export default config;
