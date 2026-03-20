import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        "bg-0": "var(--bg-0)",
        "bg-000": "var(--bg-000)",
        "bg-100": "var(--bg-100)",
        "bg-200": "var(--bg-200)",
        "bg-300": "var(--bg-300)",
        "text-100": "var(--text-100)",
        "text-200": "var(--text-200)",
        "text-300": "var(--text-300)",
        "text-400": "var(--text-400)",
        "text-500": "var(--text-500)",
        accent: "var(--accent)",
        "accent-hover": "var(--accent-hover)",
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
      boxShadow: {
        input: "0 1px 2px -1px rgba(0, 0, 0, 0.08), 0 2px 8px -2px rgba(0, 0, 0, 0.04)",
        "input-hover": "0 1px 2px -1px rgba(0, 0, 0, 0.08), 0 4px 12px -2px rgba(0, 0, 0, 0.08)",
        "input-focus": "0 0 0 2px rgba(217, 119, 87, 0.1), 0 4px 12px -2px rgba(0, 0, 0, 0.08)",
      },
      keyframes: {
        fadeIn: {
          from: {
            opacity: "0",
            transform: "translateY(8px) scale(0.98)",
            filter: "blur(4px)",
          },
          to: {
            opacity: "1",
            transform: "translateY(0) scale(1)",
            filter: "blur(0)",
          },
        },
      },
      animation: {
        "fade-in": "fadeIn 220ms var(--ease-silk, cubic-bezier(0.2, 0.0, 0, 1.0))",
      },
    },
  },
  plugins: [],
};

export default config;
