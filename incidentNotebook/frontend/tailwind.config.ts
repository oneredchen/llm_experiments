import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        syne: ["var(--font-syne)"],
        outfit: ["var(--font-outfit)"],
        mono: ["var(--font-jetbrains)", "monospace"],
      },
      colors: {
        base: "#08090E",
        surface: "#0F1420",
        elevated: "#161D2E",
        border: "#1C2438",
        "border-subtle": "#141A27",
        "text-primary": "#E4EAF2",
        "text-secondary": "#7D8FAA",
        "text-muted": "#424F66",
        amber: {
          DEFAULT: "#F59E0B",
          dim: "#92600A",
          glow: "rgba(245,158,11,0.12)",
        },
        cyan: {
          DEFAULT: "#22D3EE",
          dim: "#164E63",
        },
        red: {
          DEFAULT: "#F87171",
          dim: "#7F1D1D",
        },
        green: {
          DEFAULT: "#34D399",
          dim: "#064E3B",
        },
      },
      keyframes: {
        "pulse-amber": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.4" },
        },
        "fade-in": {
          from: { opacity: "0", transform: "translateY(6px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "slide-in": {
          from: { opacity: "0", transform: "translateX(-8px)" },
          to: { opacity: "1", transform: "translateX(0)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
      animation: {
        "pulse-amber": "pulse-amber 2s ease-in-out infinite",
        "fade-in": "fade-in 0.3s ease-out forwards",
        "slide-in": "slide-in 0.25s ease-out forwards",
        shimmer: "shimmer 1.5s linear infinite",
      },
    },
  },
  plugins: [],
};

export default config;
