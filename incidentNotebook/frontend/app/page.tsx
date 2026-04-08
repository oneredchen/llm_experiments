"use client";

import Sidebar from "@/components/sidebar";
import { Shield, ArrowRight } from "lucide-react";

export default function Home() {
  return (
    <div className="flex h-screen">
      <Sidebar />
      <main className="flex-1 flex items-center justify-center dot-grid overflow-auto">
        <div className="text-center max-w-sm animate-fade-in">
          {/* Logo mark */}
          <div className="w-16 h-16 rounded-2xl bg-amber-glow border border-amber-dim/40 flex items-center justify-center mx-auto mb-6 amber-glow">
            <Shield className="w-7 h-7 text-amber-DEFAULT" />
          </div>

          <h2 className="font-syne font-bold text-xl text-text-primary mb-2">
            Incident Notebook
          </h2>
          <p className="text-sm text-text-secondary leading-relaxed mb-6">
            AI-powered IOC extraction for incident response.
            <br />
            Select a case or create a new one to begin.
          </p>

          {/* Feature list */}
          <ul className="space-y-2 text-left mb-8">
            {[
              "Paste raw incident notes",
              "LLM extracts IOCs and timeline",
              "Host, network indicators structured",
              "Chronological event timeline built",
            ].map((item, i) => (
              <li
                key={i}
                className="flex items-center gap-2.5 text-xs text-text-muted"
              >
                <ArrowRight className="w-3.5 h-3.5 text-amber-DEFAULT flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>

          <p className="text-xs text-text-muted font-mono">
            ← Create a case in the sidebar to start
          </p>
        </div>
      </main>
    </div>
  );
}
