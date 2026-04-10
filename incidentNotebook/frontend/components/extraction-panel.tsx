"use client";

import { useState, useEffect } from "react";
import { api, ExtractionResult } from "@/lib/api";
import {
  Cpu,
  Play,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  Zap,
  FileText,
  Network,
  Clock,
} from "lucide-react";
import clsx from "clsx";

interface ExtractionPanelProps {
  caseId: string;
  onExtractionComplete: () => void;
}

export default function ExtractionPanel({
  caseId,
  onExtractionComplete,
}: ExtractionPanelProps) {
  const [text, setText] = useState("");
  const [models, setModels] = useState<string[]>([]);
  const [selectedModel, setSelectedModel] = useState("");
  const [loadingModels, setLoadingModels] = useState(true);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ExtractionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showModelDropdown, setShowModelDropdown] = useState(false);

  useEffect(() => {
    api
      .getModels()
      .then(({ models }) => {
        setModels(models);
        if (models.length > 0) setSelectedModel(models[0]);
      })
      .catch(() => {
        setModels([]);
      })
      .finally(() => setLoadingModels(false));
  }, []);

  async function handleExtract() {
    if (!text.trim() || !selectedModel) return;
    setRunning(true);
    setResult(null);
    setError(null);
    try {
      const res = await api.extractIOCs(caseId, text.trim(), selectedModel);
      setResult(res);
      onExtractionComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Extraction failed");
    } finally {
      setRunning(false);
    }
  }

  const charCount = text.length;
  const wordCount = text.trim() ? text.trim().split(/\s+/).length : 0;

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-2">
        <div className="w-6 h-6 rounded bg-amber-glow border border-amber-dim/50 flex items-center justify-center">
          <Zap className="w-3 h-3 text-amber-DEFAULT" />
        </div>
        <div>
          <h2 className="font-syne font-semibold text-sm text-text-primary">
            IOC Extraction
          </h2>
          <p className="text-xs text-text-muted mt-0.5">
            Paste raw incident notes to extract and structure indicators
          </p>
        </div>
      </div>

      {/* Model selector */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 text-xs text-text-muted">
          <Cpu className="w-3.5 h-3.5" />
          <span className="font-syne font-medium tracking-wide">MODEL</span>
        </div>
        <div className="relative">
          <button
            onClick={() => setShowModelDropdown(!showModelDropdown)}
            disabled={loadingModels}
            className={clsx(
              "flex items-center gap-2 px-3 py-1.5 rounded",
              "bg-elevated border border-border",
              "text-xs font-mono text-text-primary",
              "hover:border-amber-dim transition-colors",
              "min-w-[180px] text-left"
            )}
          >
            {loadingModels ? (
              <>
                <Loader2 className="w-3 h-3 animate-spin text-text-muted" />
                <span className="text-text-muted">Loading models…</span>
              </>
            ) : models.length === 0 ? (
              <span className="text-red-DEFAULT">No models available</span>
            ) : (
              <>
                <span className="flex-1 truncate">{selectedModel}</span>
                <ChevronDown className="w-3 h-3 text-text-muted flex-shrink-0" />
              </>
            )}
          </button>
          {showModelDropdown && models.length > 0 && (
            <div className="absolute top-full left-0 mt-1 w-full bg-elevated border border-border rounded shadow-xl z-10">
              {models.map((m) => (
                <button
                  key={m}
                  onClick={() => {
                    setSelectedModel(m);
                    setShowModelDropdown(false);
                  }}
                  className={clsx(
                    "w-full text-left px-3 py-2 text-xs font-mono",
                    "hover:bg-surface transition-colors",
                    selectedModel === m
                      ? "text-amber-DEFAULT"
                      : "text-text-primary"
                  )}
                >
                  {m}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Textarea */}
      <div className="relative">
        <div className="flex items-center gap-1.5 mb-2 text-xs text-text-muted">
          <FileText className="w-3.5 h-3.5" />
          <span className="font-syne font-medium tracking-wide uppercase">
            Incident Description
          </span>
        </div>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={`Paste raw incident notes here…

Example:
On 2024-01-15 at 03:42 UTC, EDR alerted on host WORKSTATION-07 (192.168.1.45).
Suspicious process svchost.exe spawned from cmd.exe with hash SHA256: a3f1c2...
Outbound connection to 185.220.101.45:443 observed over 6 hours.
Registry persistence key created: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`}
          rows={10}
          className={clsx(
            "w-full bg-elevated border border-border rounded",
            "px-4 py-3 text-sm text-text-primary font-outfit leading-relaxed",
            "placeholder:text-text-muted/50 placeholder:text-xs placeholder:font-mono",
            "focus:outline-none focus:border-amber-dim focus:ring-1 focus:ring-amber-DEFAULT/15",
            "resize-y min-h-[200px] transition-colors"
          )}
        />
        <div className="absolute bottom-3 right-3 flex gap-3 text-xs text-text-muted font-mono">
          <span>{wordCount} words</span>
          <span>{charCount} chars</span>
        </div>
      </div>

      {/* Run button */}
      <div className="flex items-center gap-4">
        <button
          onClick={handleExtract}
          disabled={running || !text.trim() || !selectedModel}
          className={clsx(
            "flex items-center gap-2 px-5 py-2.5 rounded",
            "font-syne font-bold text-sm tracking-wide",
            "transition-all duration-200",
            running || !text.trim() || !selectedModel
              ? "bg-elevated border border-border text-text-muted cursor-not-allowed"
              : "bg-amber-DEFAULT text-base hover:bg-amber-DEFAULT/90 amber-glow shadow-lg shadow-amber-DEFAULT/10 hover:shadow-amber-DEFAULT/20"
          )}
        >
          {running ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Analyzing…
            </>
          ) : (
            <>
              <Play className="w-4 h-4" />
              Run Extraction
            </>
          )}
        </button>
        {running && (
          <div className="flex items-center gap-2 text-xs text-text-secondary animate-fade-in">
            <div className="flex gap-1">
              {[0, 1, 2].map((i) => (
                <span
                  key={i}
                  className="w-1 h-1 rounded-full bg-amber-DEFAULT animate-pulse-amber"
                  style={{ animationDelay: `${i * 0.2}s` }}
                />
              ))}
            </div>
            LLM processing — this may take a moment
          </div>
        )}
      </div>

      {/* Error state */}
      {error && (
        <div className="flex items-start gap-2.5 p-3 bg-red-dim/20 border border-red-dim/40 rounded animate-fade-in">
          <AlertTriangle className="w-4 h-4 text-red-DEFAULT flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-red-DEFAULT">
              Extraction failed
            </p>
            <p className="text-xs text-text-secondary mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {/* Result summary */}
      {result && (
        <div className="border border-green-dim/40 bg-green-dim/10 rounded p-4 animate-fade-in">
          <div className="flex items-center gap-2 mb-3">
            <CheckCircle2 className="w-4 h-4 text-green-DEFAULT" />
            <p className="text-sm font-syne font-semibold text-green-DEFAULT">
              Extraction Complete
            </p>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <CountCard
              icon={<Cpu className="w-3.5 h-3.5" />}
              label="Host IOCs"
              value={result.counts.host_iocs}
            />
            <CountCard
              icon={<Network className="w-3.5 h-3.5" />}
              label="Network IOCs"
              value={result.counts.network_iocs}
            />
            <CountCard
              icon={<Clock className="w-3.5 h-3.5" />}
              label="Timeline Events"
              value={result.counts.timeline_events}
            />
          </div>
          <p className="text-xs text-text-muted mt-3">
            Switch to the IOC or Timeline tabs to view extracted data.
          </p>
        </div>
      )}
    </div>
  );
}

function CountCard({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
}) {
  return (
    <div className="bg-elevated border border-border rounded p-3 text-center">
      <div className="flex items-center justify-center gap-1.5 text-text-muted mb-1">
        {icon}
        <span className="text-xs font-syne uppercase tracking-wide">{label}</span>
      </div>
      <p className="text-2xl font-syne font-bold text-text-primary">{value}</p>
    </div>
  );
}
