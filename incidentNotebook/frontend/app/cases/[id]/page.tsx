"use client";

import { useState, useEffect, useCallback } from "react";
import { useParams } from "next/navigation";
import Sidebar from "@/components/sidebar";
import ExtractionPanel from "@/components/extraction-panel";
import { HostIOCTable, NetworkIOCTable } from "@/components/ioc-tables";
import TimelineView from "@/components/timeline-view";
import { api, Case, CaseData } from "@/lib/api";
import {
  Zap,
  Cpu,
  Network,
  Clock,
  Loader2,
  AlertTriangle,
  Calendar,
  Tag,
  RefreshCw,
} from "lucide-react";
import { format, parseISO } from "date-fns";
import clsx from "clsx";

type Tab = "extract" | "host" | "network" | "timeline";

const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: "extract", label: "Extract", icon: <Zap className="w-3.5 h-3.5" /> },
  { id: "host", label: "Host IOCs", icon: <Cpu className="w-3.5 h-3.5" /> },
  { id: "network", label: "Network IOCs", icon: <Network className="w-3.5 h-3.5" /> },
  { id: "timeline", label: "Timeline", icon: <Clock className="w-3.5 h-3.5" /> },
];

function StatusBadge({ status }: { status: string }) {
  const s = status.toLowerCase();
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium uppercase tracking-wide",
        s === "completed" &&
          "bg-green-dim/30 text-green-DEFAULT border border-green-dim/50",
        (s === "processing" || s === "running") &&
          "bg-amber-glow text-amber-DEFAULT border border-amber-dim/50",
        (s === "error" || s === "failed") &&
          "bg-red-dim/30 text-red-DEFAULT border border-red-dim/50",
        !["completed", "processing", "running", "error", "failed"].includes(s) &&
          "bg-elevated text-text-secondary border border-border"
      )}
    >
      {s === "processing" || s === "running" ? (
        <Loader2 className="w-2.5 h-2.5 animate-spin" />
      ) : (
        <span className="w-1.5 h-1.5 rounded-full bg-current" />
      )}
      {status}
    </span>
  );
}

export default function CasePage() {
  const params = useParams();
  const caseId = params.id as string;

  const [caseInfo, setCaseInfo] = useState<Case | null>(null);
  const [caseData, setCaseData] = useState<CaseData | null>(null);
  const [loadingCase, setLoadingCase] = useState(true);
  const [loadingData, setLoadingData] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("extract");
  const [refreshing, setRefreshing] = useState(false);

  const fetchCaseInfo = useCallback(async () => {
    try {
      const cases = await api.getCases();
      const found = cases.find((c) => c.case_id === caseId);
      if (!found) throw new Error("Case not found");
      setCaseInfo(found);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load case");
    } finally {
      setLoadingCase(false);
    }
  }, [caseId]);

  const fetchCaseData = useCallback(async () => {
    try {
      const data = await api.getCaseData(caseId);
      setCaseData(data);
    } catch (err) {
      console.error("Failed to load case data:", err);
    } finally {
      setLoadingData(false);
    }
  }, [caseId]);

  useEffect(() => {
    setLoadingCase(true);
    setLoadingData(true);
    setError(null);
    fetchCaseInfo();
    fetchCaseData();
  }, [caseId, fetchCaseInfo, fetchCaseData]);

  async function handleRefresh() {
    setRefreshing(true);
    await fetchCaseData();
    setRefreshing(false);
  }

  async function handleExtractionComplete() {
    await fetchCaseData();
    // Switch to first IOC tab with data
  }

  const totalIOCs =
    (caseData?.host_iocs.length ?? 0) +
    (caseData?.network_iocs.length ?? 0);

  return (
    <div className="flex h-screen">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Case header */}
        <header className="flex-shrink-0 border-b border-border bg-surface px-6 py-4">
          {loadingCase ? (
            <div className="flex items-center gap-3">
              <div className="skeleton h-4 w-48 rounded" />
              <div className="skeleton h-5 w-20 rounded" />
            </div>
          ) : error ? (
            <div className="flex items-center gap-2 text-red-DEFAULT">
              <AlertTriangle className="w-4 h-4" />
              <span className="text-sm">{error}</span>
            </div>
          ) : caseInfo ? (
            <div className="flex items-start justify-between">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3 flex-wrap">
                  <h1 className="font-syne font-bold text-lg text-text-primary leading-none truncate">
                    {caseInfo.name}
                  </h1>
                  <StatusBadge status={caseInfo.status} />
                </div>
                <div className="flex items-center gap-4 mt-2 flex-wrap">
                  <div className="flex items-center gap-1.5 text-xs text-text-muted">
                    <Tag className="w-3 h-3" />
                    <span className="font-mono">{caseInfo.case_id}</span>
                  </div>
                  {caseInfo.created_at && (
                    <div className="flex items-center gap-1.5 text-xs text-text-muted">
                      <Calendar className="w-3 h-3" />
                      <span>
                        {format(parseISO(caseInfo.created_at), "MMM d, yyyy HH:mm")} UTC
                      </span>
                    </div>
                  )}
                  {!loadingData && totalIOCs > 0 && (
                    <div className="flex items-center gap-1.5 text-xs text-green-DEFAULT">
                      <span className="w-1.5 h-1.5 rounded-full bg-green-DEFAULT" />
                      <span>
                        {totalIOCs} indicator{totalIOCs !== 1 ? "s" : ""} extracted
                      </span>
                    </div>
                  )}
                </div>
              </div>

              <button
                onClick={handleRefresh}
                disabled={refreshing}
                className="p-2 rounded hover:bg-elevated text-text-muted hover:text-text-primary transition-colors"
                title="Refresh data"
              >
                <RefreshCw
                  className={clsx("w-4 h-4", refreshing && "animate-spin")}
                />
              </button>
            </div>
          ) : null}
        </header>

        {/* Tab navigation */}
        <nav className="flex-shrink-0 flex items-center gap-0 border-b border-border bg-surface px-4">
          {TABS.map((tab) => {
            const count =
              tab.id === "host"
                ? caseData?.host_iocs.length
                : tab.id === "network"
                ? caseData?.network_iocs.length
                : tab.id === "timeline"
                ? caseData?.timeline_events.length
                : undefined;

            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  "flex items-center gap-2 px-4 py-3 text-xs font-syne font-semibold tracking-wide border-b-2 -mb-px transition-all",
                  activeTab === tab.id
                    ? "border-amber-DEFAULT text-amber-DEFAULT"
                    : "border-transparent text-text-muted hover:text-text-secondary hover:border-border"
                )}
              >
                {tab.icon}
                {tab.label}
                {count !== undefined && count > 0 && (
                  <span className="font-mono text-xs bg-elevated border border-border px-1.5 py-0.5 rounded leading-none">
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Tab content */}
        <div className="flex-1 overflow-y-auto dot-grid">
          <div className="max-w-5xl mx-auto px-6 py-6">
            {activeTab === "extract" && (
              <ExtractionPanel
                caseId={caseId}
                onExtractionComplete={handleExtractionComplete}
              />
            )}

            {activeTab === "host" && (
              <>
                {loadingData ? (
                  <LoadingSkeleton />
                ) : (
                  <HostIOCTable iocs={caseData?.host_iocs ?? []} />
                )}
              </>
            )}

            {activeTab === "network" && (
              <>
                {loadingData ? (
                  <LoadingSkeleton />
                ) : (
                  <NetworkIOCTable iocs={caseData?.network_iocs ?? []} />
                )}
              </>
            )}

            {activeTab === "timeline" && (
              <>
                {loadingData ? (
                  <LoadingSkeleton />
                ) : (
                  <TimelineView events={caseData?.timeline_events ?? []} />
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function LoadingSkeleton() {
  return (
    <div className="space-y-3 animate-fade-in">
      {[...Array(5)].map((_, i) => (
        <div
          key={i}
          className="skeleton h-12 rounded"
          style={{ animationDelay: `${i * 0.08}s` }}
        />
      ))}
    </div>
  );
}
