"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter, usePathname } from "next/navigation";
import { api, Case } from "@/lib/api";
import {
  Shield,
  Plus,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Loader2,
  ChevronRight,
  Activity,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import clsx from "clsx";

interface SidebarProps {
  onCasesChange?: (cases: Case[]) => void;
}

function StatusDot({ status }: { status: string }) {
  const s = status.toLowerCase();
  if (s === "completed")
    return (
      <span className="w-1.5 h-1.5 rounded-full bg-green-DEFAULT flex-shrink-0" />
    );
  if (s === "processing" || s === "running")
    return (
      <span className="w-1.5 h-1.5 rounded-full bg-amber-DEFAULT flex-shrink-0 animate-pulse-amber" />
    );
  if (s === "error" || s === "failed")
    return (
      <span className="w-1.5 h-1.5 rounded-full bg-red-DEFAULT flex-shrink-0" />
    );
  return (
    <span className="w-1.5 h-1.5 rounded-full bg-text-muted flex-shrink-0" />
  );
}

export default function Sidebar({ onCasesChange }: SidebarProps) {
  const router = useRouter();
  const pathname = usePathname();
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [newCaseName, setNewCaseName] = useState("");
  const [showNewForm, setShowNewForm] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const activeCaseId = pathname.startsWith("/cases/")
    ? pathname.split("/cases/")[1]
    : null;

  const fetchCases = useCallback(async () => {
    try {
      const data = await api.getCases();
      setCases(data);
      onCasesChange?.(data);
    } catch {
      setError("Failed to connect to backend");
    } finally {
      setLoading(false);
    }
  }, [onCasesChange]);

  useEffect(() => {
    fetchCases();
  }, [fetchCases]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!newCaseName.trim()) return;
    setCreating(true);
    try {
      const created = await api.createCase(newCaseName.trim());
      await fetchCases();
      setNewCaseName("");
      setShowNewForm(false);
      router.push(`/cases/${created.case_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create case");
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(e: React.MouseEvent, caseId: string) {
    e.stopPropagation();
    e.preventDefault();
    setDeletingId(caseId);
    try {
      await api.deleteCase(caseId);
      await fetchCases();
      if (activeCaseId === caseId) router.push("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete case");
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <aside className="relative w-64 flex-shrink-0 flex flex-col h-full border-r border-border bg-surface scanlines">
      {/* Header */}
      <div className="px-4 py-5 border-b border-border">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded bg-amber-glow border border-amber-dim flex items-center justify-center flex-shrink-0">
            <Shield className="w-3.5 h-3.5 text-amber-DEFAULT" />
          </div>
          <div>
            <h1 className="font-syne font-bold text-sm text-text-primary tracking-wide leading-none">
              INCIDENT
            </h1>
            <p className="font-syne text-xs text-amber-DEFAULT tracking-widest leading-none mt-0.5">
              NOTEBOOK
            </p>
          </div>
        </div>
        {error && (
          <div className="mt-3 flex items-center gap-1.5 text-xs text-red-DEFAULT bg-red-dim/20 border border-red-dim/30 rounded px-2 py-1.5">
            <AlertTriangle className="w-3 h-3 flex-shrink-0" />
            <span className="truncate">{error}</span>
          </div>
        )}
      </div>

      {/* Cases label */}
      <div className="px-4 pt-4 pb-2 flex items-center justify-between">
        <span className="text-xs font-syne font-semibold text-text-muted tracking-widest uppercase">
          Cases
        </span>
        <Activity className="w-3 h-3 text-text-muted" />
      </div>

      {/* Cases list */}
      <div className="flex-1 overflow-y-auto px-2 pb-2">
        {loading ? (
          <div className="space-y-1.5 px-2">
            {[...Array(4)].map((_, i) => (
              <div
                key={i}
                className="skeleton h-12 rounded"
                style={{ animationDelay: `${i * 0.1}s` }}
              />
            ))}
          </div>
        ) : cases.length === 0 ? (
          <div className="px-2 py-6 text-center">
            <p className="text-xs text-text-muted leading-relaxed">
              No cases yet.
              <br />
              Create one to get started.
            </p>
          </div>
        ) : (
          <ul className="space-y-0.5">
            {cases.map((c) => {
              const isActive = activeCaseId === c.case_id;
              return (
                <li key={c.case_id}>
                  <button
                    onClick={() => router.push(`/cases/${c.case_id}`)}
                    className={clsx(
                      "w-full text-left px-3 py-2.5 rounded group flex items-start gap-2.5 transition-all duration-150",
                      isActive
                        ? "bg-elevated border border-border text-text-primary"
                        : "text-text-secondary hover:text-text-primary hover:bg-elevated/60"
                    )}
                  >
                    <StatusDot status={c.status} />
                    <div className="flex-1 min-w-0 mt-0.5">
                      <p className="text-xs font-medium truncate leading-tight">
                        {c.name}
                      </p>
                      <p className="text-xs text-text-muted mt-0.5 font-mono">
                        {c.case_id.slice(0, 8)}…
                      </p>
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      {isActive && (
                        <ChevronRight className="w-3 h-3 text-amber-DEFAULT" />
                      )}
                      <button
                        onClick={(e) => handleDelete(e, c.case_id)}
                        className={clsx(
                          "p-1 rounded transition-all",
                          "opacity-0 group-hover:opacity-100",
                          "hover:bg-red-dim/30 hover:text-red-DEFAULT text-text-muted"
                        )}
                        title="Delete case"
                      >
                        {deletingId === c.case_id ? (
                          <Loader2 className="w-3 h-3 animate-spin" />
                        ) : (
                          <Trash2 className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* New case form */}
      <div className="px-3 pb-4 border-t border-border pt-3">
        {showNewForm ? (
          <form onSubmit={handleCreate} className="animate-fade-in">
            <input
              type="text"
              value={newCaseName}
              onChange={(e) => setNewCaseName(e.target.value)}
              placeholder="Case name…"
              autoFocus
              className={clsx(
                "w-full bg-elevated border border-border rounded px-3 py-2",
                "text-xs text-text-primary placeholder:text-text-muted",
                "focus:outline-none focus:border-amber-dim focus:ring-1 focus:ring-amber-DEFAULT/20",
                "transition-colors"
              )}
            />
            <div className="flex gap-1.5 mt-2">
              <button
                type="submit"
                disabled={creating || !newCaseName.trim()}
                className={clsx(
                  "flex-1 flex items-center justify-center gap-1.5",
                  "bg-amber-DEFAULT text-base text-xs font-syne font-semibold",
                  "px-3 py-1.5 rounded transition-all",
                  "hover:bg-amber-DEFAULT/90 disabled:opacity-40 disabled:cursor-not-allowed"
                )}
              >
                {creating ? (
                  <Loader2 className="w-3 h-3 animate-spin" />
                ) : (
                  <CheckCircle2 className="w-3 h-3" />
                )}
                Create
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowNewForm(false);
                  setNewCaseName("");
                }}
                className="px-3 py-1.5 rounded text-xs text-text-muted hover:text-text-primary hover:bg-elevated transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        ) : (
          <button
            onClick={() => setShowNewForm(true)}
            className={clsx(
              "w-full flex items-center justify-center gap-2",
              "border border-border hover:border-amber-dim",
              "text-text-secondary hover:text-amber-DEFAULT",
              "text-xs font-syne font-semibold tracking-wide",
              "py-2 rounded transition-all duration-150",
              "hover:bg-amber-glow"
            )}
          >
            <Plus className="w-3.5 h-3.5" />
            New Case
          </button>
        )}
      </div>

      {/* Footer */}
      <div className="px-4 py-2 border-t border-border-subtle">
        <p className="text-xs text-text-muted font-mono">
          {cases.length} case{cases.length !== 1 ? "s" : ""}
        </p>
      </div>
    </aside>
  );
}
