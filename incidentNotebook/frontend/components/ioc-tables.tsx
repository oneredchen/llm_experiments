"use client";

import { useState } from "react";
import { HostIOC, NetworkIOC } from "@/lib/api";
import {
  Cpu,
  Network,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Filter,
  Hash,
} from "lucide-react";
import clsx from "clsx";

function StatusBadge({ status }: { status: string }) {
  const s = status.toLowerCase();
  const styles = clsx("status-badge", {
    "bg-red-dim/30 text-red-DEFAULT border border-red-dim/50":
      s === "confirmed",
    "bg-amber-glow text-amber-DEFAULT border border-amber-dim/50":
      s === "suspicious" || s === "likely malicious",
    "bg-green-dim/30 text-green-DEFAULT border border-green-dim/50":
      s === "benign" || s === "clean",
    "bg-elevated text-text-secondary border border-border":
      !["confirmed", "suspicious", "likely malicious", "benign", "clean"].includes(s),
  });
  return <span className={styles}>{status}</span>;
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  function handleCopy() {
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }
  return (
    <button
      onClick={handleCopy}
      className="p-1 rounded hover:bg-elevated text-text-muted hover:text-cyan-DEFAULT transition-colors flex-shrink-0"
      title="Copy"
    >
      {copied ? (
        <Check className="w-3 h-3 text-green-DEFAULT" />
      ) : (
        <Copy className="w-3 h-3" />
      )}
    </button>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="py-16 text-center">
      <div className="w-10 h-10 rounded-full bg-elevated border border-border flex items-center justify-center mx-auto mb-3">
        <Hash className="w-4 h-4 text-text-muted" />
      </div>
      <p className="text-sm text-text-secondary font-syne">No {label} found</p>
      <p className="text-xs text-text-muted mt-1">
        Run extraction to populate this table
      </p>
    </div>
  );
}

type SortDir = "asc" | "desc" | null;

function SortHeader({
  label,
  field,
  sortField,
  sortDir,
  onSort,
}: {
  label: string;
  field: string;
  sortField: string | null;
  sortDir: SortDir;
  onSort: (f: string) => void;
}) {
  const active = sortField === field;
  return (
    <th
      className="px-4 py-2.5 text-left cursor-pointer group select-none"
      onClick={() => onSort(field)}
    >
      <div className="flex items-center gap-1.5">
        <span
          className={clsx(
            "text-xs font-syne font-semibold tracking-widest uppercase transition-colors",
            active ? "text-amber-DEFAULT" : "text-text-muted group-hover:text-text-secondary"
          )}
        >
          {label}
        </span>
        {active && sortDir === "asc" && (
          <ChevronUp className="w-3 h-3 text-amber-DEFAULT" />
        )}
        {active && sortDir === "desc" && (
          <ChevronDown className="w-3 h-3 text-amber-DEFAULT" />
        )}
      </div>
    </th>
  );
}

/* ─── HOST IOC TABLE ─── */
export function HostIOCTable({ iocs }: { iocs: HostIOC[] }) {
  const [filter, setFilter] = useState("");
  const [sortField, setSortField] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<SortDir>(null);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  function handleSort(field: string) {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : d === "desc" ? null : "asc"));
      if (sortDir === "desc") setSortField(null);
    } else {
      setSortField(field);
      setSortDir("asc");
    }
  }

  const filtered = iocs.filter((ioc) => {
    const q = filter.toLowerCase();
    return (
      !q ||
      ioc.indicator.toLowerCase().includes(q) ||
      ioc.indicator_type.toLowerCase().includes(q) ||
      ioc.status.toLowerCase().includes(q) ||
      ioc.source.toLowerCase().includes(q)
    );
  });

  const sorted = sortField
    ? [...filtered].sort((a, b) => {
        const av = String((a as unknown as Record<string, unknown>)[sortField] ?? "").toLowerCase();
        const bv = String((b as unknown as Record<string, unknown>)[sortField] ?? "").toLowerCase();
        return sortDir === "asc"
          ? av.localeCompare(bv)
          : bv.localeCompare(av);
      })
    : filtered;

  return (
    <div className="animate-fade-in">
      <div className="flex items-center gap-3 mb-4">
        <div className="flex items-center gap-2 text-text-muted">
          <Cpu className="w-4 h-4" />
          <span className="font-syne font-semibold text-sm text-text-secondary">
            Host IOCs
          </span>
          <span className="text-xs font-mono bg-elevated border border-border px-1.5 py-0.5 rounded">
            {iocs.length}
          </span>
        </div>
        <div className="flex-1" />
        {iocs.length > 0 && (
          <div className="relative">
            <Filter className="w-3.5 h-3.5 text-text-muted absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter…"
              className={clsx(
                "pl-7 pr-3 py-1.5 bg-elevated border border-border rounded",
                "text-xs text-text-primary placeholder:text-text-muted",
                "focus:outline-none focus:border-amber-dim w-40 transition-colors"
              )}
            />
          </div>
        )}
      </div>

      {iocs.length === 0 ? (
        <EmptyState label="host IOCs" />
      ) : (
        <div className="border border-border rounded overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="bg-elevated border-b border-border">
                  <SortHeader label="Indicator" field="indicator" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <SortHeader label="Type" field="indicator_type" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <SortHeader label="Status" field="status" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <SortHeader label="Source" field="source" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <th className="px-4 py-2.5 text-left text-xs font-syne font-semibold tracking-widest uppercase text-text-muted">
                    Details
                  </th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((ioc, idx) => {
                  const rowKey = `${ioc.indicator_id}-${idx}`;
                  const isExpanded = expandedRow === rowKey;
                  const hasExtras =
                    ioc.sha256 || ioc.sha1 || ioc.md5 || ioc.full_path || ioc.notes;
                  return (
                    <>
                      <tr
                        key={rowKey}
                        className={clsx(
                          "ioc-row cursor-pointer",
                          isExpanded && "bg-elevated/50"
                        )}
                        onClick={() =>
                          hasExtras
                            ? setExpandedRow(isExpanded ? null : rowKey)
                            : undefined
                        }
                      >
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs text-cyan-DEFAULT break-all">
                              {ioc.indicator}
                            </span>
                            <CopyButton value={ioc.indicator} />
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs font-mono text-text-secondary bg-elevated border border-border-subtle px-2 py-0.5 rounded">
                            {ioc.indicator_type}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <StatusBadge status={ioc.status} />
                        </td>
                        <td className="px-4 py-3 text-xs text-text-secondary">
                          {ioc.source}
                        </td>
                        <td className="px-4 py-3">
                          {hasExtras && (
                            <button className="text-xs text-text-muted hover:text-amber-DEFAULT transition-colors font-mono flex items-center gap-1">
                              {isExpanded ? (
                                <ChevronUp className="w-3 h-3" />
                              ) : (
                                <ChevronDown className="w-3 h-3" />
                              )}
                              {isExpanded ? "hide" : "expand"}
                            </button>
                          )}
                        </td>
                      </tr>
                      {isExpanded && hasExtras && (
                        <tr className="bg-elevated/40 border-b border-border">
                          <td colSpan={5} className="px-4 py-3">
                            <div className="grid grid-cols-2 gap-3 text-xs">
                              {ioc.full_path && (
                                <Detail label="Full Path" value={ioc.full_path} mono />
                              )}
                              {ioc.sha256 && (
                                <Detail label="SHA256" value={ioc.sha256} mono copyable />
                              )}
                              {ioc.sha1 && (
                                <Detail label="SHA1" value={ioc.sha1} mono copyable />
                              )}
                              {ioc.md5 && (
                                <Detail label="MD5" value={ioc.md5} mono copyable />
                              )}
                              {ioc.size_bytes != null && (
                                <Detail label="Size" value={`${ioc.size_bytes} bytes`} />
                              )}
                              {ioc.notes && (
                                <Detail label="Notes" value={ioc.notes} className="col-span-2" />
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── NETWORK IOC TABLE ─── */
export function NetworkIOCTable({ iocs }: { iocs: NetworkIOC[] }) {
  const [filter, setFilter] = useState("");
  const [sortField, setSortField] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<SortDir>(null);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  function handleSort(field: string) {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : d === "desc" ? null : "asc"));
      if (sortDir === "desc") setSortField(null);
    } else {
      setSortField(field);
      setSortDir("asc");
    }
  }

  const filtered = iocs.filter((ioc) => {
    const q = filter.toLowerCase();
    return (
      !q ||
      ioc.indicator.toLowerCase().includes(q) ||
      ioc.indicator_type.toLowerCase().includes(q) ||
      ioc.status.toLowerCase().includes(q) ||
      ioc.source.toLowerCase().includes(q)
    );
  });

  const sorted = sortField
    ? [...filtered].sort((a, b) => {
        const av = String((a as unknown as Record<string, unknown>)[sortField] ?? "").toLowerCase();
        const bv = String((b as unknown as Record<string, unknown>)[sortField] ?? "").toLowerCase();
        return sortDir === "asc"
          ? av.localeCompare(bv)
          : bv.localeCompare(av);
      })
    : filtered;

  return (
    <div className="animate-fade-in">
      <div className="flex items-center gap-3 mb-4">
        <div className="flex items-center gap-2 text-text-muted">
          <Network className="w-4 h-4" />
          <span className="font-syne font-semibold text-sm text-text-secondary">
            Network IOCs
          </span>
          <span className="text-xs font-mono bg-elevated border border-border px-1.5 py-0.5 rounded">
            {iocs.length}
          </span>
        </div>
        <div className="flex-1" />
        {iocs.length > 0 && (
          <div className="relative">
            <Filter className="w-3.5 h-3.5 text-text-muted absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter…"
              className={clsx(
                "pl-7 pr-3 py-1.5 bg-elevated border border-border rounded",
                "text-xs text-text-primary placeholder:text-text-muted",
                "focus:outline-none focus:border-amber-dim w-40 transition-colors"
              )}
            />
          </div>
        )}
      </div>

      {iocs.length === 0 ? (
        <EmptyState label="network IOCs" />
      ) : (
        <div className="border border-border rounded overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="bg-elevated border-b border-border">
                  <SortHeader label="Indicator" field="indicator" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <SortHeader label="Type" field="indicator_type" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <SortHeader label="Status" field="status" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <SortHeader label="Source" field="source" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                  <th className="px-4 py-2.5 text-left text-xs font-syne font-semibold tracking-widest uppercase text-text-muted">
                    Details
                  </th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((ioc, idx) => {
                  const rowKey = `${ioc.indicator_id}-${idx}`;
                  const isExpanded = expandedRow === rowKey;
                  const hasExtras =
                    ioc.initial_lead ||
                    ioc.details_comments ||
                    ioc.attack_alignment ||
                    ioc.notes;
                  return (
                    <>
                      <tr
                        key={rowKey}
                        className={clsx(
                          "ioc-row cursor-pointer",
                          isExpanded && "bg-elevated/50"
                        )}
                        onClick={() =>
                          hasExtras
                            ? setExpandedRow(isExpanded ? null : rowKey)
                            : undefined
                        }
                      >
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs text-cyan-DEFAULT break-all">
                              {ioc.indicator}
                            </span>
                            <CopyButton value={ioc.indicator} />
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs font-mono text-text-secondary bg-elevated border border-border-subtle px-2 py-0.5 rounded">
                            {ioc.indicator_type}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <StatusBadge status={ioc.status} />
                        </td>
                        <td className="px-4 py-3 text-xs text-text-secondary">
                          {ioc.source}
                        </td>
                        <td className="px-4 py-3">
                          {hasExtras && (
                            <button className="text-xs text-text-muted hover:text-amber-DEFAULT transition-colors font-mono flex items-center gap-1">
                              {isExpanded ? (
                                <ChevronUp className="w-3 h-3" />
                              ) : (
                                <ChevronDown className="w-3 h-3" />
                              )}
                              {isExpanded ? "hide" : "expand"}
                            </button>
                          )}
                        </td>
                      </tr>
                      {isExpanded && hasExtras && (
                        <tr className="bg-elevated/40 border-b border-border">
                          <td colSpan={5} className="px-4 py-3">
                            <div className="grid grid-cols-2 gap-3 text-xs">
                              {ioc.initial_lead && (
                                <Detail label="Initial Lead" value={ioc.initial_lead} />
                              )}
                              {ioc.attack_alignment && (
                                <Detail label="ATT&CK" value={ioc.attack_alignment} />
                              )}
                              {ioc.details_comments && (
                                <Detail label="Comments" value={ioc.details_comments} className="col-span-2" />
                              )}
                              {ioc.notes && (
                                <Detail label="Notes" value={ioc.notes} className="col-span-2" />
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function Detail({
  label,
  value,
  mono,
  copyable,
  className,
}: {
  label: string;
  value: string;
  mono?: boolean;
  copyable?: boolean;
  className?: string;
}) {
  return (
    <div className={clsx("space-y-0.5", className)}>
      <p className="text-text-muted uppercase tracking-widest font-syne text-xs">
        {label}
      </p>
      <div className="flex items-start gap-1.5">
        <p
          className={clsx(
            "break-all leading-relaxed",
            mono
              ? "font-mono text-cyan-DEFAULT"
              : "text-text-secondary font-outfit"
          )}
        >
          {value}
        </p>
        {copyable && <CopyButton value={value} />}
      </div>
    </div>
  );
}
