"use client";

import { TimelineEvent } from "@/lib/api";
import { format, parseISO } from "date-fns";
import {
  Clock,
  Monitor,
  Shield,
  Database,
  ChevronRight,
  Hash,
} from "lucide-react";
import clsx from "clsx";

function statusColor(tag: string) {
  const t = tag.toLowerCase();
  if (t === "confirmed") return "border-red-DEFAULT/60 bg-red-dim/20";
  if (t.includes("suspicious") || t.includes("malicious"))
    return "border-amber-DEFAULT/60 bg-amber-glow";
  if (t === "benign" || t === "clean")
    return "border-green-DEFAULT/60 bg-green-dim/20";
  return "border-border bg-elevated";
}

function dotColor(tag: string) {
  const t = tag.toLowerCase();
  if (t === "confirmed") return "bg-red-DEFAULT";
  if (t.includes("suspicious") || t.includes("malicious"))
    return "bg-amber-DEFAULT";
  if (t === "benign" || t === "clean") return "bg-green-DEFAULT";
  return "bg-text-muted";
}

function StatusTag({ tag }: { tag: string }) {
  const t = tag.toLowerCase();
  return (
    <span
      className={clsx(
        "status-badge",
        t === "confirmed" &&
          "bg-red-dim/30 text-red-DEFAULT border border-red-dim/50",
        (t.includes("suspicious") || t.includes("malicious")) &&
          "bg-amber-glow text-amber-DEFAULT border border-amber-dim/50",
        (t === "benign" || t === "clean") &&
          "bg-green-dim/30 text-green-DEFAULT border border-green-dim/50",
        !["confirmed", "suspicious", "likely malicious", "benign", "clean"].some(
          (s) => t.includes(s)
        ) && "bg-elevated text-text-secondary border border-border"
      )}
    >
      {tag}
    </span>
  );
}

function formatTimestamp(ts: string) {
  try {
    const d = parseISO(ts);
    return {
      date: format(d, "yyyy-MM-dd"),
      time: format(d, "HH:mm:ss"),
      full: format(d, "yyyy-MM-dd HH:mm:ss"),
    };
  } catch {
    return { date: "—", time: ts, full: ts };
  }
}

export default function TimelineView({ events }: { events: TimelineEvent[] }) {
  if (events.length === 0) {
    return (
      <div className="animate-fade-in py-16 text-center">
        <div className="w-10 h-10 rounded-full bg-elevated border border-border flex items-center justify-center mx-auto mb-3">
          <Clock className="w-4 h-4 text-text-muted" />
        </div>
        <p className="text-sm text-text-secondary font-syne">
          No timeline events found
        </p>
        <p className="text-xs text-text-muted mt-1">
          Run extraction to build the incident timeline
        </p>
      </div>
    );
  }

  // Sort events by timestamp
  const sorted = [...events].sort((a, b) => {
    try {
      return (
        new Date(a.timestamp_utc).getTime() -
        new Date(b.timestamp_utc).getTime()
      );
    } catch {
      return 0;
    }
  });

  return (
    <div className="animate-fade-in">
      <div className="flex items-center gap-2 mb-6">
        <Clock className="w-4 h-4 text-text-muted" />
        <span className="font-syne font-semibold text-sm text-text-secondary">
          Incident Timeline
        </span>
        <span className="text-xs font-mono bg-elevated border border-border px-1.5 py-0.5 rounded text-text-muted">
          {events.length} events · UTC
        </span>
      </div>

      <div className="relative">
        {/* Vertical line */}
        <div className="absolute left-[88px] top-3 bottom-3 w-px bg-border" />

        <div className="space-y-0">
          {sorted.map((event, idx) => {
            const ts = formatTimestamp(event.timestamp_utc);
            const isLast = idx === sorted.length - 1;

            return (
              <div
                key={`${event.timestamp_utc}-${idx}`}
                className="flex gap-4 relative animate-slide-in"
                style={{ animationDelay: `${idx * 0.05}s` }}
              >
                {/* Timestamp column */}
                <div className="w-[80px] flex-shrink-0 pt-3 text-right">
                  <p className="text-xs font-mono text-text-muted leading-none">
                    {ts.date}
                  </p>
                  <p className="text-xs font-mono text-amber-DEFAULT leading-none mt-0.5 font-medium">
                    {ts.time}
                  </p>
                </div>

                {/* Dot */}
                <div className="relative flex-shrink-0 w-4 flex items-start justify-center pt-4">
                  <div
                    className={clsx(
                      "w-2.5 h-2.5 rounded-full border-2 border-base z-10",
                      dotColor(event.status_tag)
                    )}
                  />
                </div>

                {/* Card */}
                <div
                  className={clsx(
                    "flex-1 mb-3 rounded border p-3.5",
                    statusColor(event.status_tag)
                  )}
                >
                  {/* Card header */}
                  <div className="flex items-start gap-2 flex-wrap mb-2">
                    <StatusTag tag={event.status_tag} />
                    <div className="flex items-center gap-1.5 text-xs text-text-secondary">
                      <Monitor className="w-3 h-3 flex-shrink-0" />
                      <span className="font-mono">{event.system_name}</span>
                    </div>
                    {event.attack_alignment && (
                      <div className="flex items-center gap-1.5 text-xs text-cyan-DEFAULT bg-cyan-dim/20 border border-cyan-dim/30 rounded px-2 py-0.5">
                        <Shield className="w-3 h-3 flex-shrink-0" />
                        <span className="font-mono">{event.attack_alignment}</span>
                      </div>
                    )}
                  </div>

                  {/* Activity */}
                  <p className="text-sm text-text-primary leading-relaxed mb-2">
                    {event.activity}
                  </p>

                  {/* Metadata row */}
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-muted">
                    <span className="flex items-center gap-1">
                      <Database className="w-3 h-3" />
                      {event.evidence_source}
                    </span>
                    <span className="flex items-center gap-1">
                      <ChevronRight className="w-3 h-3" />
                      {event.timestamp_type}
                    </span>
                    {event.submitted_by && (
                      <span>by {event.submitted_by}</span>
                    )}
                  </div>

                  {/* Extra details */}
                  {(event.details_comments ||
                    event.hash ||
                    event.size_bytes != null ||
                    event.notes) && (
                    <div className="mt-2.5 pt-2.5 border-t border-border/50 space-y-1.5">
                      {event.details_comments && (
                        <p className="text-xs text-text-secondary leading-relaxed">
                          {event.details_comments}
                        </p>
                      )}
                      {event.hash && (
                        <div className="flex items-center gap-1.5">
                          <Hash className="w-3 h-3 text-text-muted flex-shrink-0" />
                          <span className="font-mono text-xs text-cyan-DEFAULT break-all">
                            {event.hash}
                          </span>
                        </div>
                      )}
                      {event.size_bytes != null && (
                        <p className="text-xs text-text-muted font-mono">
                          {event.size_bytes} bytes
                        </p>
                      )}
                      {event.notes && (
                        <p className="text-xs text-text-muted italic">
                          {event.notes}
                        </p>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
