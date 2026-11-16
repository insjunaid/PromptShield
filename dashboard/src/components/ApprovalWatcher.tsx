import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Hand, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";

import { fetchApprovals } from "@/api/client";
import { useLiveStore } from "@/store/live";

export const TOAST_MS = 8_000;

/** Pending approvals, shared by the sidebar badge and the Approvals page through the query cache. */
export function usePendingApprovals() {
  return useQuery({ queryKey: ["approvals", "pending"], queryFn: () => fetchApprovals("pending"), refetchInterval: 10_000 });
}

interface Toast {
  id: string;
  tool: string;
  approvalId: string;
}

function approvalId(payload: unknown): string {
  const value = (payload as { approval_id?: unknown } | undefined)?.approval_id;
  return typeof value === "string" ? value : "";
}

/**
 * Watches the live stream for approval events. A new request shows a toast (no sound) and
 * refreshes the queue; a decision refreshes it too. Events that were already there when the page
 * opened don't toast, so a reload doesn't replay old alerts.
 */
export function ApprovalWatcher() {
  const client = useQueryClient();
  const events = useLiveStore((state) => state.events);
  const seen = useRef<Set<string> | null>(null);
  // History loads after the page opens, so "new to this page" also means "happened after it opened".
  const openedAt = useRef(Date.now() - 5_000);
  const [toasts, setToasts] = useState<Toast[]>([]);

  useEffect(() => {
    if (seen.current === null) {
      seen.current = new Set(events.map((event) => event.id));
      return;
    }
    const known = seen.current;
    const fresh = events.filter((event) => !known.has(event.id));
    for (const event of fresh) known.add(event.id);
    const approvalEvents = fresh.filter((event) => event.type === "approval_requested" || event.type === "approval_resolved");
    if (approvalEvents.length === 0) return;
    void client.invalidateQueries({ queryKey: ["approvals"] });
    // A decided approval no longer needs its toast.
    const resolved = new Set(approvalEvents.filter((event) => event.type === "approval_resolved").map((event) => approvalId(event.payload)));
    if (resolved.size > 0) setToasts((current) => current.filter((toast) => !resolved.has(toast.approvalId)));
    const requested = approvalEvents.filter(
      (event) => event.type === "approval_requested" && Date.parse(event.ts) >= openedAt.current && !resolved.has(approvalId(event.payload)),
    );
    if (requested.length > 0) {
      setToasts((current) => [...current, ...requested.map((event) => ({ id: event.id, tool: event.tool ?? "a tool", approvalId: approvalId(event.payload) }))].slice(-3));
    }
  }, [events, client]);

  useEffect(() => {
    if (toasts.length === 0) return;
    const timer = setTimeout(() => setToasts((current) => current.slice(1)), TOAST_MS);
    return () => clearTimeout(timer);
  }, [toasts]);

  if (toasts.length === 0) return null;
  return (
    <div className="fixed bottom-4 right-4 z-50 space-y-2" aria-live="polite">
      {toasts.map((toast) => (
        <div key={toast.id} role="status" className="flex items-center gap-3 rounded-card border border-approval/40 bg-surface px-4 py-3 shadow-lg">
          <Hand className="h-4 w-4 text-approval" aria-hidden="true" />
          <p className="text-sm text-text">
            Approval needed: <span className="font-mono">{toast.tool}</span>
          </p>
          <Link to="/approvals" className="text-sm font-medium text-accent underline-offset-4 hover:underline">
            Review
          </Link>
          <button
            type="button"
            aria-label="Dismiss"
            className="text-muted hover:text-text"
            onClick={() => setToasts((current) => current.filter((item) => item.id !== toast.id))}
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
      ))}
    </div>
  );
}
