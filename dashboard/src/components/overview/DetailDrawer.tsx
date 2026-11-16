import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { Link } from "react-router";

import { DecisionChip, SeverityChip } from "@/components/DecisionChip";
import { eventTool, formatMs, formatTime, type VerdictEvent } from "@/lib/feed";

/** One verdict, explained: decision, reasons, which layers ran, and every finding. */
export function DetailDrawer({ event, onClose }: { event: VerdictEvent | null; onClose: () => void }) {
  return (
    <Dialog.Root open={event !== null} onOpenChange={(open) => !open && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/40" />
        <Dialog.Content className="fixed inset-y-0 right-0 w-[min(560px,100vw)] overflow-y-auto border-l border-border bg-surface p-6 shadow-xl focus:outline-none">
          {event !== null && <Detail event={event} />}
          <Dialog.Close
            className="absolute right-4 top-4 rounded-chip p-1 text-muted hover:bg-surface-2 hover:text-text"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </Dialog.Close>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function Detail({ event }: { event: VerdictEvent }) {
  const { verdict } = event;
  const findings = verdict.findings ?? [];
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Dialog.Title className="text-[22px] font-semibold">Verdict</Dialog.Title>
        <Dialog.Description className="text-sm text-muted">
          {formatTime(event.ts)} · <span className="font-mono">{eventTool(event)}</span>
        </Dialog.Description>
        <div className="flex items-center gap-3">
          <DecisionChip decision={verdict.decision} />
          <span className="text-sm text-muted tabular">risk {verdict.risk_score.toFixed(2)}</span>
          <span className="text-sm text-muted tabular">{formatMs(verdict.total_latency_ms ?? 0)}</span>
        </div>
      </div>

      <section className="space-y-2">
        <h3 className="text-xs font-medium uppercase tracking-wide text-muted">Why</h3>
        <ul className="list-disc space-y-1 pl-5 text-sm">
          {(verdict.reasons ?? []).map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      </section>

      <section className="space-y-2">
        <h3 className="text-xs font-medium uppercase tracking-wide text-muted">Layers</h3>
        <div className="flex flex-wrap gap-2">
          {Object.entries(verdict.layers_run ?? {}).map(([layer, status]) => (
            <span key={layer} className="rounded-chip bg-surface-2 px-2 py-1 font-mono text-xs">
              {layer} <span className="text-muted">{status}</span>
            </span>
          ))}
        </div>
      </section>

      <section className="space-y-2">
        <h3 className="text-xs font-medium uppercase tracking-wide text-muted">Findings ({findings.length})</h3>
        {findings.length === 0 ? (
          <p className="text-sm text-muted">No findings.</p>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="text-xs text-muted">
              <tr>
                <th className="py-1 text-left font-medium">Rule</th>
                <th className="px-3 py-1 text-left font-medium">Severity</th>
                <th className="py-1 pl-3 text-right font-medium">Score</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding, index) => (
                <tr key={`${finding.rule_id}-${index}`} className="border-t border-border align-top">
                  <td className="py-2 pr-2">
                    <div className="font-mono text-xs">{finding.rule_id}</div>
                    <div className="mt-1 line-clamp-2 font-mono text-[11px] text-muted">{finding.evidence}</div>
                  </td>
                  <td className="px-3 py-2 align-top">
                    <SeverityChip severity={finding.severity} />
                  </td>
                  <td className="py-2 pl-3 text-right align-top tabular">{finding.score.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {event.session_id && (
        <Link className="inline-block text-sm text-accent underline-offset-4 hover:underline" to={`/sessions/${event.session_id}`}>
          Open the session replay
        </Link>
      )}
    </div>
  );
}
