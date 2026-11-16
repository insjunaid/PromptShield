import { Check, ChevronRight, Copy, Eye, EyeOff } from "lucide-react";
import { useState } from "react";

import type { Finding, Verdict } from "@/api/types";
import { DecisionChip, SeverityChip } from "@/components/DecisionChip";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";
import { formatMs } from "@/lib/feed";
import { aiParts, humanText, legendFor, type NodeTone, pipelineNodes } from "@/lib/replay";

const TONE: Record<NodeTone, string> = {
  clear: "border-allow/40 bg-allow/10 text-allow",
  fired: "border-sanitize/50 bg-sanitize/15 text-sanitize",
  skipped: "border-border bg-surface-2 text-muted",
  error: "border-block/50 bg-block/15 text-block",
  absent: "border-dashed border-border text-muted",
};

const TONE_WORD: Record<NodeTone, string> = {
  clear: "clear",
  fired: "fired",
  skipped: "skipped",
  error: "error",
  absent: "not run",
};

/** L0 → L2 → L1 → Canary → L3 → Policy, each node coloured and labelled by what it did. */
export function PipelineDiagram({ verdict }: { verdict: Verdict }) {
  const nodes = pipelineNodes(verdict);
  return (
    <ol className="flex flex-wrap items-center gap-1.5" aria-label="Scan pipeline">
      {nodes.map((node) => (
        <li key={node.layer} className="flex items-center gap-1.5">
          <span className={cn("rounded-chip border px-2 py-1 text-[11px] leading-tight", TONE[node.tone])}>
            <span className="block font-medium">{node.label}</span>
            <span className="block opacity-90">
              {TONE_WORD[node.tone]}
              {node.findings > 0 && ` · ${node.findings}`}
              {node.ms !== null && ` · ${formatMs(node.ms)}`}
            </span>
          </span>
          <ChevronRight className="h-3 w-3 text-muted" aria-hidden="true" />
        </li>
      ))}
      <li className="flex items-center gap-1.5 rounded-chip border border-border bg-surface-2 px-2 py-1 text-[11px]">
        <span className="font-medium text-text">Policy</span>
        <DecisionChip decision={verdict.decision} />
        <span className="text-muted tabular">{formatMs(verdict.total_latency_ms ?? 0)}</span>
      </li>
    </ol>
  );
}

/** "What a human sees" next to "What the AI received", hidden text highlighted by origin. */
export function TwoPaneDiff({ verdict }: { verdict: Verdict }) {
  const segments = verdict.segments ?? [];
  const parts = aiParts(segments);
  const legend = legendFor(parts);
  const human = humanText(segments);
  return (
    <div className="space-y-2">
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <section aria-label="What a human sees" className="rounded-card border border-border bg-surface p-3">
          <h4 className="mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-muted">
            <Eye className="h-3.5 w-3.5" aria-hidden="true" /> What a human sees
          </h4>
          <p className="max-h-72 overflow-y-auto whitespace-pre-wrap text-sm leading-relaxed text-text">
            {human || <span className="text-muted">Nothing visible.</span>}
          </p>
        </section>
        <section aria-label="What the AI received" className="rounded-card border border-border bg-surface p-3">
          <h4 className="mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-muted">
            <EyeOff className="h-3.5 w-3.5" aria-hidden="true" /> What the AI received
          </h4>
          <div className="max-h-72 space-y-1 overflow-y-auto text-sm leading-relaxed text-text">
            {parts.map((part, index) =>
              part.hidden ? (
                <p key={index} className={cn("whitespace-pre-wrap rounded px-1.5 py-0.5", part.className)}>
                  <span className="mr-1.5 font-mono text-[10px] font-semibold uppercase">
                    [{part.label}
                    {part.detail ? `: ${part.detail}` : ""}]
                  </span>
                  {part.text}
                </p>
              ) : (
                <p key={index} className="whitespace-pre-wrap">
                  {part.text}
                </p>
              ),
            )}
          </div>
        </section>
      </div>
      {legend.length > 0 && (
        <ul className="flex flex-wrap gap-2 text-[11px]" aria-label="Legend">
          {legend.map((item) => (
            <li key={item.label} className={cn("rounded-chip px-2 py-0.5", item.className)}>
              {item.label}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function FindingsTable({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return <p className="text-sm text-muted">No findings.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-xs text-muted">
          <tr>
            <th className="py-1 pr-3 font-medium">Layer</th>
            <th className="py-1 pr-3 font-medium">Rule</th>
            <th className="py-1 pr-3 font-medium">Severity</th>
            <th className="py-1 pr-3 text-right font-medium">Score</th>
            <th className="py-1 pr-3 font-medium">Evidence</th>
            <th className="py-1 text-right font-medium">Latency</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding, index) => (
            <tr key={`${finding.rule_id}-${index}`} className="border-t border-border align-top">
              <td className="py-2 pr-3 font-mono text-xs">{finding.layer}</td>
              <td className="py-2 pr-3">
                <div className="font-mono text-xs text-text">{finding.rule_id}</div>
                <div className="text-xs text-muted">{finding.title}</div>
              </td>
              <td className="py-2 pr-3">
                <SeverityChip severity={finding.severity} />
              </td>
              <td className="py-2 pr-3 text-right tabular">{finding.score.toFixed(2)}</td>
              <td className="max-w-md py-2 pr-3">
                <div className="line-clamp-3 break-words font-mono text-[11px] text-muted">{finding.evidence}</div>
              </td>
              <td className="py-2 text-right text-xs text-muted tabular">{formatMs(finding.latency_ms)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function CopyJson({ value }: { value: unknown }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(value, null, 2));
      setState("copied");
    } catch {
      setState("failed"); // blocked clipboard (insecure context, permissions)
    }
    setTimeout(() => setState("idle"), 2000);
  };
  return (
    <Button size="sm" variant="outline" onClick={() => void copy()}>
      {state === "copied" ? <Check className="h-3.5 w-3.5" aria-hidden="true" /> : <Copy className="h-3.5 w-3.5" aria-hidden="true" />}
      {state === "copied" ? "Copied" : state === "failed" ? "Copy failed" : "Copy as JSON"}
    </Button>
  );
}

/** Everything about one verdict: pipeline, reasons, the diff when there is text, and findings. */
export function VerdictDetail({ verdict }: { verdict: Verdict }) {
  const hasText = (verdict.segments ?? []).length > 0;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PipelineDiagram verdict={verdict} />
        <CopyJson value={verdict} />
      </div>
      {(verdict.reasons ?? []).length > 0 && (
        <ul className="list-disc space-y-0.5 pl-5 text-sm text-text">
          {verdict.reasons?.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      )}
      {hasText && <TwoPaneDiff verdict={verdict} />}
      <FindingsTable findings={verdict.findings ?? []} />
    </div>
  );
}
