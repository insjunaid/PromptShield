import { motion, useReducedMotion } from "framer-motion";
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  CircleDashed,
  Loader2,
  MessageSquare,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  XCircle,
} from "lucide-react";
import { type ReactNode, useEffect, useRef } from "react";
import { Link } from "react-router";

import type { LabJob } from "@/api/types";
import { DecisionChip } from "@/components/DecisionChip";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/cn";
import { formatMs } from "@/lib/feed";
import { describeCapture, isActive, runVerdict, type TimelineItem, type Tone } from "@/lib/lab";

function clip(value: string, max = 280): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function StepBody({ item }: { item: TimelineItem }) {
  switch (item.kind) {
    case "thought":
      return (
        <Step icon={MessageSquare} label="Agent">
          <p className="whitespace-pre-wrap text-text">{clip(item.text)}</p>
        </Step>
      );
    case "call":
      return (
        <Step icon={Wrench} label="Tool call">
          <p className="font-mono text-xs text-text">{item.tool}</p>
          <p className="mt-0.5 break-all font-mono text-[11px] text-muted">{clip(item.args, 200)}</p>
        </Step>
      );
    case "result":
      return (
        <Step icon={Bot} label={`Result · ${item.tool}`}>
          {item.marked && (
            <p className="mb-1 text-[11px] text-accent">
              The AI got this wrapped as untrusted data, with ^ between words. Shown here without the marks.
            </p>
          )}
          <p className="whitespace-pre-wrap break-words text-xs text-muted">{clip(item.text)}</p>
        </Step>
      );
    case "check": {
      const verdict = item.verdict;
      const acted = verdict.decision !== "ALLOW";
      return (
        <Step icon={acted ? ShieldAlert : ShieldCheck} label={item.stage === "action" ? "PromptShield · action check" : "PromptShield · content scan"} accent>
          <div className="flex flex-wrap items-center gap-2">
            <DecisionChip decision={verdict.decision} />
            <span className="font-mono text-[11px] text-muted">{item.tool}</span>
            <span className="text-[11px] text-muted tabular">{formatMs(verdict.total_latency_ms ?? 0)}</span>
          </div>
          {acted && verdict.reasons?.[0] && <p className="mt-1 text-xs text-text">{verdict.reasons[0]}</p>}
        </Step>
      );
    }
    case "alert":
      return (
        <Step icon={AlertTriangle} label={item.title} accent>
          <p className="text-xs text-text">{item.detail}</p>
        </Step>
      );
  }
}

function Step({
  icon: Icon,
  label,
  accent = false,
  children,
}: {
  icon: typeof Bot;
  label: string;
  accent?: boolean;
  children: ReactNode;
}) {
  return (
    <div className={cn("flex gap-3 rounded-chip px-3 py-2", accent && "bg-accent/5")}>
      <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", accent ? "text-accent" : "text-muted")} aria-hidden="true" />
      <div className="min-w-0 flex-1 text-sm">
        <p className="mb-0.5 text-[11px] font-medium uppercase tracking-wide text-muted">{label}</p>
        {children}
      </div>
    </div>
  );
}

function Timeline({ items, waiting }: { items: TimelineItem[]; waiting: boolean }) {
  const end = useRef<HTMLDivElement>(null);
  const reduce = useReducedMotion();

  // Follow the run as it streams, like a terminal. scrollIntoView is missing in jsdom.
  useEffect(() => {
    end.current?.scrollIntoView?.({ block: "nearest", behavior: reduce ? "auto" : "smooth" });
  }, [items.length, reduce]);

  if (items.length === 0) {
    return (
      <p className="flex items-center gap-2 px-3 py-8 text-sm text-muted">
        {waiting ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <CircleDashed className="h-4 w-4" aria-hidden="true" />}
        {waiting ? "Waiting for the agent's first step…" : "No steps recorded for this run."}
      </p>
    );
  }
  return (
    <>
    <ol className="space-y-1" aria-label="Agent steps">
      {items.map((item) => (
        <motion.li key={item.id} initial={reduce ? false : { opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.18 }}>
          <StepBody item={item} />
        </motion.li>
      ))}
    </ol>
    <div ref={end} />
    </>
  );
}

function SinkPanel({ job }: { job: LabJob | undefined }) {
  const done = job !== undefined && !isActive(job);
  const captured = job?.captured ?? [];
  if (!done) {
    return (
      <div className="flex items-center gap-2 rounded-chip border border-border bg-surface-2 px-3 py-2 text-sm text-muted">
        <Radio className="h-4 w-4" aria-hidden="true" />
        Attacker sink: watching…
      </div>
    );
  }
  if (captured.length === 0) {
    return (
      <div className="flex items-center gap-2 rounded-chip border border-allow/30 bg-allow/10 px-3 py-2 text-sm text-allow">
        <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
        Attacker sink: nothing received
      </div>
    );
  }
  return (
    <div className="rounded-chip border border-block/40 bg-block/10 px-3 py-2 text-sm text-block" role="status">
      <p className="flex items-center gap-2 font-medium">
        <XCircle className="h-4 w-4" aria-hidden="true" />
        Attacker sink received {captured.length === 1 ? "1 request" : `${captured.length} requests`}
      </p>
      <ul className="mt-1 space-y-0.5">
        {captured.slice(0, 3).map((capture) => (
          <li key={capture.id} className="break-all font-mono text-[11px]">
            {describeCapture(capture)}
          </li>
        ))}
      </ul>
    </div>
  );
}

const TONE_STYLE: Record<Tone, string> = {
  bad: "border-block/40 bg-block/10 text-block",
  good: "border-allow/40 bg-allow/10 text-allow",
  neutral: "border-border bg-surface-2 text-text",
};

const TONE_ICON: Record<Tone, typeof Bot> = { bad: XCircle, good: CheckCircle2, neutral: CircleDashed };

function VerdictBanner({ job }: { job: LabJob | undefined }) {
  const verdict = runVerdict(job);
  if (verdict === null) return null;
  const Icon = TONE_ICON[verdict.tone];
  return (
    <div className={cn("flex items-start gap-3 rounded-chip border px-3 py-2.5", TONE_STYLE[verdict.tone])} role="status">
      <Icon className="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />
      <div className="min-w-0">
        <p className="text-sm font-semibold">{verdict.title}</p>
        <p className="text-xs opacity-90">{verdict.detail}</p>
      </div>
    </div>
  );
}

function statusLabel(job: LabJob | undefined): string {
  if (job === undefined) return "Starting";
  if (job.status === "queued") return "Queued";
  if (job.status === "running") return "Running";
  if (job.status === "failed") return "Failed";
  return job.outcome ? `Done · ${job.outcome.steps} steps · ${formatMs(job.outcome.latency_ms)}` : "Done";
}

export function RunPanel({
  title,
  shield,
  job,
  items,
}: {
  title: string;
  shield: boolean;
  job: LabJob | undefined;
  items: TimelineItem[];
}) {
  const active = isActive(job);
  return (
    <Card className={cn("flex min-w-0 flex-col", shield && "border-accent/40")} aria-label={title} role="region">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-text">
          {shield ? <ShieldCheck className="h-4 w-4 text-accent" aria-hidden="true" /> : <ShieldAlert className="h-4 w-4 text-muted" aria-hidden="true" />}
          {title}
        </h2>
        <span className="flex items-center gap-3 text-xs text-muted tabular">
          <span className="flex items-center gap-1.5">
            {active && <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />}
            {statusLabel(job)}
          </span>
          {job && !active && (
            <Link className="font-medium text-accent underline-offset-4 hover:underline" to={`/sessions/${job.session_id}`}>
              Open replay
            </Link>
          )}
        </span>
      </div>
      <div className="h-[420px] overflow-y-auto p-2">
        <Timeline items={items} waiting={active} />
      </div>
      <div className="space-y-2 border-t border-border p-3">
        <SinkPanel job={job} />
        <VerdictBanner job={job} />
      </div>
    </Card>
  );
}
