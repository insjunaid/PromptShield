import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  Bot,
  ChevronDown,
  CirclePlay,
  CircleStop,
  Hand,
  History,
  MessageSquare,
  SearchX,
  ShieldAlert,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";

import { ApiError, fetchReplay } from "@/api/client";
import type { SessionReplay, SessionSummary } from "@/api/types";
import { DecisionChip, SeverityChip } from "@/components/DecisionChip";
import { EmptyState } from "@/components/EmptyState";
import { VerdictDetail } from "@/components/replay/VerdictDetail";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/cn";
import { formatTime } from "@/lib/feed";
import { readableResult } from "@/lib/lab";
import { type ReplayStep, replaySteps, sessionEnded, type StepKind, stepText } from "@/lib/replay";

export const LIVE_REFRESH_MS = 3_000;

const ICON: Record<StepKind, typeof Bot> = {
  start: CirclePlay,
  end: CircleStop,
  thought: MessageSquare,
  call: Wrench,
  check: ShieldCheck,
  result: Bot,
  alert: AlertTriangle,
  approval: Hand,
};

function Outcome({ session }: { session: SessionSummary }) {
  const run = session.lab_run;
  if (!run) return null;
  const text = !run.attack
    ? run.utility_ok === false
      ? "Benign task not completed"
      : "Benign task"
    : run.attack_succeeded === true
      ? "Attack succeeded"
      : run.attack_succeeded === false && (run.blocked_by ?? []).length > 0
        ? "Attack blocked"
        : run.attack_succeeded === false
          ? "Attack didn't land"
          : "No result";
  const tone = text === "Attack succeeded" || text.endsWith("not completed") ? "bg-block/15 text-block" : text === "Attack blocked" ? "bg-allow/15 text-allow" : "bg-surface-2 text-text";
  return <span className={cn("rounded-chip px-2 py-0.5 text-xs font-medium", tone)}>{`${run.scenario_id} · ${text}`}</span>;
}

function Header({ replay }: { replay: SessionReplay }) {
  const session = replay.session;
  return (
    <Card>
      <CardContent className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-base font-semibold text-text">Session {session.id.slice(-6)}</h1>
          <span
            className={cn(
              "inline-flex items-center gap-1 rounded-chip px-2 py-0.5 text-xs font-medium",
              session.shield ? "bg-accent/15 text-accent" : "bg-surface-2 text-muted",
            )}
          >
            {session.shield ? <ShieldCheck className="h-3 w-3" aria-hidden="true" /> : <ShieldAlert className="h-3 w-3" aria-hidden="true" />}
            {session.shield ? "Shield on" : "Shield off"}
          </span>
          <Outcome session={session} />
          {session.max_severity && <SeverityChip severity={session.max_severity} />}
        </div>
        <p className="text-sm text-text">{session.user_task ?? <span className="text-muted">No task recorded (MCP clients don't send one).</span>}</p>
        <p className="text-xs text-muted tabular">
          Started {new Date(session.started).toLocaleString()} · {session.events} events · {session.findings} findings
          {Object.entries(session.decisions ?? {}).map(([decision, count]) => ` · ${count} ${decision.toLowerCase().replace("_", " ")}`)}
        </p>
        {replay.truncated && <p className="text-xs text-sanitize">Long session: only the newest {replay.events.length} events are shown.</p>}
      </CardContent>
    </Card>
  );
}

function StepBody({ step }: { step: ReplayStep }) {
  const verdict = step.event.verdict;
  if (step.kind === "check" && verdict) return <VerdictDetail verdict={verdict} />;
  const raw = stepText(step.event);
  if (!raw) return <p className="text-sm text-muted">Nothing more recorded for this step.</p>;
  const { text, marked } = step.kind === "result" ? readableResult(raw) : { text: raw, marked: false };
  return (
    <div className="space-y-1">
      {marked && <p className="text-[11px] text-accent">The AI got this wrapped as untrusted data, with ^ between words. Shown here without the marks.</p>}
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-chip bg-surface-2 p-3 font-mono text-xs text-text">{text}</pre>
    </div>
  );
}

function StepRow({ step }: { step: ReplayStep }) {
  const quiet = step.kind === "start" || step.kind === "end";
  const [open, setOpen] = useState(step.flagged);
  const Icon = step.kind === "check" && step.decision && step.decision !== "ALLOW" ? ShieldAlert : ICON[step.kind];
  const panel = `step-${step.id}`;
  if (quiet) {
    return (
      <li className="flex items-center gap-3 py-1 pl-1 text-xs text-muted">
        <Icon className="h-3.5 w-3.5" aria-hidden="true" />
        {step.title} · <span className="tabular">{formatTime(step.ts)}</span>
      </li>
    );
  }
  return (
    <li className={cn("rounded-card border bg-surface", step.flagged ? "border-sanitize/40" : "border-border")}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panel}
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-center gap-3 px-4 py-2.5 text-left focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
      >
        <Icon className={cn("h-4 w-4 shrink-0", step.flagged ? "text-sanitize" : "text-muted")} aria-hidden="true" />
        <span className="text-sm font-medium text-text">{step.title}</span>
        {step.tool && <span className="truncate font-mono text-xs text-muted">{step.tool}</span>}
        {step.decision && <DecisionChip decision={step.decision} />}
        <span className="ml-auto text-xs text-muted tabular">{formatTime(step.ts)}</span>
        <ChevronDown className={cn("h-4 w-4 text-muted transition-transform", open && "rotate-180")} aria-hidden="true" />
      </button>
      {open && (
        <div id={panel} className="border-t border-border px-4 py-3">
          <StepBody step={step} />
        </div>
      )}
    </li>
  );
}

export function ReplayPage() {
  const { id = "" } = useParams();
  const replay = useQuery({
    queryKey: ["replay", id],
    queryFn: () => fetchReplay(id),
    // A session still going keeps refreshing; a finished one is final.
    refetchInterval: (query) => (query.state.data && !sessionEnded(query.state.data.events) ? LIVE_REFRESH_MS : false),
    retry: (count, error) => !(error instanceof ApiError && error.status === 404) && count < 1,
  });

  if (replay.isPending) {
    return (
      <div className="space-y-3" aria-label="Loading session">
        <div className="h-24 animate-pulse rounded-card bg-surface-2" />
        {Array.from({ length: 4 }, (_, index) => (
          <div key={index} className="h-12 animate-pulse rounded-card bg-surface-2" />
        ))}
      </div>
    );
  }
  if (replay.isError) {
    const missing = replay.error instanceof ApiError && replay.error.status === 404;
    return (
      <EmptyState icon={missing ? SearchX : History} title={missing ? "Session not found." : "Couldn't load this session."}>
        {missing ? (
          <Link className="text-accent underline-offset-4 hover:underline" to="/">
            Back to Overview
          </Link>
        ) : (
          <button type="button" className="text-accent underline-offset-4 hover:underline" onClick={() => void replay.refetch()}>
            Retry
          </button>
        )}
      </EmptyState>
    );
  }

  const steps = replaySteps(replay.data.events);
  return (
    <div className="space-y-4">
      <Header replay={replay.data} />
      {steps.length === 0 ? (
        <EmptyState icon={History} title="No steps recorded yet." />
      ) : (
        <ol className="space-y-2" aria-label="Session timeline">
          {steps.map((step) => (
            <StepRow key={step.id} step={step} />
          ))}
        </ol>
      )}
    </div>
  );
}
