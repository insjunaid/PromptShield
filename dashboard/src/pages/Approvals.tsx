import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import { ApiError, decideApproval, fetchApprovals } from "@/api/client";
import type { ApprovalView } from "@/api/types";
import { EmptyState } from "@/components/EmptyState";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { remainingShare, secondsLeft } from "@/lib/admin";

export const APPROVALS_REFRESH_MS = 5_000;

/** A clock that ticks once a second, for the countdowns. */
function useNow(): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  return now;
}

/** Time left until the call is denied automatically, as a ring and as text. */
export function CountdownRing({ share, seconds }: { share: number; seconds: number }) {
  const radius = 18;
  const circumference = 2 * Math.PI * radius;
  const urgent = seconds <= 15;
  return (
    <div className="relative h-12 w-12 shrink-0" role="timer" aria-label={`${seconds} seconds until it is denied`}>
      <svg viewBox="0 0 44 44" className="h-12 w-12 -rotate-90" aria-hidden="true">
        <circle cx="22" cy="22" r={radius} fill="none" strokeWidth="4" className="stroke-border" />
        <circle
          cx="22"
          cy="22"
          r={radius}
          fill="none"
          strokeWidth="4"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - share)}
          className={urgent ? "stroke-block" : "stroke-approval"}
        />
      </svg>
      <span className="absolute inset-0 flex items-center justify-center text-[11px] font-semibold text-text tabular">{seconds}s</span>
    </div>
  );
}

function ApprovalCard({ approval, now, first }: { approval: ApprovalView; now: number; first: boolean }) {
  const client = useQueryClient();
  const [problem, setProblem] = useState<string | null>(null);
  const decide = useMutation({
    mutationFn: (decision: "approve" | "deny") => decideApproval(approval.id ?? "", decision),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["approvals"] }),
    onError: (error) => {
      if (error instanceof ApiError && error.status === 409) setProblem("Already decided, or it timed out.");
      else if (error instanceof ApiError && error.status === 401) setProblem("The API turned the decision away (no admin token).");
      else setProblem("Couldn't send the decision. Try again.");
      void client.invalidateQueries({ queryKey: ["approvals"] });
    },
  });
  const call = approval.tool_call;
  const seconds = secondsLeft(approval.expires, now);
  return (
    <Card className="p-4" aria-label={`Approval for ${call.server}.${call.tool}`} role="region">
      <div className="flex items-start gap-4">
        <CountdownRing share={remainingShare(approval.created ?? approval.expires, approval.expires, now)} seconds={seconds} />
        <div className="min-w-0 flex-1 space-y-2">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-mono text-sm font-semibold text-text">
              {call.server}.{call.tool}
            </span>
            {approval.destination && (
              <span className="break-all text-sm text-muted">
                → <span className="font-mono text-text">{approval.destination}</span>
              </span>
            )}
          </div>
          <div>
            <p className="text-[11px] font-medium uppercase tracking-wide text-muted">Why it was held</p>
            <ul className="list-disc pl-5 text-sm text-text">
              {approval.reasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          </div>
          <div>
            <p className="text-[11px] font-medium uppercase tracking-wide text-muted">The user asked</p>
            <p className="text-sm text-text">{approval.user_task ?? <span className="text-muted">Not recorded (MCP clients don't send the task).</span>}</p>
          </div>
          <details>
            <summary className="cursor-pointer text-xs text-muted">Arguments (redacted)</summary>
            <pre className="mt-1 max-h-48 overflow-auto rounded-chip bg-surface-2 p-2 font-mono text-[11px] text-text">{JSON.stringify(call.args, null, 2)}</pre>
          </details>
          {problem && (
            <p className="text-sm text-block" role="alert">
              {problem}
            </p>
          )}
        </div>
        <div className="flex shrink-0 flex-col gap-2">
          {/* Deny has focus by default: pressing Enter by reflex must not let the call through. */}
          <Button variant="danger" autoFocus={first} disabled={decide.isPending} onClick={() => decide.mutate("deny")}>
            Deny
          </Button>
          <Button variant="outline" disabled={decide.isPending} onClick={() => decide.mutate("approve")}>
            Approve once
          </Button>
        </div>
      </div>
    </Card>
  );
}

export function ApprovalsPage() {
  const now = useNow();
  const approvals = useQuery({
    queryKey: ["approvals", "pending"],
    queryFn: () => fetchApprovals("pending"),
    refetchInterval: APPROVALS_REFRESH_MS,
  });

  if (approvals.isPending) {
    return (
      <div className="space-y-3" aria-label="Loading approvals">
        {Array.from({ length: 2 }, (_, index) => (
          <div key={index} className="h-40 animate-pulse rounded-card bg-surface-2" />
        ))}
      </div>
    );
  }
  if (approvals.isError) {
    return (
      <EmptyState icon={ShieldCheck} title="Couldn't load approvals.">
        <button type="button" className="text-accent underline-offset-4 hover:underline" onClick={() => void approvals.refetch()}>
          Retry
        </button>
      </EmptyState>
    );
  }
  const waiting = approvals.data.filter((item) => secondsLeft(item.expires, now) > 0);
  if (waiting.length === 0) {
    return (
      <EmptyState icon={ShieldCheck} title="No approvals waiting">
        Tool calls that need a human decision appear here. Unanswered ones are denied when time runs out.
      </EmptyState>
    );
  }
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">
        {waiting.length === 1 ? "1 call is" : `${waiting.length} calls are`} waiting. If nobody answers, the call is denied.
      </p>
      {waiting.map((approval, index) => (
        <ApprovalCard key={approval.id} approval={approval} now={now} first={index === 0} />
      ))}
    </div>
  );
}
