import { useMutation, useQuery } from "@tanstack/react-query";
import { FlaskConical, Play, RotateCcw } from "lucide-react";
import { useMemo, useState } from "react";

import { ApiError, fetchRun, fetchScenarios, resetLab, startPair } from "@/api/client";
import type { LabScenario, StartedRun } from "@/api/types";
import { EmptyState } from "@/components/EmptyState";
import { RunPanel } from "@/components/lab/RunPanel";
import { ScenarioPicker } from "@/components/lab/ScenarioPicker";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/cn";
import { categoryLabel, isActive, timelineItems } from "@/lib/lab";
import { useLiveStore } from "@/store/live";

export const RUN_POLL_MS = 1_500;

interface Pair {
  scenario: LabScenario;
  off: StartedRun;
  on: StartedRun;
}

type Notice = { tone: "error" | "info"; text: string };

/** Polls one run while it is queued or running; the timeline itself streams from the live store. */
function useRun(run: StartedRun | undefined) {
  return useQuery({
    queryKey: ["lab-run", run?.run_id],
    queryFn: () => fetchRun(run?.run_id ?? ""),
    enabled: run !== undefined,
    refetchInterval: (query) => (isActive(query.state.data) ? RUN_POLL_MS : false),
  });
}

function explain(error: unknown, action: "start" | "reset"): string {
  if (error instanceof ApiError && error.status === 401) {
    return "The API turned the request away (no admin token). Start the API before the dashboard, then try again.";
  }
  if (error instanceof ApiError && error.status === 409) return "A run is still going. Reset when it finishes.";
  const what = action === "start" ? "start the runs" : "reset the lab";
  return `Couldn't ${what}: ${error instanceof Error ? error.message : "unknown error"}.`;
}

export function LabPage() {
  const scenarios = useQuery({ queryKey: ["lab-scenarios"], queryFn: fetchScenarios, staleTime: Infinity });
  const events = useLiveStore((state) => state.events);
  const [selected, setSelected] = useState<string | null>(null);
  const [pair, setPair] = useState<Pair | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const off = useRun(pair?.off);
  const on = useRun(pair?.on);
  const busy = pair !== null && (isActive(off.data) || isActive(on.data));

  const start = useMutation({
    mutationFn: (scenario: LabScenario) => startPair(scenario.id).then((runs) => ({ scenario, runs })),
    onMutate: () => setNotice(null),
    onSuccess: ({ scenario, runs }) => {
      const [first, second] = runs;
      if (first === undefined || second === undefined) {
        setNotice({ tone: "error", text: "The API didn't return both runs." });
        return;
      }
      setPair({ scenario, off: first, on: second });
    },
    onError: (error) => setNotice({ tone: "error", text: explain(error, "start") }),
  });

  const reset = useMutation({
    mutationFn: resetLab,
    onMutate: () => setNotice(null),
    onSuccess: () => {
      setPair(null);
      setNotice({ tone: "info", text: "Lab reset. Run folders and the attacker sink log are cleared." });
    },
    onError: (error) => setNotice({ tone: "error", text: explain(error, "reset") }),
  });

  const offItems = useMemo(() => (pair ? timelineItems(events, pair.off.session_id) : []), [events, pair]);
  const onItems = useMemo(() => (pair ? timelineItems(events, pair.on.session_id) : []), [events, pair]);
  const choice = scenarios.data?.find((scenario) => scenario.id === selected) ?? null;

  if (scenarios.error instanceof ApiError && scenarios.error.status === 404) {
    // The installed package ships the shield without the lab (the API says so).
    return (
      <EmptyState icon={FlaskConical} title="The Red-Team Lab isn't installed here.">
        {scenarios.error.message}{" "}
        <a className="text-accent underline-offset-4 hover:underline" href="https://github.com/insjunaid/PromptShield">
          Get the repository
        </a>
      </EmptyState>
    );
  }

  if (scenarios.isError) {
    return (
      <EmptyState icon={FlaskConical} title="Couldn't load the scenarios.">
        Is the API running on 127.0.0.1:8000?{" "}
        <button type="button" className="text-accent underline-offset-4 hover:underline" onClick={() => void scenarios.refetch()}>
          Retry
        </button>
      </EmptyState>
    );
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardContent className="flex flex-wrap items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="text-[11px] font-medium uppercase tracking-wide text-muted">Scenario</p>
            <p className="text-sm text-text">
              {choice
                ? `${choice.id} · ${choice.name} · ${categoryLabel(choice.category)}`
                : "Pick one below, then run it without and with PromptShield, side by side."}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" onClick={() => reset.mutate()} disabled={busy || reset.isPending}>
              <RotateCcw className="h-4 w-4" aria-hidden="true" />
              Reset lab
            </Button>
            <Button
              variant="primary"
              onClick={() => choice && start.mutate(choice)}
              disabled={choice === null || busy || start.isPending}
            >
              <Play className="h-4 w-4" aria-hidden="true" />
              {busy ? "Running…" : "Run comparison"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {notice && (
        <div
          role={notice.tone === "error" ? "alert" : "status"}
          className={cn(
            "rounded-card border px-4 py-3 text-sm",
            notice.tone === "error" ? "border-block/30 bg-block/10 text-block" : "border-border bg-surface-2 text-text",
          )}
        >
          {notice.text}
        </div>
      )}

      {pair && (
        <section className="space-y-3" aria-label="Run comparison">
          <p className="text-xs text-muted">
            {pair.scenario.id} · {pair.scenario.name}. The runs go one after the other: shield off first, then on. Each
            starts from a fresh sandbox.
          </p>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <RunPanel title="Without PromptShield" shield={false} job={off.data} items={offItems} />
            <RunPanel title="With PromptShield" shield job={on.data} items={onItems} />
          </div>
        </section>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Scenarios</CardTitle>
          <span className="text-xs text-muted tabular">{scenarios.data?.length ?? 0} available</span>
        </CardHeader>
        <CardContent>
          {scenarios.isPending ? (
            <div className="grid grid-cols-2 gap-2 xl:grid-cols-4" aria-label="Loading scenarios">
              {Array.from({ length: 8 }, (_, index) => (
                <div key={index} className="h-16 animate-pulse rounded-card bg-surface-2" />
              ))}
            </div>
          ) : (
            <ScenarioPicker scenarios={scenarios.data} selected={selected} disabled={busy} onSelect={setSelected} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
