import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ScrollText } from "lucide-react";
import { useEffect, useState } from "react";

import { ApiError, fetchConfig, fetchPolicy, savePolicy, setPolicyMode } from "@/api/client";
import type { PolicyDocument, PolicyProblem } from "@/api/types";
import { EmptyState } from "@/components/EmptyState";
import { YamlEditor } from "@/components/policy/YamlEditor";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/cn";
import { setThreshold, type ThresholdKey } from "@/lib/admin";

type Notice = { tone: "error" | "info"; text: string; problems?: PolicyProblem[] };

function problemsOf(error: unknown): PolicyProblem[] {
  if (!(error instanceof ApiError)) return [];
  const problems = error.details.problems;
  return Array.isArray(problems) ? (problems as PolicyProblem[]) : [];
}

function explain(error: unknown): Notice {
  if (error instanceof ApiError && error.status === 401) {
    return { tone: "error", text: "The API turned the change away (no admin token). Start the API before the dashboard." };
  }
  const problems = problemsOf(error);
  if (problems.length > 0) return { tone: "error", text: "Not saved: the policy has problems.", problems };
  return { tone: "error", text: `Not saved: ${error instanceof Error ? error.message : "unknown error"}.` };
}

function thresholds(doc: PolicyDocument | undefined): { sanitize: number; block: number } {
  const parsed = (doc?.policy as { thresholds?: { sanitize?: number; block?: number } } | undefined)?.thresholds;
  return { sanitize: parsed?.sanitize ?? 0.35, block: parsed?.block ?? 0.75 };
}

function Slider({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) {
  const id = `slider-${label.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-sm">
        <label htmlFor={id} className="text-text">
          {label}
        </label>
        <span className="font-mono text-xs text-muted tabular">{value.toFixed(2)}</span>
      </div>
      <input id={id} type="range" min={0} max={1} step={0.05} value={value} onChange={(event) => onChange(Number(event.target.value))} className="w-full accent-[var(--accent)]" />
    </div>
  );
}

export function PolicyPage() {
  const client = useQueryClient();
  const policy = useQuery({ queryKey: ["policy"], queryFn: fetchPolicy, staleTime: Infinity });
  const config = useQuery({ queryKey: ["config"], queryFn: fetchConfig });
  const [text, setText] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const saved = policy.data?.yaml ?? "";
  const current = text ?? saved;
  const dirty = text !== null && text !== saved;

  // Sliders start from the saved policy, and moving one edits the YAML. Typing in the editor doesn't
  // move them; the YAML is what Save sends either way.
  const [levels, setLevels] = useState(() => thresholds(policy.data));
  useEffect(() => setLevels(thresholds(policy.data)), [policy.data]);

  const applied = (doc: PolicyDocument, message: string) => {
    client.setQueryData(["policy"], doc);
    void client.invalidateQueries({ queryKey: ["config"] });
    setText(null);
    setNotice({ tone: "info", text: message });
  };
  const save = useMutation({
    mutationFn: () => savePolicy(current),
    onMutate: () => setNotice(null),
    onSuccess: (doc) => applied(doc, "Saved and live: new scans use this policy now."),
    onError: (error) => setNotice(explain(error)),
  });
  const mode = useMutation({
    mutationFn: setPolicyMode,
    onMutate: () => setNotice(null),
    onSuccess: (doc, next) => applied(doc, next === "monitor" ? "Monitor mode: verdicts are recorded, nothing is blocked." : "Enforce mode: verdicts are applied."),
    onError: (error) => setNotice(explain(error)),
  });

  const slide = (key: ThresholdKey, value: number) => {
    const next = setThreshold(current, key, value);
    if (next === null) {
      setNotice({ tone: "error", text: `Couldn't find thresholds.${key} in the YAML. Edit it in the editor instead.` });
      return;
    }
    setLevels((old) => ({ ...old, [key]: value }));
    setText(next);
  };

  if (policy.isPending) return <div className="h-[560px] animate-pulse rounded-card bg-surface-2" aria-label="Loading policy" />;
  if (policy.isError) {
    return (
      <EmptyState icon={ScrollText} title="Couldn't load the policy.">
        <button type="button" className="text-accent underline-offset-4 hover:underline" onClick={() => void policy.refetch()}>
          Retry
        </button>
      </EmptyState>
    );
  }

  const activeMode = config.data?.mode ?? "enforce";
  const order = levels.sanitize < levels.block;
  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
      <div className="space-y-3 xl:col-span-8">
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted">
            <span className="font-mono text-text">{policy.data.file}</span> · saved as written, comments included
          </p>
          <div className="flex gap-2">
            <Button
              variant="ghost"
              size="sm"
              disabled={!dirty || save.isPending}
              onClick={() => {
                setText(null);
                setLevels(thresholds(policy.data));
              }}
            >
              Revert
            </Button>
            <Button variant="primary" size="sm" disabled={!dirty || save.isPending} onClick={() => save.mutate()}>
              {save.isPending ? "Saving…" : "Save"}
            </Button>
          </div>
        </div>
        <YamlEditor value={current} onChange={setText} label="Policy YAML" />
        {notice && (
          <div
            role={notice.tone === "error" ? "alert" : "status"}
            className={cn(
              "rounded-card border px-4 py-3 text-sm",
              notice.tone === "error" ? "border-block/30 bg-block/10 text-block" : "border-allow/30 bg-allow/10 text-allow",
            )}
          >
            <p>{notice.text}</p>
            {notice.problems && (
              <ul className="mt-1 space-y-0.5">
                {notice.problems.map((problem) => (
                  <li key={`${problem.where}-${problem.message}`}>
                    <span className="font-mono">{problem.where}</span>: {problem.message}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>

      <div className="space-y-6 xl:col-span-4">
        <Card>
          <CardHeader>
            <CardTitle>Mode</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex rounded-chip border border-border p-0.5" role="group" aria-label="Mode">
              {(["enforce", "monitor"] as const).map((item) => (
                <button
                  key={item}
                  type="button"
                  aria-pressed={activeMode === item}
                  disabled={mode.isPending || dirty}
                  onClick={() => activeMode !== item && mode.mutate(item)}
                  className={cn(
                    "flex-1 rounded-chip px-3 py-1.5 text-sm capitalize transition-colors disabled:opacity-60",
                    activeMode === item ? "bg-surface-2 font-medium text-text" : "text-muted hover:text-text",
                  )}
                >
                  {item}
                </button>
              ))}
            </div>
            <p className="text-xs text-muted">
              {dirty ? "Save or revert your edits first: switching mode saves the file." : "Monitor records what would happen and blocks nothing."}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Thresholds</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Slider label="Sanitize at risk" value={levels.sanitize} onChange={(value) => slide("sanitize", value)} />
            <Slider label="Block at risk" value={levels.block} onChange={(value) => slide("block", value)} />
            <p className={cn("text-xs", order ? "text-muted" : "text-block")}>
              {order ? "Sliders edit the YAML; Save makes them live." : "Sanitize must be below block, or the save is refused."}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>L3 judge</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1 text-sm">
            <p className="text-text">
              Judge: <span className="font-mono">{config.data?.judge_mode ?? "unknown"}</span>
              {config.data?.judge_model && <span className="text-muted"> · {config.data.judge_model}</span>}
            </p>
            <p className="text-xs text-muted">
              A startup setting, not part of the policy: set <span className="font-mono">PROMPTSHIELD_JUDGE_MODE</span> (off, uncertain, always) and restart the API.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
