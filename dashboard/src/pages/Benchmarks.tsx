import { useQuery } from "@tanstack/react-query";
import { BarChart3 } from "lucide-react";
import type { ReactNode } from "react";
import { Bar, BarChart, LabelList, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { fetchReport, fetchReports } from "@/api/client";
import type { LabReport, ReportSummary } from "@/api/types";
import { EmptyState } from "@/components/EmptyState";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { categoryLabel } from "@/lib/lab";
import { type CategoryRow, categoryRows, fraction, percent, pickPair } from "@/lib/admin";

function Provenance({ report, label }: { report: ReportSummary; label: string }) {
  return (
    <li>
      {label}: generated from <span className="font-mono text-text">eval/reports/{report.id}.json</span>
      {report.date && ` at ${report.date}`}
      {report.git && <> · git <span className="font-mono">{report.git}</span></>}
      {report.repeats && ` · ${report.repeats} repeats`}
    </li>
  );
}

function Headline({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <Card className="p-4">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-text tabular">{value}</p>
      <p className="mt-1 text-xs text-muted">{detail}</p>
    </Card>
  );
}

function seconds(value: number | undefined): string {
  return value === undefined ? "—" : `${Math.round(value)} s`;
}

function CategoryChart({ rows }: { rows: CategoryRow[] }) {
  const data = rows.map((row) => ({ ...row, name: categoryLabel(row.category) }));
  return (
    <div className="h-[420px]" role="img" aria-label="Attack success by category, without and with PromptShield. The table below has the same numbers.">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 24 }} barGap={2} barCategoryGap={10}>
          <XAxis type="number" domain={[0, 100]} unit="%" tick={{ fill: "var(--text-muted)", fontSize: 11 }} stroke="var(--border)" />
          <YAxis type="category" dataKey="name" width={124} tick={{ fill: "var(--text-muted)", fontSize: 11 }} stroke="var(--border)" />
          <Tooltip
            cursor={{ fill: "var(--surface-2)" }}
            contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 8, color: "var(--text)", fontSize: 12 }}
            formatter={(value, name, item) => {
              const row = item.payload as CategoryRow;
              const label = name === "Without PromptShield" ? row.offLabel : row.onLabel;
              return [value === null ? "no runs" : `${String(value)}% (${label})`, name];
            }}
          />
          <Legend wrapperStyle={{ fontSize: 12 }} formatter={(value) => <span style={{ color: "var(--text-muted)" }}>{value}</span>} />
          <Bar dataKey="off" name="Without PromptShield" fill="var(--series-1)" barSize={8} radius={[0, 4, 4, 0]} isAnimationActive={false} />
          <Bar dataKey="on" name="With PromptShield" fill="var(--series-2)" barSize={8} minPointSize={2} radius={[0, 4, 4, 0]} isAnimationActive={false}>
            {/* Labelled, because the shield-on bars are often 0% and would otherwise draw as nothing. */}
            <LabelList dataKey="on" position="right" formatter={(value) => (value === null || value === undefined ? "no runs" : `${String(value)}%`)} style={{ fill: "var(--text-muted)", fontSize: 10 }} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function CategoryTable({ rows }: { rows: CategoryRow[] }) {
  return (
    <table className="w-full text-left text-sm">
      <thead className="text-xs text-muted">
        <tr>
          <th className="py-1 pr-3 font-medium">Category</th>
          <th className="py-1 pr-3 text-right font-medium">Without PromptShield</th>
          <th className="py-1 text-right font-medium">With PromptShield</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.category} className="border-t border-border">
            <td className="py-1.5 pr-3 text-text">{categoryLabel(row.category)}</td>
            <td className="py-1.5 pr-3 text-right tabular text-text">{row.off === null ? "—" : `${row.off}% (${row.offLabel})`}</td>
            <td className="py-1.5 text-right tabular text-text">{row.on === null ? "—" : `${row.on}% (${row.onLabel})`}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Later({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted">{children}</p>
      </CardContent>
    </Card>
  );
}

export function BenchmarksPage() {
  const reports = useQuery({ queryKey: ["reports"], queryFn: fetchReports });
  const pair = pickPair(reports.data ?? []);
  const off = useQuery({ queryKey: ["report", pair.off?.id], queryFn: () => fetchReport(pair.off?.id ?? ""), enabled: pair.off !== null });
  const on = useQuery({ queryKey: ["report", pair.on?.id], queryFn: () => fetchReport(pair.on?.id ?? ""), enabled: pair.on !== null });

  if (reports.isPending || (pair.off && off.isPending) || (pair.on && on.isPending)) {
    return (
      <div className="space-y-4" aria-label="Loading benchmarks">
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {Array.from({ length: 4 }, (_, index) => (
            <div key={index} className="h-28 animate-pulse rounded-card bg-surface-2" />
          ))}
        </div>
        <div className="h-96 animate-pulse rounded-card bg-surface-2" />
      </div>
    );
  }
  if (reports.isError || off.isError || on.isError) {
    return (
      <EmptyState icon={BarChart3} title="Couldn't load the reports.">
        <button type="button" className="text-accent underline-offset-4 hover:underline" onClick={() => void reports.refetch()}>
          Retry
        </button>
      </EmptyState>
    );
  }
  if (!pair.off && !pair.on) {
    return (
      <EmptyState icon={BarChart3} title="No lab reports yet.">
        Run <span className="font-mono">uv run python -m lab.run</span> and <span className="font-mono">eval.report</span> to write one to eval/reports.
      </EmptyState>
    );
  }

  const before: LabReport | undefined = off.data;
  const after: LabReport | undefined = on.data;
  const rows = categoryRows(before, after);
  return (
    <div className="space-y-6">
      <section className="grid grid-cols-2 gap-4 lg:grid-cols-4" aria-label="Headline numbers">
        <Headline
          label="Attack success rate"
          value={`${percent(before?.summary.attack_success)} → ${percent(after?.summary.attack_success)}`}
          detail={`without → with the shield (${fraction(before?.summary.attack_success)} → ${fraction(after?.summary.attack_success)} runs)`}
        />
        <Headline
          label="Benign tasks completed"
          value={percent(after?.summary.utility_benign)}
          detail={`with the shield (${fraction(after?.summary.utility_benign)}); without: ${percent(before?.summary.utility_benign)}`}
        />
        <Headline
          label="Task done under attack"
          value={`${percent(before?.summary.utility_under_attack)} → ${percent(after?.summary.utility_under_attack)}`}
          detail="without → with: a block can also stop the agent finishing"
        />
        <Headline
          label="Run time per scenario"
          value={`${seconds(after?.summary.p50_seconds)} / ${seconds(after?.summary.p95_seconds)}`}
          detail="p50 / p95 with the shield, whole agent run on CPU (not shield latency)"
        />
      </section>

      <Card>
        <CardHeader>
          <CardTitle>Attack success by category</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <CategoryChart rows={rows} />
          <details>
            <summary className="cursor-pointer text-xs text-muted">Show as a table</summary>
            <div className="mt-2">
              <CategoryTable rows={rows} />
            </div>
          </details>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Later title="False-positive rate and datasets">
          Precision, recall and F1 on public datasets, and the false-positive rate on benign text, come from the Phase 7
          benchmark runs. Nothing is shown until those reports exist.
        </Later>
        <Later title="Layer ablation">
          Which layer contributes what is measured in Phase 7 by switching layers off one at a time.
        </Later>
      </div>

      <ul className="space-y-0.5 text-xs text-muted" aria-label="Provenance">
        {pair.off && <Provenance report={pair.off} label="Without the shield" />}
        {pair.on && <Provenance report={pair.on} label="With the shield" />}
      </ul>
    </div>
  );
}
