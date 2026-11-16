import { Area, AreaChart, ResponsiveContainer } from "recharts";

import { Card } from "@/components/ui/card";
import { cn } from "@/lib/cn";

export type KpiTone = "neutral" | "block" | "sanitize" | "approval";

const TONE: Record<KpiTone, { text: string; stroke: string }> = {
  neutral: { text: "text-text", stroke: "var(--accent)" },
  block: { text: "text-block", stroke: "var(--block)" },
  sanitize: { text: "text-sanitize", stroke: "var(--sanitize)" },
  approval: { text: "text-approval", stroke: "var(--approval)" },
};

export function KpiCard({
  label,
  value,
  series,
  tone = "neutral",
  loading = false,
}: {
  label: string;
  value: string;
  series: number[];
  tone?: KpiTone;
  loading?: boolean;
}) {
  const { text, stroke } = TONE[tone];
  const data = series.map((point, index) => ({ index, point }));
  return (
    <Card className="flex flex-col gap-2 p-4">
      <span className="text-xs font-medium text-muted">{label}</span>
      {loading ? (
        <span className="h-8 w-20 animate-pulse rounded-chip bg-surface-2" aria-label="Loading" />
      ) : (
        <span className={cn("text-[32px] font-semibold leading-none tabular", text)}>{value}</span>
      )}
      {/* Decorative: the number above carries the meaning. */}
      <div className="h-8" aria-hidden="true">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }} accessibilityLayer={false}>
            <Area
              type="monotone"
              dataKey="point"
              stroke={stroke}
              strokeWidth={1.5}
              fill={stroke}
              fillOpacity={0.12}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
