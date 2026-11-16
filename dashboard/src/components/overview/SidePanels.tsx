import { ShieldAlert, ShieldCheck } from "lucide-react";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const LAYER_NAMES: Record<string, string> = {
  L0: "L0 Normalize",
  L1: "L1 Classifier",
  L2: "L2 Hidden",
  L3: "L3 Judge",
  L4: "L4 Action",
  CANARY: "Canary",
  REGISTRY: "Registry",
};

export function LayerChart({ counts }: { counts: Record<string, number> }) {
  const data = Object.entries(counts).map(([layer, count]) => ({ layer: LAYER_NAMES[layer] ?? layer, count }));
  return (
    <Card>
      <CardHeader>
        <CardTitle>Detections by layer</CardTitle>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <p className="text-sm text-muted">No detections in this window.</p>
        ) : (
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16 }}>
                <XAxis type="number" allowDecimals={false} tick={{ fill: "var(--text-muted)", fontSize: 11 }} stroke="var(--border)" />
                <YAxis type="category" dataKey="layer" width={96} tick={{ fill: "var(--text-muted)", fontSize: 11 }} stroke="var(--border)" />
                <Tooltip
                  cursor={{ fill: "var(--surface-2)" }}
                  contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 6 }}
                />
                <Bar dataKey="count" fill="var(--accent)" radius={[0, 4, 4, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function TopRules({ rules }: { rules: Record<string, number> }) {
  const entries = Object.entries(rules);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Top rules</CardTitle>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <p className="text-sm text-muted">No rules fired in this window.</p>
        ) : (
          <ol className="space-y-2">
            {entries.map(([rule, count]) => (
              <li key={rule} className="flex items-center justify-between gap-3">
                <span className="truncate font-mono text-xs">{rule}</span>
                <span className="text-sm text-muted tabular">{count}</span>
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}

/** The smoke alarm: a canary leaving means an exfiltration attempt was caught. */
export function CanaryCard({ tripped }: { tripped: number }) {
  const safe = tripped === 0;
  const Icon = safe ? ShieldCheck : ShieldAlert;
  return (
    <Card className={safe ? "" : "border-block/50 bg-block/10"}>
      <CardContent className="flex items-start gap-3">
        <Icon className={safe ? "h-5 w-5 text-allow" : "h-5 w-5 text-block"} aria-hidden="true" />
        <div>
          <p className={safe ? "text-sm font-semibold text-allow" : "text-sm font-semibold text-block"}>
            {safe ? "All canaries safe" : "Exfiltration attempt stopped"}
          </p>
          <p className="mt-1 text-xs text-muted">
            {safe
              ? "No planted secret has tried to leave in this window."
              : `A planted secret tried to leave ${tripped} ${tripped === 1 ? "time" : "times"} and was blocked.`}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
