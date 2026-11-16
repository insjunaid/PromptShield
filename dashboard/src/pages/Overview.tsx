import { useQuery } from "@tanstack/react-query";
import { Activity } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router";

import { fetchStats } from "@/api/client";
import type { StatsSnapshot } from "@/api/types";
import { EmptyState } from "@/components/EmptyState";
import { DetailDrawer } from "@/components/overview/DetailDrawer";
import { KpiCard } from "@/components/overview/KpiCard";
import { CanaryCard, LayerChart, TopRules } from "@/components/overview/SidePanels";
import { ThreatFeed } from "@/components/overview/ThreatFeed";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { feedItems, formatMs, type VerdictEvent } from "@/lib/feed";
import { useLiveStore } from "@/store/live";
import { useUiStore } from "@/store/ui";

export const STATS_REFRESH_MS = 5_000;

function series(stats: StatsSnapshot | undefined, pick: (b: NonNullable<StatsSnapshot["series"]>[number]) => number): number[] {
  return (stats?.series ?? []).map(pick);
}

/** Ids that arrived after the page opened, so only those animate. */
function useFreshIds(events: VerdictEvent[]): Set<string> {
  const initial = useRef<Set<string> | null>(null);
  if (initial.current === null) initial.current = new Set(events.map((event) => event.id));
  const known = initial.current;
  return useMemo(() => new Set(events.filter((event) => !known.has(event.id)).map((event) => event.id)), [events, known]);
}

export function OverviewPage() {
  const window = useUiStore((state) => state.window);
  const events = useLiveStore((state) => state.events);
  const [now, setNow] = useState(() => new Date());
  const [open, setOpen] = useState<VerdictEvent | null>(null);
  const stats = useQuery({
    queryKey: ["stats", window],
    queryFn: () => fetchStats(window),
    refetchInterval: STATS_REFRESH_MS,
  });

  // The window slides with time, so old rows leave the feed without a reload.
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 30_000);
    return () => clearInterval(timer);
  }, []);

  const feed = useMemo(() => feedItems(events, window, now), [events, window, now]);
  const fresh = useFreshIds(feed);
  const data = stats.data;
  const loading = stats.isPending;

  if (!loading && feed.length === 0 && (data?.scans ?? 0) === 0) {
    return (
      <EmptyState icon={Activity} title="No traffic yet.">
        Run a scenario in the{" "}
        <Link className="text-accent underline-offset-4 hover:underline" to="/lab">
          Red-Team Lab
        </Link>
        .
      </EmptyState>
    );
  }

  return (
    <div className="space-y-6">
      {stats.isError && (
        <div className="flex items-center justify-between rounded-card border border-sanitize/30 bg-sanitize/10 px-4 py-3 text-sm text-sanitize" role="alert">
          Couldn't load the numbers for this window.
          <button type="button" className="font-medium underline-offset-4 hover:underline" onClick={() => void stats.refetch()}>
            Retry
          </button>
        </div>
      )}
      <section className="grid grid-cols-2 gap-4 lg:grid-cols-5" aria-label="Key numbers">
        <KpiCard label="Tool calls scanned" value={String(data?.scans ?? 0)} series={series(data, (b) => b.scans ?? 0)} loading={loading} />
        <KpiCard label="Attacks blocked" value={String(data?.blocked ?? 0)} series={series(data, (b) => b.blocked ?? 0)} tone="block" loading={loading} />
        <KpiCard label="Sanitized" value={String(data?.sanitized ?? 0)} series={series(data, (b) => b.sanitized ?? 0)} tone="sanitize" loading={loading} />
        <KpiCard label="Pending approvals" value={String(data?.approvals_pending ?? 0)} series={[]} tone="approval" loading={loading} />
        <KpiCard label="p95 added latency" value={formatMs(data?.p95_ms ?? 0)} series={series(data, (b) => b.p95_ms ?? 0)} loading={loading} />
      </section>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <Card className="xl:col-span-7">
          <CardHeader>
            <CardTitle>Live threat feed</CardTitle>
            <span className="text-xs text-muted tabular">{feed.length} in window</span>
          </CardHeader>
          <div className="p-2">
            {feed.length === 0 ? (
              <p className="px-3 py-8 text-sm text-muted">Nothing scanned in this window yet.</p>
            ) : (
              <ThreatFeed events={feed} freshIds={fresh} onOpen={setOpen} />
            )}
          </div>
        </Card>
        <div className="space-y-6 xl:col-span-5">
          <CanaryCard tripped={data?.canaries_tripped ?? 0} />
          <LayerChart counts={data?.findings_by_layer ?? {}} />
          <TopRules rules={data?.top_rules ?? {}} />
        </div>
      </div>

      <DetailDrawer event={open} onClose={() => setOpen(null)} />
    </div>
  );
}
