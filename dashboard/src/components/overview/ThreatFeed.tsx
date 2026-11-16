import { useVirtualizer } from "@tanstack/react-virtual";
import { motion } from "framer-motion";
import { useRef } from "react";

import { DecisionChip } from "@/components/DecisionChip";
import { eventTool, formatTime, layersFired, shortId, topReason, type VerdictEvent } from "@/lib/feed";

const ROW_HEIGHT = 52;

function LayerBadges({ layers }: { layers: string[] }) {
  if (layers.length === 0) return <span className="text-xs text-muted">—</span>;
  return (
    <span className="flex gap-1" aria-label={`Layers fired: ${layers.join(", ")}`}>
      {layers.map((layer) => (
        <span key={layer} className="rounded-[4px] bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-muted">
          {layer}
        </span>
      ))}
    </span>
  );
}

function Row({ event, fresh, onOpen }: { event: VerdictEvent; fresh: boolean; onOpen: () => void }) {
  const blocked = event.verdict.decision === "BLOCK";
  return (
    <motion.button
      type="button"
      onClick={onOpen}
      // Motion only for meaning: a fresh block slides in and pulses red once; nothing else moves.
      initial={fresh ? { opacity: 0, x: -8 } : false}
      animate={
        fresh && blocked
          ? { opacity: 1, x: 0, boxShadow: ["0 0 0 0 var(--critical-glow)", "0 0 0 6px rgba(0,0,0,0)"] }
          : { opacity: 1, x: 0 }
      }
      transition={{ duration: 0.6 }}
      className="grid h-[48px] w-full grid-cols-[88px_64px_minmax(0,1fr)_112px_minmax(0,2fr)_auto] items-center gap-3 rounded-chip px-3 text-left text-sm hover:bg-surface-2"
    >
      <span className="whitespace-nowrap font-mono text-xs text-muted tabular">{formatTime(event.ts)}</span>
      <span className="font-mono text-xs text-muted">{shortId(event.session_id)}</span>
      <span className="truncate font-mono text-xs">{eventTool(event)}</span>
      <DecisionChip decision={event.verdict.decision} />
      <span className="truncate text-muted">{topReason(event.verdict)}</span>
      <LayerBadges layers={layersFired(event.verdict)} />
    </motion.button>
  );
}

/**
 * Virtualized, so a busy session doesn't make the page slow or shift. Rows that arrive after the
 * page opened animate once; scrolling back to them later doesn't replay it.
 */
export function ThreatFeed({
  events,
  onOpen,
  freshIds,
}: {
  events: VerdictEvent[];
  onOpen: (event: VerdictEvent) => void;
  freshIds: Set<string>;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: events.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 8,
    initialRect: { width: 800, height: 560 },
  });
  return (
    <div ref={scrollRef} className="h-[560px] overflow-y-auto" role="list" aria-label="Live threat feed">
      <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
        {virtualizer.getVirtualItems().map((item) => {
          const event = events[item.index];
          if (event === undefined) return null;
          return (
            <div
              key={event.id}
              role="listitem"
              style={{ position: "absolute", top: 0, left: 0, right: 0, transform: `translateY(${item.start}px)` }}
            >
              <Row event={event} fresh={freshIds.has(event.id)} onOpen={() => onOpen(event)} />
            </div>
          );
        })}
      </div>
    </div>
  );
}
