import type { LabScenario } from "@/api/types";
import { cn } from "@/lib/cn";
import { groupScenarios } from "@/lib/lab";

function KindBadge({ attack }: { attack: boolean }) {
  return (
    <span
      className={cn(
        "rounded-chip px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        attack ? "bg-block/10 text-block" : "bg-allow/10 text-allow",
      )}
    >
      {attack ? "Attack" : "Benign"}
    </span>
  );
}

export function ScenarioPicker({
  scenarios,
  selected,
  disabled,
  onSelect,
}: {
  scenarios: LabScenario[];
  selected: string | null;
  disabled: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="space-y-4">
      {groupScenarios(scenarios).map((group) => (
        <section key={group.category} aria-label={group.label}>
          <h3 className="mb-2 text-[11px] font-medium uppercase tracking-wide text-muted">{group.label}</h3>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
            {group.scenarios.map((scenario) => {
              const active = scenario.id === selected;
              return (
                <button
                  key={scenario.id}
                  type="button"
                  aria-pressed={active}
                  disabled={disabled}
                  onClick={() => onSelect(scenario.id)}
                  className={cn(
                    "flex flex-col items-start gap-1.5 rounded-card border px-3 py-2.5 text-left transition-colors",
                    "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:opacity-60",
                    active ? "border-accent bg-accent/10" : "border-border bg-surface hover:bg-surface-2",
                  )}
                >
                  <span className="flex w-full items-center justify-between gap-2">
                    <span className="font-mono text-xs text-muted">{scenario.id}</span>
                    <KindBadge attack={scenario.attack} />
                  </span>
                  <span className="text-sm text-text">{scenario.name}</span>
                </button>
              );
            })}
          </div>
        </section>
      ))}
    </div>
  );
}
