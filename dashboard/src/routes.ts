import {
  Activity,
  BarChart3,
  FlaskConical,
  type LucideIcon,
  Package,
  ScrollText,
  ShieldCheck,
} from "lucide-react";

export interface NavRoute {
  path: string;
  title: string;
  icon: LucideIcon;
}

/** One list drives both the sidebar and the page titles, so they can't disagree. */
export const NAV_ROUTES: NavRoute[] = [
  { path: "/", title: "Overview", icon: Activity },
  { path: "/lab", title: "Red-Team Lab", icon: FlaskConical },
  { path: "/approvals", title: "Approvals", icon: ShieldCheck },
  { path: "/registry", title: "Tool Registry", icon: Package },
  { path: "/policy", title: "Policies", icon: ScrollText },
  { path: "/benchmarks", title: "Benchmarks", icon: BarChart3 },
];

export function titleFor(pathname: string): string {
  if (pathname.startsWith("/sessions/")) return "Attack Replay";
  return NAV_ROUTES.find((route) => route.path === pathname)?.title ?? "Not found";
}
