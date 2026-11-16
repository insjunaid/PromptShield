import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { lazy, Suspense } from "react";
import { createBrowserRouter, RouterProvider } from "react-router";

import { AppShell } from "@/components/AppShell";
import { ApprovalsPage } from "@/pages/Approvals";
import { BenchmarksPage } from "@/pages/Benchmarks";
import { LabPage } from "@/pages/Lab";
import { OverviewPage } from "@/pages/Overview";
import { NotFoundPage } from "@/pages/placeholders";
import { RegistryPage } from "@/pages/Registry";
import { ReplayPage } from "@/pages/Replay";

// The editor is large and only this page uses it, so it loads when the page is opened.
const PolicyPage = lazy(() => import("@/pages/Policy").then((module) => ({ default: module.PolicyPage })));

function LazyPolicy() {
  return (
    <Suspense fallback={<div className="h-[560px] animate-pulse rounded-card bg-surface-2" aria-label="Loading policy" />}>
      <PolicyPage />
    </Suspense>
  );
}

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 10_000, retry: 1, refetchOnWindowFocus: false } },
});

const router = createBrowserRouter([
  {
    element: <AppShell />,
    children: [
      { path: "/", element: <OverviewPage /> },
      { path: "/lab", element: <LabPage /> },
      { path: "/sessions/:id", element: <ReplayPage /> },
      { path: "/approvals", element: <ApprovalsPage /> },
      { path: "/registry", element: <RegistryPage /> },
      { path: "/policy", element: <LazyPolicy /> },
      { path: "/benchmarks", element: <BenchmarksPage /> },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
]);

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}
