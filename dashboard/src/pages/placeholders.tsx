import { SearchX } from "lucide-react";
import { Link } from "react-router";

import { EmptyState } from "@/components/EmptyState";

export function NotFoundPage() {
  return (
    <EmptyState icon={SearchX} title="Page not found">
      <Link className="text-accent underline-offset-4 hover:underline" to="/">Back to Overview</Link>
    </EmptyState>
  );
}
