import { AlertTriangle, Inbox, Loader2 } from "lucide-react";
import type { ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { errorMessage } from "@/lib/api";
import { cn } from "@/lib/utils";

export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn("animate-pulse rounded-md bg-surface-3", className)} />;
}

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div role="status" className="flex items-center justify-center gap-2 py-10 text-sm text-muted">
      <Loader2 className="size-4 animate-spin" aria-hidden />
      {label}
    </div>
  );
}

export function EmptyState({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-4 py-10 text-center">
      <Inbox className="size-8 text-subtle" aria-hidden />
      <p className="text-sm font-medium text-fg">{title}</p>
      {description && <p className="max-w-sm text-xs text-muted">{description}</p>}
      {action}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className="flex flex-col items-start gap-3 rounded-lg border border-risk-critical/40 bg-risk-critical/5 p-4 text-sm"
    >
      <div className="flex items-center gap-2 text-risk-critical">
        <AlertTriangle className="size-4" aria-hidden />
        <span className="font-medium">Something went wrong</span>
      </div>
      <p className="text-muted">{errorMessage(error)}</p>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function Notice({
  tone = "info",
  children,
  className,
}: {
  tone?: "info" | "warning" | "success" | "danger";
  children: ReactNode;
  className?: string;
}) {
  const styles = {
    info: "border-accent/30 bg-accent/5 text-muted",
    warning: "border-risk-medium/40 bg-risk-medium/5 text-muted",
    success: "border-risk-low/40 bg-risk-low/5 text-muted",
    danger: "border-risk-critical/40 bg-risk-critical/5 text-muted",
  }[tone];
  return <div className={cn("rounded-lg border px-4 py-3 text-xs leading-relaxed", styles, className)}>{children}</div>;
}
