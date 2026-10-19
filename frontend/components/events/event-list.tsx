import { Activity, AlertTriangle, ClipboardCheck, ClipboardPlus, Gauge, KeyRound, Link2, MessageSquareWarning, UserX } from "lucide-react";

import { RiskBadge, SourceBadge } from "@/components/risk";
import { Badge } from "@/components/ui/badge";
import { cn, formatRelative, humanize } from "@/lib/utils";
import type { EventType, SecurityEvent } from "@/types/api";

export const EVENT_ICONS: Record<EventType, typeof Activity> = {
  high_risk_message: MessageSquareWarning,
  high_risk_url: Link2,
  failed_login_burst: KeyRound,
  suspicious_login: UserX,
  rate_limit: Gauge,
  account_takeover_warning: AlertTriangle,
  incident_created: ClipboardPlus,
  incident_resolved: ClipboardCheck,
};

export function EventRow({
  event,
  selected,
  onSelect,
  isNew,
}: {
  event: SecurityEvent;
  selected?: boolean;
  onSelect?: (event: SecurityEvent) => void;
  isNew?: boolean;
}) {
  const Icon = EVENT_ICONS[event.event_type] ?? Activity;
  const content = (
    <>
      <Icon className="mt-0.5 size-4 shrink-0 text-muted" aria-hidden />
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium">{humanize(event.event_type)}</span>
          <RiskBadge level={event.severity} />
          <SourceBadge source={event.source} />
          {event.status !== "new" && <Badge>{humanize(event.status)}</Badge>}
          {isNew && <Badge tone="accent">new</Badge>}
        </div>
        <p className="line-clamp-2 text-xs leading-relaxed text-muted">{event.description}</p>
        <p className="text-[11px] text-subtle">
          {event.actor} · <time dateTime={event.created_at}>{formatRelative(event.created_at)}</time>
          {event.risk_score !== null && ` · score ${event.risk_score}`}
        </p>
      </div>
    </>
  );
  const className = cn(
    "flex w-full gap-3 border-b border-border px-4 py-3 text-left last:border-b-0",
    onSelect && "hover:bg-surface-2",
    selected && "bg-accent/5",
  );
  return (
    <li>
      {onSelect ? (
        <button type="button" className={className} onClick={() => onSelect(event)} aria-pressed={selected}>
          {content}
        </button>
      ) : (
        <div className={className}>{content}</div>
      )}
    </li>
  );
}
